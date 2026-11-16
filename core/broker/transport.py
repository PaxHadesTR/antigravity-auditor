"""Named Pipe Server Transport with Windows Native and Cross-Platform Testing Support."""

from __future__ import annotations

import ctypes
import os
import struct
import threading
import time
from typing import Any

from broker.constants import (
    BUFFER_SIZE,
    DEFAULT_MAX_CONCURRENT_CLIENTS,
    DEFAULT_PIPE_NAME,
    DEFAULT_PIPE_SDDL,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_MESSAGE_SIZE,
)
from broker.dispatcher import BrokerDispatcher
from broker.exceptions import (
    BrokerSchemaError,
    BrokerTimeoutError,
    BrokerUnavailableError,
)
from broker.protocol import (
    decode_frame_header,
    encode_frame,
    make_error_response,
    parse_request_bytes,
)
from broker.security import (
    ClientIdentity,
    create_pipe_security_descriptor,
    free_pipe_security_descriptor,
    get_win32_kernel32,
    inspect_pipe_client_identity,
    is_windows,
    read_exact_pipe,
    write_all_pipe,
)


class BasePipeServer:
    """Abstract base class for Broker transport servers."""

    def __init__(self, dispatcher: BrokerDispatcher) -> None:
        self.dispatcher = dispatcher
        self._running = False
        self._stop_event = threading.Event()

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def is_alive(self) -> bool:
        return self._running


class WindowsNamedPipeServer(BasePipeServer):
    """Production Windows Named Pipe server using native Win32 APIs via ctypes.

    Security Features:
    - PIPE_REJECT_REMOTE_CLIENTS flag blocks incoming remote network/SMB pipe connections.
    - Explicit Security Descriptor (DACL) restricting client access.
    - Inspects client token/PID via GetNamedPipeClientProcessId & ImpersonateNamedPipeClient.
    - Bounded message reads enforcing MAX_MESSAGE_SIZE.
    - Clean disconnection and pipe instance recycling.
    """

    # Win32 Named Pipe Flags
    PIPE_ACCESS_DUPLEX = 0x00000003
    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
    PIPE_WAIT = 0x00000000
    INVALID_HANDLE_VALUES = (None, 0, -1, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)

    def __init__(
        self,
        dispatcher: BrokerDispatcher,
        pipe_name: str = DEFAULT_PIPE_NAME,
        sddl: str = DEFAULT_PIPE_SDDL,
        max_instances: int = DEFAULT_MAX_CONCURRENT_CLIENTS,
    ) -> None:
        super().__init__(dispatcher)
        self.pipe_name = pipe_name
        self.sddl = sddl
        self.max_instances = max_instances
        self._server_thread: threading.Thread | None = None
        self._server_thread_id: int | None = None
        self._client_threads: list[threading.Thread] = []
        self._active_connections = 0
        self._lock = threading.Lock()
        self._ready_event = threading.Event()
        self._startup_error: Exception | None = None
        self.startup_error_code: int | None = None

    def start(self) -> None:
        """Start listening for incoming Named Pipe connections on a background thread."""
        if not is_windows():
            raise RuntimeError("WindowsNamedPipeServer requires native Windows platform.")
        if self._running and self._server_thread and self._server_thread.is_alive():
            return
        self._running = True
        self._stop_event.clear()
        self._ready_event.clear()
        self._startup_error = None
        self.startup_error_code = None
        self._server_thread = threading.Thread(target=self._listen_loop, daemon=True, name="NamedPipeServerThread")
        self._server_thread.start()

        if not self._ready_event.wait(timeout=5.0):
            self._running = False
            raise BrokerUnavailableError(f"Named Pipe server timed out initializing {self.pipe_name}.")
        if self._startup_error is not None:
            self._running = False
            self._server_thread.join(timeout=2.0)
            raise self._startup_error

    def stop(self) -> None:
        """Signal server to stop listening, unblock accept, and drain client threads."""
        self._running = False
        self._stop_event.set()
        kernel32 = get_win32_kernel32() if is_windows() else None
        # Connect briefly to unblock any pending ConnectNamedPipe
        if kernel32 is not None:
            try:
                h = kernel32.CreateFileW(
                    self.pipe_name,
                    0xC0000000,  # GENERIC_READ | GENERIC_WRITE
                    0,
                    None,
                    3,  # OPEN_EXISTING
                    0,
                    None,
                )
                if h not in self.INVALID_HANDLE_VALUES:
                    kernel32.CloseHandle(h)
                elif self._server_thread_id:
                    # Fallback if SDDL blocks self-connect: cancel synchronous ConnectNamedPipe I/O
                    h_thr = kernel32.OpenThread(0x0001, False, self._server_thread_id)
                    if h_thr not in self.INVALID_HANDLE_VALUES:
                        try:
                            kernel32.CancelSynchronousIo(h_thr)
                        finally:
                            kernel32.CloseHandle(h_thr)
            except Exception:
                pass
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=3.0)
        with self._lock:
            threads = list(self._client_threads)
        for t in threads:
            if t.is_alive():
                t.join(timeout=2.0)
        with self._lock:
            self._client_threads = [t for t in self._client_threads if t.is_alive()]

    def _create_pipe_instance(self, kernel32: ctypes.WinDLL, sa_ptr: Any, first_instance: bool) -> int | None:
        """Create one local-only Win32 Named Pipe instance."""
        open_mode = self.PIPE_ACCESS_DUPLEX
        if first_instance:
            open_mode |= self.FILE_FLAG_FIRST_PIPE_INSTANCE
        pipe_mode = self.PIPE_TYPE_BYTE | self.PIPE_READMODE_BYTE | self.PIPE_WAIT | self.PIPE_REJECT_REMOTE_CLIENTS
        return kernel32.CreateNamedPipeW(
            self.pipe_name,
            open_mode,
            pipe_mode,
            self.max_instances,
            BUFFER_SIZE,
            BUFFER_SIZE,
            5000,
            sa_ptr,
        )

    def _listen_loop(self) -> None:
        """Main listening loop accepting client pipe instances."""
        kernel32 = get_win32_kernel32()
        self._server_thread_id = int(kernel32.GetCurrentThreadId())

        p_sd = create_pipe_security_descriptor(self.sddl)
        if self.sddl and not p_sd:
            err = ctypes.get_last_error()
            self.startup_error_code = err
            self._startup_error = BrokerUnavailableError(
                f"Failed to parse/build pipe SDDL '{self.sddl}' (Win32 Error {err})."
            )
            self._ready_event.set()
            return

        # Build SECURITY_ATTRIBUTES struct
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", ctypes.c_ulong),
                ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", ctypes.c_int),
            ]

        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = p_sd
        sa.bInheritHandle = 0
        sa_ptr = ctypes.byref(sa) if p_sd else None

        ERROR_PIPE_CONNECTED = 535

        try:
            # Synchronous first-instance creation before signaling readiness
            pending_pipe = self._create_pipe_instance(kernel32, sa_ptr, first_instance=True)
            if pending_pipe in self.INVALID_HANDLE_VALUES:
                err = ctypes.get_last_error()
                self.startup_error_code = err
                self._startup_error = BrokerUnavailableError(
                    f"CreateNamedPipeW failed for {self.pipe_name} (Win32 Error {err})."
                )
                self._ready_event.set()
                return

            self._ready_event.set()

            while self._running:
                if pending_pipe is None:
                    h_pipe = self._create_pipe_instance(kernel32, sa_ptr, first_instance=False)
                    if h_pipe in self.INVALID_HANDLE_VALUES:
                        time.sleep(0.05)
                        continue
                else:
                    h_pipe = pending_pipe
                    pending_pipe = None

                # ConnectNamedPipe blocks until client connects, stop() unblocks, or error
                res_connect = kernel32.ConnectNamedPipe(h_pipe, None)
                err = ctypes.get_last_error()
                if res_connect or err == ERROR_PIPE_CONNECTED:
                    if not self._running:
                        kernel32.DisconnectNamedPipe(h_pipe)
                        kernel32.CloseHandle(h_pipe)
                        break

                    # Spawn worker thread for this connection and track for shutdown drain
                    t = threading.Thread(
                        target=self._handle_client_connection,
                        args=(h_pipe,),
                        daemon=True,
                    )
                    with self._lock:
                        self._client_threads = [ct for ct in self._client_threads if ct.is_alive()]
                        self._client_threads.append(t)
                    t.start()
                else:
                    kernel32.CloseHandle(h_pipe)
        finally:
            self._running = False
            self._server_thread_id = None
            if p_sd:
                free_pipe_security_descriptor(p_sd)

    @staticmethod
    def _read_exact(kernel32: ctypes.WinDLL, h_pipe: int, length: int) -> bytes | None:
        """Read exact number of bytes from pipe handle."""
        return read_exact_pipe(kernel32, h_pipe, length)

    def _handle_client_connection(self, h_pipe: int) -> None:
        """Handle incoming framed requests from a connected client pipe instance."""
        kernel32 = get_win32_kernel32()
        with self._lock:
            self._active_connections += 1

        try:
            client_id: ClientIdentity | None = None

            while self._running:
                # 1. Read 4-byte length prefix (must read pipe before ImpersonateNamedPipeClient)
                header_bytes = self._read_exact(kernel32, h_pipe, 4)
                if header_bytes is None:
                    break  # Client disconnected cleanly or mid-header

                # 2. Inspect client token and integrity level once data has arrived on pipe
                if client_id is None:
                    client_id = inspect_pipe_client_identity(h_pipe)

                try:
                    payload_len = decode_frame_header(header_bytes)
                except BrokerSchemaError as s_err:
                    err_resp = make_error_response(None, -32600, s_err.message)
                    self._write_pipe_frame(h_pipe, err_resp.serialize())
                    break

                # 3. Read payload bytes (bounded by MAX_MESSAGE_SIZE)
                payload_bytes = self._read_exact(kernel32, h_pipe, payload_len)
                if payload_bytes is None or len(payload_bytes) != payload_len:
                    break

                # 4. Parse JSON-RPC Request
                try:
                    req = parse_request_bytes(payload_bytes)
                    response = self.dispatcher.dispatch(req, client_id)
                except BrokerSchemaError as b_err:
                    code = b_err.data.get("code", -32600) if b_err.data else -32600
                    response = make_error_response(None, code, b_err.message)

                # 5. Send serialized response frame
                raw_response_frame = response.serialize()
                self._write_pipe_frame(h_pipe, raw_response_frame)
        finally:
            kernel32.DisconnectNamedPipe(h_pipe)
            kernel32.CloseHandle(h_pipe)
            with self._lock:
                self._active_connections -= 1

    def _write_pipe_frame(self, h_pipe: int, frame_data: bytes) -> None:
        """Write framed bytes to pipe."""
        kernel32 = get_win32_kernel32()
        write_all_pipe(kernel32, h_pipe, frame_data)


class MemoryPipeTransport:
    """In-memory mock transport for unit and integration testing without Win32 pipe handles.

    Executes identical protocol serialization, frame header decoding, schema validation,
    and dispatch logic in memory for test isolation.
    """

    def __init__(self, dispatcher: BrokerDispatcher, default_client: ClientIdentity | None = None) -> None:
        self.dispatcher = dispatcher
        self.default_client = default_client or ClientIdentity(
            pid=os.getpid(),
            sid="S-1-5-21-TEST-MOCK",
            integrity_level="MEDIUM",
            is_low_integrity=False,
            verified_by_os=True,
        )

    def execute_raw_frame(self, frame_bytes: bytes, client: ClientIdentity | None = None) -> bytes:
        """Process incoming raw frame bytes and return response frame bytes."""
        active_client = client or self.default_client

        if len(frame_bytes) < 4:
            raise BrokerSchemaError("Frame bytes shorter than 4-byte length prefix.")

        payload_len = decode_frame_header(frame_bytes[:4])
        payload_data = frame_bytes[4 : 4 + payload_len]

        if len(payload_data) != payload_len:
            raise BrokerSchemaError(f"Payload length mismatch: expected {payload_len}, got {len(payload_data)}")

        try:
            if self.dispatcher is None:
                raise BrokerUnavailableError("MemoryPipeTransport dispatcher is not configured.")
            req = parse_request_bytes(payload_data)
            resp = self.dispatcher.dispatch(req, active_client)
        except BrokerUnavailableError:
            raise
        except BrokerSchemaError as b_err:
            code = b_err.data.get("code", -32600) if b_err.data else -32600
            resp = make_error_response(None, code, b_err.message)

        return resp.serialize()

    def execute_request_dict(self, req_dict: dict[str, Any], client: ClientIdentity | None = None) -> dict[str, Any]:
        """Convenience method for testing dictionary payloads."""
        import json
        raw_json = json.dumps(req_dict).encode("utf-8")
        frame = encode_frame(raw_json)
        resp_frame = self.execute_raw_frame(frame, client)
        resp_payload_len = decode_frame_header(resp_frame[:4])
        return json.loads(resp_frame[4 : 4 + resp_payload_len].decode("utf-8"))
