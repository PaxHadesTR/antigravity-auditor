"""JSON-RPC 2.0 protocol encoding, decoding, and schema validation."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

from broker.constants import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_PARSE_ERROR,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
)
from broker.exceptions import BrokerSchemaError


@dataclass
class JsonRpcRequest:
    """Represents a validated JSON-RPC 2.0 request."""

    id: str | int
    method: str
    params: dict[str, Any]
    protocol_version: str = PROTOCOL_VERSION


@dataclass
class JsonRpcResponse:
    """Represents a JSON-RPC 2.0 response."""

    id: str | int | None
    result: Any = None
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            payload["error"] = self.error
        else:
            payload["result"] = self.result
        return payload

    def serialize(self) -> bytes:
        raw_json = json.dumps(self.to_dict(), ensure_ascii=False).encode("utf-8")
        if len(raw_json) > MAX_MESSAGE_SIZE:
            raise BrokerSchemaError(f"Response size {len(raw_json)} exceeds maximum {MAX_MESSAGE_SIZE}")
        return encode_frame(raw_json)


def encode_frame(data: bytes) -> bytes:
    """Frame payload with a 4-byte big-endian unsigned length prefix."""
    if len(data) > MAX_MESSAGE_SIZE:
        raise BrokerSchemaError(f"Payload size {len(data)} exceeds maximum {MAX_MESSAGE_SIZE}")
    return struct.pack("!I", len(data)) + data


def decode_frame_header(header_bytes: bytes) -> int:
    """Decode 4-byte big-endian length prefix."""
    if len(header_bytes) != 4:
        raise BrokerSchemaError(f"Invalid frame header length: {len(header_bytes)} bytes")
    (length,) = struct.unpack("!I", header_bytes)
    if length > MAX_MESSAGE_SIZE:
        raise BrokerSchemaError(f"Frame length {length} exceeds maximum {MAX_MESSAGE_SIZE}")
    return length


def parse_request_bytes(raw_bytes: bytes) -> JsonRpcRequest:
    """Parse raw JSON bytes into a validated JsonRpcRequest."""
    if len(raw_bytes) > MAX_MESSAGE_SIZE:
        raise BrokerSchemaError(f"Message size {len(raw_bytes)} exceeds maximum {MAX_MESSAGE_SIZE}", data={"code": JSONRPC_INVALID_REQUEST})

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise BrokerSchemaError(f"JSON parse error: {exc}", data={"code": JSONRPC_PARSE_ERROR}) from exc

    if not isinstance(data, dict):
        raise BrokerSchemaError("JSON-RPC message must be an object", data={"code": JSONRPC_INVALID_REQUEST})

    # Validate jsonrpc version
    if data.get("jsonrpc") != "2.0":
        raise BrokerSchemaError("Missing or invalid 'jsonrpc' version; must be '2.0'", data={"code": JSONRPC_INVALID_REQUEST})

    # Validate id
    req_id = data.get("id")
    if req_id is None:
        raise BrokerSchemaError("Missing request 'id'; notifications are not permitted in governance broker", data={"code": JSONRPC_INVALID_REQUEST})
    if not isinstance(req_id, (str, int)):
        raise BrokerSchemaError("Request 'id' must be a string or integer", data={"code": JSONRPC_INVALID_REQUEST})
    if isinstance(req_id, str) and not req_id.strip():
        raise BrokerSchemaError("Request 'id' string cannot be empty or whitespace", data={"code": JSONRPC_INVALID_REQUEST})

    # Validate method
    method = data.get("method")
    if not isinstance(method, str) or not method.strip():
        raise BrokerSchemaError("Missing or invalid 'method'; must be non-empty string", data={"code": JSONRPC_INVALID_REQUEST})

    # Validate protocol_version if specified
    proto_ver = data.get("protocol_version")
    if proto_ver is not None:
        if not isinstance(proto_ver, str) or proto_ver.split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
            raise BrokerSchemaError(f"Unsupported protocol version '{proto_ver}'; expected '{PROTOCOL_VERSION}'", data={"code": JSONRPC_INVALID_PARAMS})

    # Validate params
    params = data.get("params")
    if params is None:
        params_dict: dict[str, Any] = {}
    elif isinstance(params, dict):
        params_dict = params
    elif isinstance(params, list):
        # Named parameters are strictly preferred in broker RPC
        params_dict = {"_positional": params}
    else:
        raise BrokerSchemaError("Request 'params' must be an object or list", data={"code": JSONRPC_INVALID_PARAMS})

    return JsonRpcRequest(
        id=req_id,
        method=method.strip(),
        params=params_dict,
        protocol_version=proto_ver or PROTOCOL_VERSION,
    )


def make_error_response(req_id: str | int | None, code: int, message: str, data: Any = None) -> JsonRpcResponse:
    """Construct an error JsonRpcResponse."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return JsonRpcResponse(id=req_id, error=err)


def make_success_response(req_id: str | int, result: Any) -> JsonRpcResponse:
    """Construct a successful JsonRpcResponse."""
    return JsonRpcResponse(id=req_id, result=result)
