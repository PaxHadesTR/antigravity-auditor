"""Base adapter contract and shared discovery execution context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from runtime_discovery.cli_detection import CliRunner, DEFAULT_CLI_TIMEOUT_SECONDS
from runtime_discovery.evidence import EvidenceLedger
from runtime_discovery.windows_detection import WindowsHostInspector


@dataclass
class AdapterContext:
    """Read-only environment roots and injectable inspectors for adapters."""

    user_home: Path
    local_appdata: Path
    appdata: Path
    program_files: Path
    project_path: Path | None
    host_inspector: WindowsHostInspector
    cli_runner: CliRunner
    ledger: EvidenceLedger
    timeout_seconds: float = DEFAULT_CLI_TIMEOUT_SECONDS


class BaseDiscoveryAdapter(ABC):
    """Abstract base class for provider-neutral application adapters."""

    application_id: str
    application_family: str

    @abstractmethod
    def discover(self, ctx: AdapterContext) -> dict[str, Any]:
        """Perform bounded, read-only discovery and return a normalized profile."""
