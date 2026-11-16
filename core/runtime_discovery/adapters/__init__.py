"""Application discovery adapters package."""

from runtime_discovery.adapters.antigravity import AntigravityAdapter
from runtime_discovery.adapters.base import AdapterContext, BaseDiscoveryAdapter
from runtime_discovery.adapters.claude_code import ClaudeCodeAdapter
from runtime_discovery.adapters.claude_desktop import ClaudeDesktopAdapter
from runtime_discovery.adapters.codex import CodexAdapter

__all__ = [
    "AdapterContext",
    "AntigravityAdapter",
    "BaseDiscoveryAdapter",
    "ClaudeCodeAdapter",
    "ClaudeDesktopAdapter",
    "CodexAdapter",
]
