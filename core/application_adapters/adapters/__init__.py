"""Application-specific adapter implementations (Antigravity, Claude Desktop, Codex, Claude Code)."""

from application_adapters.adapters.antigravity import AntigravityApplicationAdapter
from application_adapters.adapters.claude_code import ClaudeCodeApplicationAdapter
from application_adapters.adapters.claude_desktop import ClaudeDesktopApplicationAdapter
from application_adapters.adapters.codex import CodexApplicationAdapter

__all__ = [
    "AntigravityApplicationAdapter",
    "ClaudeCodeApplicationAdapter",
    "ClaudeDesktopApplicationAdapter",
    "CodexApplicationAdapter",
]
