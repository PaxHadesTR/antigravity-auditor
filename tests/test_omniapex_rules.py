"""Bundled OmniApex rules must load in Antigravity: `globs` is a quoted, comma-separated string, never a YAML list
(Antigravity rejects a list with "cannot unmarshal !!seq into string" and drops the rule)."""

from __future__ import annotations

import re
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "integrations" / "omniapex" / ".agents" / "rules"


def _frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    assert text.startswith("---\n"), path
    head = text[4:text.index("\n---", 4)]
    return dict(line.split(":", 1) for line in head.splitlines() if ":" in line)


def test_bundled_rules_use_string_globs() -> None:
    files = sorted(RULES.glob("*.md"))
    assert files
    for path in files:
        fm = {k.strip(): v.strip() for k, v in _frontmatter(path).items()}
        assert fm.get("trigger") in ("always_on", "model_decision", "glob", "manual"), path
        if fm.get("trigger") == "glob":
            globs = fm.get("globs", "")
            assert re.fullmatch(r'"[^"\[\]]+"', globs), (path, globs)  # one quoted string, no list
            assert all(p.strip() for p in globs.strip('"').split(",")), path
