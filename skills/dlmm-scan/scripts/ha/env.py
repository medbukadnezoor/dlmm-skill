"""Restricted credential loading.

Only the explicitly requested names are read. Values stay in process memory and
are never printed, logged, or written to artifacts. The dotenv parser never
sources or evals the file and rejects shell interpolation.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INTERPOLATION = ("$", "`")
_WORKTREE_MARKER = "/.claude/worktrees/"


class EnvError(ValueError):
    """Fail-closed dotenv parse error (never includes a value)."""


def find_env_file(start: Path | None = None) -> Path | None:
    """Locate the repository base .env, also from inside a .claude/worktrees checkout."""
    explicit = os.environ.get("HOLDER_ANALYSIS_ENV")
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    here = (start or Path.cwd()).resolve()
    candidates: list[Path] = []
    text = str(here)
    if _WORKTREE_MARKER in text:
        candidates.append(Path(text.split(_WORKTREE_MARKER, 1)[0]) / ".env")
    candidates.extend(parent / ".env" for parent in (here, *here.parents))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_keys(names: list[str], env_file: Path | None = None) -> dict[str, str]:
    """Return {name: value} for the requested names that are present.

    The process environment wins over the dotenv file.
    """
    for name in names:
        if not _NAME_RE.fullmatch(name):
            raise EnvError("invalid credential name requested")
    found: dict[str, str] = {}
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            found[name] = value
    missing = [name for name in names if name not in found]
    if not missing:
        return found
    path = env_file or find_env_file()
    if path is None or not Path(path).is_file():
        return found
    seen: set[str] = set()
    for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        if name not in missing:
            continue
        if name in seen:
            raise EnvError(f"duplicate dotenv key {name}")
        seen.add(name)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if any(marker in value for marker in _INTERPOLATION):
            raise EnvError(f"dotenv interpolation is not allowed on line {line_no}")
        if value.strip():
            found[name] = value.strip()
    return found
