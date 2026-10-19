"""
Regression guard: `get_clearpass_client()` must never be used as an async
context manager.

`get_clearpass_client()` is a plain `async def` that returns a `ClearPassClient`.
Calling it produces a *coroutine*, and a coroutine has no `__aenter__`, so
`async with get_clearpass_client() as client:` raises TypeError at runtime.

The canonical form is:

    client = await get_clearpass_client()

This bug class has recurred twice in this repo (policy_elements.py, then
session_control.py). This test makes a third recurrence impossible to merge
silently.
"""

from pathlib import Path

BROKEN_PATTERN = "async with get_clearpass_client("

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def _find_offenders():
    """Return a list of (path, line_number, line_text) for every broken usage."""
    offenders = []
    for py_file in sorted(SRC_DIR.rglob("*.py")):
        try:
            text = py_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - defensive
            continue
        if BROKEN_PATTERN not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if BROKEN_PATTERN in line:
                offenders.append((py_file, lineno, line.strip()))
    return offenders


def test_src_dir_exists():
    """Guard against the scan silently passing because src/ moved."""
    assert SRC_DIR.is_dir(), f"Expected source directory at {SRC_DIR}"
    assert any(SRC_DIR.rglob("*.py")), f"No .py files found under {SRC_DIR}"


def test_no_async_with_get_clearpass_client():
    """No .py file under src/ may use get_clearpass_client() as an async CM."""
    offenders = _find_offenders()

    if offenders:
        by_file = {}
        for path, lineno, line in offenders:
            by_file.setdefault(path, []).append((lineno, line))

        details = []
        for path in sorted(by_file):
            hits = by_file[path]
            linenos = ", ".join(str(n) for n, _ in hits)
            details.append(f"  {path} (lines {linenos}):")
            for lineno, line in hits:
                details.append(f"      line {lineno}: {line}")

        raise AssertionError(
            "Found {n} use(s) of the broken pattern "
            "`{pattern}` under {src}.\n"
            "`get_clearpass_client()` returns a coroutine, which has no "
            "__aenter__ — this raises TypeError at runtime.\n"
            "Use the canonical form instead:\n"
            "    client = await get_clearpass_client()\n"
            "Offending file(s) and line number(s):\n{details}".format(
                n=len(offenders),
                pattern=BROKEN_PATTERN,
                src=SRC_DIR,
                details="\n".join(details),
            )
        )
