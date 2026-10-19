"""
Regression guard: an ``except`` handler must never reference a local name that
is only bound *after* an ``await`` inside the corresponding ``try`` body.

The bug shape this catches::

    try:
        client = await get_clearpass_client()
        if user_id is not None:
            result = await client.get_admin_user_by_id(user_id)
            identifier = f"ID {user_id}"      # <- bound only on success
        ...
    except ClearPassAPIError as e:
        return await format_api_error(e, f"... for {identifier}")   # <- BOOM

When the awaited call raises (a plain 404 is enough), ``identifier`` was never
assigned, so the handler itself raises::

    UnboundLocalError: cannot access local variable 'identifier'
                       where it is not associated with a value

...and the *real* API error is destroyed and replaced by a confusing one.

This was confirmed live on five ``global_server_config`` operations
(``get_admin_user_details``, ``get_attribute_details``, ``get_data_filter_details``,
``get_operator_profile_details``, ``get_snmp_trap_receiver_details``).

The fix is always the same: hoist the assignment *above* the ``try`` (or stop
depending on it in the handler).

Companion to ``tests/test_no_async_with_client.py``.
"""

import ast
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"

# Pre-existing offenders that live in modules owned by other work-streams.
# This list may only ever SHRINK. Do not add to it -- fix the code instead.
# Keyed by (relative path, function name, offending variable name).
KNOWN_OFFENDERS = set()


def _walk_excluding_nested_defs(roots):
    """Yield nodes under ``roots``, not descending into nested function/class bodies."""
    stack = list(roots)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            stack.append(child)


def _bindings(roots):
    """Map name -> sorted line numbers where the name is bound."""
    out = {}
    for node in _walk_excluding_nested_defs(roots):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            out.setdefault(node.id, []).append(node.lineno)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".")[0]
                out.setdefault(name, []).append(node.lineno)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.setdefault(node.name, []).append(node.lineno)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                # Treat as bound from the top of the function.
                out.setdefault(name, []).append(0)
    return out


def _loads(roots):
    """Map name -> line numbers where the name is read (all nested scopes included)."""
    out = {}
    stack = list(roots)
    while stack:
        node = stack.pop()
        stack.extend(ast.iter_child_nodes(node))
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.setdefault(node.id, []).append(node.lineno)
    return out


def _first_await_line(roots):
    lines = []
    stack = list(roots)
    while stack:
        node = stack.pop()
        stack.extend(ast.iter_child_nodes(node))
        if isinstance(node, ast.Await):
            lines.append(node.lineno)
    return min(lines) if lines else None


def _scan_function(path, fn):
    args = fn.args
    params = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
    if args.vararg:
        params.add(args.vararg.arg)
    if args.kwarg:
        params.add(args.kwarg.arg)

    fn_bindings = _bindings(fn.body)
    offenders = []

    for node in _walk_excluding_nested_defs(fn.body):
        if not isinstance(node, ast.Try):
            continue
        first_await = _first_await_line(node.body)
        if first_await is None:
            continue
        for handler in node.handlers:
            handler_bindings = _bindings(handler.body)
            for name, read_lines in _loads(handler.body).items():
                if name in params or name == handler.name:
                    continue
                bound_at = fn_bindings.get(name)
                if not bound_at:
                    continue  # module-level, import or builtin -- always available
                local = handler_bindings.get(name)
                if local and min(local) <= min(read_lines):
                    continue  # (re)bound inside the handler before it is read
                outer = [ln for ln in bound_at if ln not in (local or [])]
                if outer and min(outer) > first_await:
                    offenders.append(
                        {
                            "path": path,
                            "function": fn.name,
                            "name": name,
                            "read_line": min(read_lines),
                            "bound_line": min(outer),
                            "await_line": first_await,
                        }
                    )
    return offenders


def _find_offenders():
    offenders = []
    for py_file in sorted(SRC_DIR.rglob("*.py")):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                offenders.extend(_scan_function(py_file, node))
    return offenders


def _key(off):
    return (
        off["path"].relative_to(SRC_DIR).as_posix(),
        off["function"],
        off["name"],
    )


def test_src_dir_exists():
    """Guard against the scan silently passing because src/ moved."""
    assert SRC_DIR.is_dir(), f"Expected source directory at {SRC_DIR}"
    assert any(SRC_DIR.rglob("*.py")), f"No .py files found under {SRC_DIR}"


def test_detector_catches_the_known_bug_shape(tmp_path):
    """The detector must actually fire on the canonical bug (and not on the fix)."""
    broken = tmp_path / "broken.py"
    broken.write_text(
        "async def op(user_id):\n"
        "    try:\n"
        "        result = await client.get(user_id)\n"
        "        identifier = f'ID {user_id}'\n"
        "        return result\n"
        "    except Exception:\n"
        "        return f'failed for {identifier}'\n",
        encoding="utf-8",
    )
    tree = ast.parse(broken.read_text(encoding="utf-8"))
    found = _scan_function(broken, tree.body[0])
    assert [o["name"] for o in found] == ["identifier"]

    fixed = tmp_path / "fixed.py"
    fixed.write_text(
        "async def op(user_id):\n"
        "    identifier = f'ID {user_id}'\n"
        "    try:\n"
        "        result = await client.get(user_id)\n"
        "        return result\n"
        "    except Exception:\n"
        "        return f'failed for {identifier}'\n",
        encoding="utf-8",
    )
    tree = ast.parse(fixed.read_text(encoding="utf-8"))
    assert _scan_function(fixed, tree.body[0]) == []


def test_no_except_handler_reads_a_post_await_local():
    """No except handler under src/ may read a name bound only after an await."""
    offenders = [o for o in _find_offenders() if _key(o) not in KNOWN_OFFENDERS]

    if offenders:
        details = "\n".join(
            "  {path}:{read_line} in {function}(): '{name}' is only bound at "
            "line {bound_line}, after the await on line {await_line}".format(**o)
            for o in sorted(offenders, key=lambda o: (str(o["path"]), o["read_line"]))
        )
        raise AssertionError(
            f"Found {len(offenders)} except handler(s) that reference a local "
            "bound only after an await in the same try block.\n"
            "When the awaited call raises, the handler raises UnboundLocalError "
            "and the real API error is lost.\n"
            "Hoist the assignment above the try (or stop using it in the "
            f"handler).\n{details}"
        )


def test_report_stale_allowlist_entries(capsys):
    """Surface allowlist entries that are already fixed, so they get pruned.

    Deliberately non-fatal: this runs green while several work-streams edit
    different modules in parallel, and a *fixed* bug must never break the build.
    Stale entries are printed with -s / on failure of the test above.
    """
    live = {_key(o) for o in _find_offenders()}
    stale = KNOWN_OFFENDERS - live
    if stale:
        print(
            "NOTE: these KNOWN_OFFENDERS entries are already fixed and should "
            f"be removed from the allowlist: {sorted(stale)}"
        )
