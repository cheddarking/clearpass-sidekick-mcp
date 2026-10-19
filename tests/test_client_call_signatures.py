"""Static signature audit: every call made against the ClearPass client must
resolve against the real ``ClearPassClient`` API.

This is the offline, permanent form of an ad-hoc AST audit that found 15 real
bugs before a single live call was made:

* ``self.<method>(...)`` calls inside ``src/client_methods/`` naming methods
  that do not exist on ``ClearPassClient`` (the whole proxy-target family).
* ``self._make_request(..., json=...)`` — the signature is
  ``(method, endpoint, data=None, params=None)``; there is no ``json``
  parameter, so the call explodes with ``TypeError`` at runtime.
* ``client.<method>(kwarg=...)`` calls inside ``src/tools/`` passing a keyword
  the client method does not accept.

Every one of these is a guaranteed runtime ``TypeError`` / ``AttributeError``
on the first invocation, reachable only through a live appliance call — which
is exactly the kind of bug a static check should catch for free.

Rules
-----
* A method declaring ``**kwargs`` accepts any keyword; a method declaring
  ``*args`` accepts any number of positionals.
* Private helpers (``_foo``) are not audited, with the single deliberate
  exception of ``_make_request``, which is the shared transport entry point.
* ``f(**mapping)`` / ``f(*seq)`` disable the keyword / positional check for
  that call only — the contents are not statically knowable.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Dict, List, Set

import pytest

from src.clearpass_client import ClearPassClient

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
AUDITED_DIRS = (SRC / "tools", SRC / "client_methods")

# Private helpers are skipped, except the shared transport entry point.
AUDITED_PRIVATE = {"_make_request"}


# --------------------------------------------------------------------------
# The real client API, via inspect
# --------------------------------------------------------------------------


def client_api() -> Dict[str, inspect.Signature]:
    """name -> signature for every method on ``ClearPassClient`` (all mixins)."""
    api: Dict[str, inspect.Signature] = {}
    for name, func in inspect.getmembers(ClearPassClient, predicate=inspect.isfunction):
        try:
            api[name] = inspect.signature(func)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            continue
    return api


def _accepts(sig: inspect.Signature) -> tuple:
    """(positional names, keyword names, has *args, has **kwargs) minus ``self``."""
    positional: List[str] = []
    keyword: Set[str] = set()
    var_positional = var_keyword = False
    for name, param in sig.parameters.items():
        if name == "self":
            continue
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            var_positional = True
        elif param.kind is inspect.Parameter.VAR_KEYWORD:
            var_keyword = True
        elif param.kind is inspect.Parameter.POSITIONAL_ONLY:
            positional.append(name)
        elif param.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD:
            positional.append(name)
            keyword.add(name)
        elif param.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword.add(name)
    return positional, keyword, var_positional, var_keyword


# --------------------------------------------------------------------------
# AST walk
# --------------------------------------------------------------------------


def client_receiver_names(tree: ast.AST, is_mixin: bool) -> Set[str]:
    """Local variable names known to hold a ``ClearPassClient``.

    Inside ``src/client_methods/`` the mixins call through ``self``. Inside
    ``src/tools/`` the client arrives as ``<name> = await get_clearpass_client()``.
    """
    names: Set[str] = {"self"} if is_mixin else set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if isinstance(value, ast.Await):
            value = value.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == "get_clearpass_client"):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def audit_source(source: str, filename: str, api: Dict[str, inspect.Signature],
                 is_mixin: bool) -> List[str]:
    """Return one message per bad client call in ``source``."""
    tree = ast.parse(source, filename=filename)
    receivers = client_receiver_names(tree, is_mixin)
    violations: List[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            continue
        receiver, method = func.value.id, func.attr
        if receiver not in receivers:
            continue
        if method.startswith("_") and method not in AUDITED_PRIVATE:
            continue

        where = f"{filename}:{node.lineno}  {receiver}.{method}(...)"

        sig = api.get(method)
        if sig is None:
            violations.append(
                f"{where}  ->  ClearPassClient has no method {method!r}"
            )
            continue

        positional, keyword, var_positional, var_keyword = _accepts(sig)

        if not var_keyword:
            for kw in node.keywords:
                if kw.arg is None:  # f(**mapping) - not statically knowable
                    continue
                if kw.arg not in keyword:
                    accepted = ", ".join(sorted(keyword)) or "<none>"
                    violations.append(
                        f"{where}  ->  {method}() got an unexpected keyword "
                        f"argument {kw.arg!r}; accepts: {accepted}"
                    )

        if not var_positional and not any(
            isinstance(a, ast.Starred) for a in node.args
        ):
            if len(node.args) > len(positional):
                violations.append(
                    f"{where}  ->  {method}() takes {len(positional)} positional "
                    f"argument(s) but {len(node.args)} were given"
                )

    return violations


def audited_files() -> List[Path]:
    files: List[Path] = []
    for directory in AUDITED_DIRS:
        files.extend(sorted(p for p in directory.rglob("*.py")
                            if p.name != "__init__.py"))
    return files


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


def test_audited_directories_are_present():
    for directory in AUDITED_DIRS:
        assert directory.is_dir(), f"missing audited directory: {directory}"
    assert audited_files(), "no source files found to audit"


def test_client_api_is_discoverable():
    api = client_api()
    assert "_make_request" in api
    # Sanity: the transport helper takes data/params, never `json`.
    _, keyword, _, var_keyword = _accepts(api["_make_request"])
    assert not var_keyword
    assert "json" not in keyword
    assert {"data", "params"} <= keyword


def test_all_client_calls_resolve_against_the_real_client():
    api = client_api()
    violations: List[str] = []
    for path in audited_files():
        is_mixin = path.parent.name == "client_methods"
        violations.extend(
            audit_source(path.read_text(encoding="utf-8"),
                         str(path.relative_to(REPO_ROOT)), api, is_mixin)
        )

    assert not violations, (
        f"{len(violations)} call site(s) do not match the real ClearPassClient "
        "API — every one is a runtime TypeError/AttributeError:\n  "
        + "\n  ".join(violations)
    )


@pytest.mark.parametrize(
    "source, is_mixin, expected_fragment",
    [
        # method that does not exist on ClearPassClient
        (
            "async def f(self):\n"
            "    return await self.get_proxy_target('x')\n",
            True,
            "has no method 'get_proxy_target'",
        ),
        # _make_request has no `json` parameter
        (
            "async def f(self):\n"
            "    return await self._make_request('PATCH', 'e', json={})\n",
            True,
            "unexpected keyword argument 'json'",
        ),
        # keyword the client method does not accept, via a tools-style receiver
        (
            "async def f():\n"
            "    client = await get_clearpass_client()\n"
            "    return await client._make_request('GET', 'e', nope=1)\n",
            False,
            "unexpected keyword argument 'nope'",
        ),
        # too many positional arguments
        (
            "async def f(self):\n"
            "    return await self._make_request('GET', 'e', 1, 2, 3, 4)\n",
            True,
            "positional argument",
        ),
    ],
)
def test_audit_detects_known_bad_shapes(source, is_mixin, expected_fragment):
    """The audit must actually be able to fail — guards against a silent no-op."""
    found = audit_source(source, "<synthetic>", client_api(), is_mixin)
    assert any(expected_fragment in v for v in found), found


def test_audit_accepts_a_correct_call():
    good = (
        "async def f(self):\n"
        "    return await self._make_request('GET', 'endpoint', params={'a': 1})\n"
    )
    assert audit_source(good, "<synthetic>", client_api(), True) == []
