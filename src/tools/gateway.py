"""Gateway meta-tools exposing the full ClearPass operation catalog
through progressive disclosure."""

import inspect
import logging
from typing import Any, Dict, List, Optional

from fastmcp import Context

from ..app_config import mcp
from ..registry import registry
from ..utils import format_error

logger = logging.getLogger(__name__)


@mcp.tool()
async def list_operations(
    ctx: Context,
    domain: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """List available ClearPass operations (name, domain, one-line summary).

    Use `domain` to filter to one area (see `domains` in the response) or
    `search` for keyword matching. Then call `describe_operations` for full
    parameter schemas and `invoke_operation` to execute one.
    """
    specs = registry.search(domain=domain, query=search)
    return {
        "success": True,
        "total": len(specs),
        "domains": registry.domains(),
        "operations": [
            {"name": s.name, "domain": s.domain, "summary": s.summary} for s in specs
        ],
    }


@mcp.tool()
async def describe_operations(
    ctx: Context,
    names: List[str],
) -> Dict[str, Any]:
    """Get full documentation and parameter JSON schemas for the named
    ClearPass operations. Call this before `invoke_operation`."""
    found, missing = [], []
    for name in names:
        spec = registry.get(name)
        if spec is None:
            missing.append(name)
        else:
            found.append({
                "name": spec.name,
                "domain": spec.domain,
                "description": spec.description,
                "parameters_schema": spec.parameters_schema,
            })
    result: Dict[str, Any] = {"success": True, "operations": found}
    if missing:
        result["missing"] = missing
        msg = (
            f"Unknown operations: {', '.join(missing)}. "
            "Use list_operations to find valid names."
        )
        result["message"] = msg
        result["suggestion"] = msg
    return result


@mcp.tool()
async def invoke_operation(
    ctx: Context,
    name: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Execute a ClearPass operation by name with a params object matching
    its schema from `describe_operations`."""
    params = params or {}
    spec = registry.get(name)
    if spec is None:
        msg = f"Use list_operations (optionally with search=...) to find the correct operation name, then retry."
        return {
            "success": False,
            "operation": name,
            "error": f"Unknown operation '{name}'",
            "error_type": "validation_error",
            "message": msg,
            "suggestion": msg,
        }

    sig = inspect.signature(spec.func)
    valid = {p for p in sig.parameters if p not in ("ctx", "context")}
    aliases = spec.param_aliases

    # Accept either the real parameter name or its declared pydantic alias
    # (e.g. `filter` for `filter_str`), matching legacy direct-tool behavior.
    resolved: Dict[str, Any] = {}
    supplied_as: Dict[str, str] = {}
    unknown, conflicts = set(), []
    for key, value in params.items():
        target = key if key in valid else aliases.get(key)
        if target is None:
            unknown.add(key)
            continue
        if target in resolved and supplied_as[target] != key:
            conflicts.append((supplied_as[target], key))
            continue
        resolved[target] = value
        supplied_as[target] = key

    if unknown:
        accepted = sorted(valid | set(aliases))
        msg = f"Valid parameters: {accepted}. Call describe_operations(names=['{name}']) for the schema."
        return {
            "success": False,
            "operation": name,
            "error": f"Unknown parameter(s) {sorted(unknown)} for '{name}'",
            "error_type": "validation_error",
            "message": msg,
            "suggestion": msg,
        }

    if conflicts:
        pairs = sorted(f"'{a}'/'{b}'" for a, b in conflicts)
        msg = f"Those are aliases of the same parameter — supply only one. Call describe_operations(names=['{name}']) for the schema."
        return {
            "success": False,
            "operation": name,
            "error": f"Conflicting parameter(s) {pairs} for '{name}'",
            "error_type": "validation_error",
            "message": msg,
            "suggestion": msg,
        }

    missing = [p for p in spec.required_params if p not in resolved]
    if missing:
        msg = f"Required parameters: {sorted(spec.required_params)}. Call describe_operations(names=['{name}']) for the schema, then retry with all required parameters supplied."
        return {
            "success": False,
            "operation": name,
            "error": f"Missing required parameter(s) {missing} for '{name}'",
            "error_type": "validation_error",
            "message": msg,
            "suggestion": msg,
        }

    kwargs = dict(resolved)
    if "ctx" in sig.parameters:
        kwargs["ctx"] = ctx
    elif "context" in sig.parameters:
        kwargs["context"] = ctx

    logger.info(f"invoke_operation: {name}({sorted(resolved)})")
    try:
        result = await spec.func(**kwargs)
        if not isinstance(result, dict):
            logger.error(
                f"invoke_operation: {name} returned {type(result).__name__}, expected dict"
            )
            msg = f"Operation '{name}' returned a malformed result. This is a server-side defect, not a bad parameter — consult server logs."
            return {
                "success": False,
                "operation": name,
                "error": f"Operation '{name}' returned {type(result).__name__}, expected an object",
                "error_type": "unexpected_error",
                "message": msg,
                "suggestion": msg,
            }
        return result
    except Exception as e:
        logger.error(f"invoke_operation: {name} raised an unexpected error: {e}")
        err_res = await format_error(e, f"invoke operation {name}")
        err_res["operation"] = name
        return err_res
