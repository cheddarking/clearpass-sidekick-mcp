"""Operation registry for progressive-disclosure tool exposure."""

import functools
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from pydantic import create_model
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined


@dataclass
class OperationSpec:
    name: str
    domain: str
    summary: str
    description: str
    parameters_schema: Dict[str, Any]
    func: Callable = field(repr=False)
    required_params: List[str] = field(default_factory=list)
    param_aliases: Dict[str, str] = field(default_factory=dict)


def _is_required_field(info: FieldInfo) -> bool:
    """True when a `Field(...)` declares no usable default (pydantic-required)."""
    return info.default is PydanticUndefined and info.default_factory is None


def required_parameters(func: Callable) -> List[str]:
    """Names of func's parameters the caller MUST supply (MCP Context excluded).

    Mirrors `_resolve_field_defaults`: a parameter is required when it has no
    default at all, or when its `Field(...)` default is `PydanticUndefined`
    (i.e. `Field(...)` / `Field(description=...)` with no default value).
    """
    required: List[str] = []
    for pname, param in inspect.signature(func).parameters.items():
        if pname in ("ctx", "context"):
            continue
        default = param.default
        if isinstance(default, FieldInfo):
            if _is_required_field(default):
                required.append(pname)
        elif default is inspect.Parameter.empty:
            required.append(pname)
    return required


def parameter_aliases(func: Callable) -> Dict[str, str]:
    """Map each declared pydantic `alias` to its real parameter name.

    Operations such as `list_system_events` declare
    ``filter_str: Optional[str] = Field(None, alias="filter")``. In legacy mode
    pydantic accepts the alias; the gateway uses this map so `invoke_operation`
    accepts it too.
    """
    aliases: Dict[str, str] = {}
    for pname, param in inspect.signature(func).parameters.items():
        if pname in ("ctx", "context"):
            continue
        default = param.default
        if isinstance(default, FieldInfo) and default.alias and default.alias != pname:
            aliases[default.alias] = pname
    return aliases


def _build_parameters_schema(func: Callable) -> Dict[str, Any]:
    """Build a JSON schema for func's parameters, excluding the MCP Context.

    Properties are keyed by the *real* parameter name (not the pydantic alias),
    because that is what the gateway dispatches on. Where an alias exists it is
    advertised honestly: in the property description and in a top-level
    ``aliases`` map, since `invoke_operation` accepts either spelling.
    """
    sig = inspect.signature(func)
    fields: Dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if pname in ("ctx", "context"):
            continue
        annotation = param.annotation if param.annotation is not inspect.Parameter.empty else Any
        if isinstance(param.default, FieldInfo):
            fields[pname] = (annotation, param.default)
        elif param.default is not inspect.Parameter.empty:
            fields[pname] = (annotation, param.default)
        else:
            fields[pname] = (annotation, ...)
    model = create_model(f"{func.__name__}_params", **fields)
    schema = model.model_json_schema(by_alias=False)

    aliases = parameter_aliases(func)
    if aliases:
        properties = schema.get("properties", {})
        for alias, pname in aliases.items():
            prop = properties.get(pname)
            if isinstance(prop, dict):
                note = f"Accepted as '{pname}' or '{alias}'."
                desc = prop.get("description")
                prop["description"] = f"{desc} {note}" if desc else note
        schema["aliases"] = dict(aliases)
    return schema


class OperationRegistry:
    def __init__(self) -> None:
        self._operations: Dict[str, OperationSpec] = {}

    def register(self, spec: OperationSpec) -> None:
        if spec.name in self._operations:
            raise ValueError(f"Operation '{spec.name}' is already registered")
        self._operations[spec.name] = spec

    def get(self, name: str) -> Optional[OperationSpec]:
        return self._operations.get(name)

    def all(self) -> List[OperationSpec]:
        return list(self._operations.values())

    def domains(self) -> List[str]:
        return sorted({s.domain for s in self._operations.values()})

    def search(self, domain: Optional[str] = None, query: Optional[str] = None) -> List[OperationSpec]:
        results = self.all()
        if domain:
            results = [s for s in results if s.domain == domain]
        if query:
            q = query.lower()
            results = [
                s for s in results
                if q in s.name.lower() or q in s.summary.lower() or q in s.description.lower()
            ]
        return sorted(results, key=lambda s: s.name)


registry = OperationRegistry()


def _resolve_field_defaults(func: Callable) -> Callable:
    """Wrap `func` so unsupplied `Field(...)` defaults become real values.

    Operations declare parameters as ``x: T = Field(default, description=...)``.
    When FastMCP registers such a function as a direct tool, pydantic resolves
    those defaults before the call. The gateway (`invoke_operation`) calls the
    function object directly, so any parameter the caller omits would otherwise
    arrive as a raw `FieldInfo` object and blow up inside the operation body.

    This wrapper closes that gap: omitted parameters get the Field's actual
    default, and omitted *required* parameters (``Field(...)``) raise a normal
    TypeError instead of silently passing a FieldInfo through.

    `functools.wraps` keeps `__wrapped__` set, so `inspect.signature` (and hence
    FastMCP's schema generation in legacy mode) still sees the original
    Field-annotated signature.
    """
    sig = inspect.signature(func)
    field_defaults = {
        name: param.default
        for name, param in sig.parameters.items()
        if isinstance(param.default, FieldInfo)
    }
    if not field_defaults:
        return func

    def _fill(args: tuple, kwargs: dict) -> dict:
        supplied = set(sig.bind_partial(*args, **kwargs).arguments)
        for name, info in field_defaults.items():
            if name in supplied:
                continue
            default = info.get_default(call_default_factory=True)
            if default is PydanticUndefined:
                raise TypeError(
                    f"{func.__name__}() missing required argument: '{name}'"
                )
            kwargs[name] = default
        return kwargs

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **_fill(args, kwargs))
    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **_fill(args, kwargs))

    return wrapper


def operation(domain: str) -> Callable:
    """Register an async function as an invokable ClearPass operation."""
    def decorator(func: Callable) -> Callable:
        doc = inspect.getdoc(func) or ""
        summary = doc.splitlines()[0].strip() if doc else func.__name__
        wrapped = _resolve_field_defaults(func)
        registry.register(OperationSpec(
            name=func.__name__,
            domain=domain,
            summary=summary,
            description=doc,
            parameters_schema=_build_parameters_schema(func),
            func=wrapped,
            required_params=required_parameters(func),
            param_aliases=parameter_aliases(func),
        ))
        return wrapped
    return decorator


def register_legacy_tools(mcp) -> int:
    """Register every operation as a direct MCP tool (pre-refactor behavior).

    Enabled via CLEARPASS_MCP_LEGACY_TOOLS=true.
    """
    for spec in registry.all():
        mcp.tool()(spec.func)
    return len(registry.all())
