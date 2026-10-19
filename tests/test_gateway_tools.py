from typing import Optional

import pytest
from pydantic import Field

from src.registry import registry, operation
from src.tools import gateway


@pytest.fixture(autouse=True)
def sample_ops():
    saved = dict(registry._operations)
    registry._operations.clear()

    @operation(domain="demo")
    async def demo_list(ctx=None, limit: int = 50) -> dict:
        """List demo items."""
        return {"success": True, "limit": limit}

    yield
    registry._operations.clear()
    registry._operations.update(saved)


class FakeCtx:
    async def info(self, msg): pass
    async def error(self, msg): pass


# NOTE: FastMCP 2.5.1's @mcp.tool() returns the plain (unwrapped) async
# function and registers the tool as a side effect, so there is no `.fn`
# attribute (present in newer FastMCP). Per the brief's note, the tests
# call the module-level functions directly.
@pytest.mark.asyncio
async def test_list_operations_returns_compact_index():
    result = await gateway.list_operations(FakeCtx(), domain="demo")
    assert result["total"] == 1
    entry = result["operations"][0]
    assert entry == {"name": "demo_list", "domain": "demo", "summary": "List demo items."}


@pytest.mark.asyncio
async def test_describe_operations_returns_schema():
    result = await gateway.describe_operations(FakeCtx(), names=["demo_list"])
    op = result["operations"][0]
    assert "limit" in op["parameters_schema"]["properties"]


@pytest.mark.asyncio
async def test_invoke_operation_calls_underlying_function():
    result = await gateway.invoke_operation(FakeCtx(), name="demo_list", params={"limit": 5})
    assert result == {"success": True, "limit": 5}


@pytest.mark.asyncio
async def test_invoke_unknown_operation_returns_actionable_error():
    result = await gateway.invoke_operation(FakeCtx(), name="nope", params={})
    assert result["success"] is False
    assert "list_operations" in result["message"]


@pytest.mark.asyncio
async def test_invoke_operation_wraps_unexpected_exception():
    @operation(domain="demo")
    async def demo_boom(ctx=None) -> dict:
        """Raise an unexpected error."""
        raise RuntimeError("boom")

    result = await gateway.invoke_operation(FakeCtx(), name="demo_boom", params={})
    assert result["success"] is False
    assert "boom" in result["error"]
    assert "demo_boom" in result["message"]


# --- Fix 1: required parameters are validated before dispatch ---------------

@pytest.mark.asyncio
async def test_invoke_missing_required_field_returns_structured_error():
    @operation(domain="demo")
    async def demo_create(
        ctx=None,
        name: str = Field(..., description="Name of the thing."),
        note: Optional[str] = Field(None, description="Optional note."),
    ) -> dict:
        """Create a demo thing."""
        return {"success": True, "name": name}

    result = await gateway.invoke_operation(FakeCtx(), name="demo_create", params={})
    assert result["success"] is False
    assert "name" in result["error"]
    assert "Missing required parameter" in result["error"]
    assert "describe_operations" in result["message"]
    # No raw TypeError text leaks through.
    assert "missing required argument" not in result["error"]


@pytest.mark.asyncio
async def test_invoke_missing_plain_required_arg_returns_structured_error():
    @operation(domain="demo")
    async def demo_plain(ctx=None, thing_id: str = None) -> dict:
        """Plain default."""
        return {"success": True, "thing_id": thing_id}

    @operation(domain="demo")
    async def demo_positional(ctx, thing_id: str) -> dict:
        """No default at all."""
        return {"success": True, "thing_id": thing_id}

    ok = await gateway.invoke_operation(FakeCtx(), name="demo_plain", params={})
    assert ok["success"] is True

    result = await gateway.invoke_operation(FakeCtx(), name="demo_positional", params={})
    assert result["success"] is False
    assert "thing_id" in result["error"]


@pytest.mark.asyncio
async def test_invoke_with_required_param_supplied_still_works():
    @operation(domain="demo")
    async def demo_ok(ctx=None, name: str = Field(..., description="Name.")) -> dict:
        """Create."""
        return {"success": True, "name": name}

    result = await gateway.invoke_operation(FakeCtx(), name="demo_ok", params={"name": "x"})
    assert result == {"success": True, "name": "x"}


# --- Fix 2: non-dict returns are wrapped ------------------------------------

@pytest.mark.asyncio
async def test_invoke_wraps_non_dict_return():
    @operation(domain="demo")
    async def demo_none(ctx=None):
        """Return nothing."""
        return None

    result = await gateway.invoke_operation(FakeCtx(), name="demo_none", params={})
    assert result["success"] is False
    assert "NoneType" in result["error"]
    assert "demo_none" in result["message"]


@pytest.mark.asyncio
async def test_invoke_wraps_non_dict_scalar_return():
    @operation(domain="demo")
    async def demo_list_return(ctx=None):
        """Return a list."""
        return [1, 2, 3]

    result = await gateway.invoke_operation(FakeCtx(), name="demo_list_return", params={})
    assert result["success"] is False
    assert "list" in result["error"]


# --- Fix 3: pydantic aliases are accepted through the gateway ---------------

@pytest.mark.asyncio
async def test_invoke_accepts_alias_and_real_name():
    @operation(domain="demo")
    async def demo_filter(
        ctx=None,
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
        limit: int = Field(25, description="Limit."),
    ) -> dict:
        """Filterable list."""
        return {"success": True, "filter_str": filter_str, "limit": limit}

    by_alias = await gateway.invoke_operation(
        FakeCtx(), name="demo_filter", params={"filter": '{"a": 1}'}
    )
    by_name = await gateway.invoke_operation(
        FakeCtx(), name="demo_filter", params={"filter_str": '{"a": 1}'}
    )
    assert by_alias["filter_str"] == '{"a": 1}'
    assert by_alias == by_name


@pytest.mark.asyncio
async def test_invoke_rejects_alias_and_name_together():
    @operation(domain="demo")
    async def demo_conflict(
        ctx=None,
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
    ) -> dict:
        """Filterable list."""
        return {"success": True, "filter_str": filter_str}

    result = await gateway.invoke_operation(
        FakeCtx(), name="demo_conflict", params={"filter": "a", "filter_str": "b"}
    )
    assert result["success"] is False
    assert "Conflicting parameter" in result["error"]


@pytest.mark.asyncio
async def test_unknown_parameter_error_lists_aliases_as_accepted():
    @operation(domain="demo")
    async def demo_unknown(
        ctx=None,
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
    ) -> dict:
        """Filterable list."""
        return {"success": True}

    result = await gateway.invoke_operation(
        FakeCtx(), name="demo_unknown", params={"nope": 1}
    )
    assert result["success"] is False
    assert "'filter'" in result["message"] and "'filter_str'" in result["message"]


@pytest.mark.asyncio
async def test_describe_operations_advertises_aliases_honestly():
    @operation(domain="demo")
    async def demo_described(
        ctx=None,
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
    ) -> dict:
        """Filterable list."""
        return {"success": True}

    result = await gateway.describe_operations(FakeCtx(), names=["demo_described"])
    schema = result["operations"][0]["parameters_schema"]
    # Keyed by the real parameter name, with the alias advertised.
    assert "filter_str" in schema["properties"]
    assert schema["aliases"] == {"filter": "filter_str"}
    assert "'filter'" in schema["properties"]["filter_str"]["description"]
