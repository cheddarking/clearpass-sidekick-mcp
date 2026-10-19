from typing import Optional

import pytest
from pydantic import Field

from src.registry import (
    registry,
    operation,
    OperationRegistry,
    parameter_aliases,
    required_parameters,
)


@pytest.fixture(autouse=True)
def clean_registry():
    saved = dict(registry._operations)
    registry._operations.clear()
    yield
    registry._operations.clear()
    registry._operations.update(saved)


def test_operation_decorator_registers_function():
    @operation(domain="demo")
    async def demo_op(name: str, limit: int = 50) -> dict:
        """List demo things.

        Longer description here."""
        return {"ok": True}

    spec = registry.get("demo_op")
    assert spec is not None
    assert spec.domain == "demo"
    assert spec.summary == "List demo things."
    props = spec.parameters_schema["properties"]
    assert "name" in props and "limit" in props
    assert "ctx" not in props


def test_search_by_domain_and_query():
    @operation(domain="alpha")
    async def alpha_list():
        """List alpha items."""

    @operation(domain="beta")
    async def beta_create():
        """Create a beta item."""

    assert [s.name for s in registry.search(domain="alpha")] == ["alpha_list"]
    assert [s.name for s in registry.search(query="create")] == ["beta_create"]
    assert len(registry.search()) == 2


def test_duplicate_registration_raises():
    @operation(domain="demo")
    async def dup_op():
        """First."""

    with pytest.raises(ValueError):
        @operation(domain="demo")
        async def dup_op():  # noqa: F811
            """Second."""


def test_required_parameters_distinguishes_field_defaults():
    async def op(
        ctx,
        positional: str,
        required_field: str = Field(..., description="Required."),
        described_only: str = Field(description="Also required."),
        defaulted_field: int = Field(25, description="Has a default."),
        plain_default: int = 5,
        optional_field: Optional[str] = Field(None, description="Optional."),
    ):
        """Doc."""

    assert required_parameters(op) == ["positional", "required_field", "described_only"]


def test_parameter_aliases_maps_alias_to_real_name():
    async def op(
        ctx,
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
        sort: Optional[str] = Field(None, description="Sort."),
    ):
        """Doc."""

    assert parameter_aliases(op) == {"filter": "filter_str"}


def test_spec_records_required_params_and_aliases():
    @operation(domain="demo")
    async def demo_aliased(
        ctx=None,
        name: str = Field(..., description="Name."),
        filter_str: Optional[str] = Field(None, alias="filter", description="Filter."),
    ) -> dict:
        """Aliased op."""
        return {"success": True}

    spec = registry.get("demo_aliased")
    assert spec.required_params == ["name"]
    assert spec.param_aliases == {"filter": "filter_str"}
    assert spec.parameters_schema["aliases"] == {"filter": "filter_str"}
    assert set(spec.parameters_schema["properties"]) == {"name", "filter_str"}


def test_real_operation_aliases_are_registered():
    """A real aliased operation in src/tools resolves `filter` -> `filter_str`."""
    # The clean_registry fixture empties the registry, so inspect the decorated
    # function directly rather than the (cleared) spec.
    from src.tools.audit_logs import list_system_events

    assert parameter_aliases(list_system_events) == {"filter": "filter_str"}
