"""
MCP tools for Guest Configuration.
Provides portal customization, template management, and guest settings.
"""

import logging
import json
from typing import Dict, Any, Union, Optional
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..models.guest_common import find_response_error
from ..utils import format_api_error

logger = logging.getLogger(__name__)


def _template_write_failure(response: Dict[str, Any], template_id: Any,
                            kind: str, verb: str) -> Optional[Dict[str, Any]]:
    """Return a structured failure when a 200 carries a template error body.

    ``PUT``/``PATCH print-template/<id>`` answers HTTP 200 with
    ``{"error": 1, "field": "id", "message": "There is no print template with
    ID %1"}`` for an id that does not exist, so the HTTP status alone cannot be
    trusted. (The pass-template twins return a real 422; the inconsistency is
    appliance-side, so both are checked.)
    """
    body_error = find_response_error(response, subject=f"{kind} template {verb}")
    if not body_error:
        return None
    return {
        "success": False,
        "error": body_error,
        "message": f"{kind.capitalize()} template {template_id} was NOT {verb}",
        "error_type": "api_response_error",
        "response": response
    }


# ============================================================================
# Pass Templates (Digital Passes - Apple Wallet / Google Pay)
# ============================================================================

@operation(domain="guest_configuration")
async def list_pass_templates(
    ctx: Context,
    filter: Optional[str] = Field(None, description="JSON filter expression"),
    sort: Optional[str] = Field(None, description="Sort ordering (default -id)"),
    offset: Optional[int] = Field(None, description="Zero based offset"),
    limit: Optional[int] = Field(None, description="Maximum number of items (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Calculate total item count")
) -> Dict[str, Any]:
    """
    List all digital pass templates for Apple Wallet / Google Pay.

    Pass templates enable mobile wallet credential delivery with customizable
    branding, colors, images, and fields.

    Use cases:
    - Review available pass templates
    - Find templates by filter criteria
    - Audit pass template configuration
    """
    await ctx.info(f"Listing pass templates (limit: {limit or 'default'})")

    try:
        client = await get_clearpass_client()
        response = await client.list_pass_templates(filter, sort, offset, limit, calculate_count)

        if "_embedded" in response and "items" in response["_embedded"]:
            templates = response["_embedded"]["items"]
        else:
            templates = response.get("items", [])

        return {
            "success": True,
            "total_count": len(templates),
            "templates": templates,
            "message": f"Retrieved {len(templates)} pass templates"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list pass templates: {e}")
        return await format_api_error(e, "list pass templates")
    except Exception as e:
        logger.error(f"Unexpected error listing pass templates: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def get_pass_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Pass template ID")
) -> Dict[str, Any]:
    """Get details of a specific digital pass template by ID."""
    await ctx.info(f"Retrieving pass template: {template_id}")

    try:
        client = await get_clearpass_client()
        response = await client.get_pass_template(template_id)

        return {
            "success": True,
            "template": response,
            "message": f"Retrieved pass template {template_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get pass template: {e}")
        return await format_api_error(e, "get pass template")
    except Exception as e:
        logger.error(f"Unexpected error getting pass template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def create_pass_template(
    ctx: Context,
    name: str = Field(..., description="Template name"),
    template_data: str = Field(..., description="Template configuration (JSON string)")
) -> Dict[str, Any]:
    """
    Create a new digital pass template.

    Creates a customizable template for Apple Wallet / Google Pay passes
    including branding, colors, images, fields, and location-based features.

    Use cases:
    - Create branded mobile wallet passes
    - Configure guest credential delivery via digital passes
    - Set up event-specific or location-specific passes
    """
    await ctx.info(f"Creating pass template: {name}")

    try:
        data = json.loads(template_data)
        data["name"] = name

        client = await get_clearpass_client()
        response = await client.create_pass_template(data)

        return {
            "success": True,
            "template": response,
            "message": f"Pass template '{name}' created successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create pass template: {e}")
        return await format_api_error(e, "create pass template")
    except Exception as e:
        logger.error(f"Unexpected error creating pass template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_pass_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Pass template ID"),
    template_data: str = Field(..., description="Fields to update (JSON string)")
) -> Dict[str, Any]:
    """Update some fields of a digital pass template (partial update)."""
    await ctx.info(f"Updating pass template: {template_id}")

    try:
        data = json.loads(template_data)

        client = await get_clearpass_client()
        response = await client.update_pass_template(template_id, data)

        failure = _template_write_failure(response, template_id, "pass", "updated")
        if failure:
            return failure

        return {
            "success": True,
            "template": response,
            "message": f"Pass template {template_id} updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update pass template: {e}")
        return await format_api_error(e, "update pass template")
    except Exception as e:
        logger.error(f"Unexpected error updating pass template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def replace_pass_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Pass template ID"),
    template_data: str = Field(..., description="Complete template configuration (JSON string)")
) -> Dict[str, Any]:
    """Replace a digital pass template completely (full replacement)."""
    await ctx.info(f"Replacing pass template: {template_id}")

    try:
        data = json.loads(template_data)

        client = await get_clearpass_client()
        response = await client.replace_pass_template(template_id, data)

        failure = _template_write_failure(response, template_id, "pass", "replaced")
        if failure:
            return failure

        return {
            "success": True,
            "template": response,
            "message": f"Pass template {template_id} replaced successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace pass template: {e}")
        return await format_api_error(e, "replace pass template")
    except Exception as e:
        logger.error(f"Unexpected error replacing pass template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def delete_pass_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Pass template ID"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a digital pass template."""
    await ctx.info(f"Deleting pass template: {template_id}")

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "Set confirm=True to proceed. This will remove the pass template from ClearPass.",
            "warning": "Deleting a pass template cannot be undone."
        }

    try:
        client = await get_clearpass_client()
        await client.delete_pass_template(template_id)

        return {
            "success": True,
            "message": f"Pass template {template_id} deleted successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete pass template: {e}")
        return await format_api_error(e, "delete pass template")
    except Exception as e:
        logger.error(f"Unexpected error deleting pass template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


# ============================================================================
# Print Templates (Receipt Printing)
# ============================================================================

@operation(domain="guest_configuration")
async def list_print_templates(
    ctx: Context,
    filter: Optional[str] = Field(None, description="JSON filter expression"),
    sort: Optional[str] = Field(None, description="Sort ordering (default -id)"),
    offset: Optional[int] = Field(None, description="Zero based offset"),
    limit: Optional[int] = Field(None, description="Maximum number of items (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Calculate total item count")
) -> Dict[str, Any]:
    """
    List all print receipt templates.

    Print templates customize the format and content of guest credential receipts
    for printing or email delivery.

    Use cases:
    - Review available print templates
    - Audit receipt customization
    - Find templates by filter criteria
    """
    await ctx.info(f"Listing print templates (limit: {limit or 'default'})")

    try:
        client = await get_clearpass_client()
        response = await client.list_print_templates(filter, sort, offset, limit, calculate_count)

        if "_embedded" in response and "items" in response["_embedded"]:
            templates = response["_embedded"]["items"]
        else:
            templates = response.get("items", [])

        return {
            "success": True,
            "total_count": len(templates),
            "templates": templates,
            "message": f"Retrieved {len(templates)} print templates"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list print templates: {e}")
        return await format_api_error(e, "list print templates")
    except Exception as e:
        logger.error(f"Unexpected error listing print templates: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def get_print_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Print template ID")
) -> Dict[str, Any]:
    """Get details of a specific print receipt template by ID."""
    await ctx.info(f"Retrieving print template: {template_id}")

    try:
        client = await get_clearpass_client()
        response = await client.get_print_template(template_id)

        return {
            "success": True,
            "template": response,
            "message": f"Retrieved print template {template_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get print template: {e}")
        return await format_api_error(e, "get print template")
    except Exception as e:
        logger.error(f"Unexpected error getting print template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def create_print_template(
    ctx: Context,
    name: str = Field(..., description="Template name"),
    template_data: str = Field(..., description="Template configuration (JSON string)")
) -> Dict[str, Any]:
    """
    Create a new print receipt template.

    Creates a customizable HTML/text template for guest credential receipts
    with branding, logos, and custom fields.

    Use cases:
    - Create branded receipt templates
    - Configure custom receipt layouts
    - Set up event-specific or department-specific receipts
    """
    await ctx.info(f"Creating print template: {name}")

    try:
        data = json.loads(template_data)
        data["name"] = name

        client = await get_clearpass_client()
        response = await client.create_print_template(data)

        return {
            "success": True,
            "template": response,
            "message": f"Print template '{name}' created successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create print template: {e}")
        return await format_api_error(e, "create print template")
    except Exception as e:
        logger.error(f"Unexpected error creating print template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_print_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Print template ID"),
    template_data: str = Field(..., description="Fields to update (JSON string)")
) -> Dict[str, Any]:
    """Update some fields of a print receipt template (partial update)."""
    await ctx.info(f"Updating print template: {template_id}")

    try:
        data = json.loads(template_data)

        client = await get_clearpass_client()
        response = await client.update_print_template(template_id, data)

        failure = _template_write_failure(response, template_id, "print", "updated")
        if failure:
            return failure

        return {
            "success": True,
            "template": response,
            "message": f"Print template {template_id} updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update print template: {e}")
        return await format_api_error(e, "update print template")
    except Exception as e:
        logger.error(f"Unexpected error updating print template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def replace_print_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Print template ID"),
    template_data: str = Field(..., description="Complete template configuration (JSON string)")
) -> Dict[str, Any]:
    """Replace a print receipt template completely (full replacement)."""
    await ctx.info(f"Replacing print template: {template_id}")

    try:
        data = json.loads(template_data)

        client = await get_clearpass_client()
        response = await client.replace_print_template(template_id, data)

        failure = _template_write_failure(response, template_id, "print", "replaced")
        if failure:
            return failure

        return {
            "success": True,
            "template": response,
            "message": f"Print template {template_id} replaced successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "template_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace print template: {e}")
        return await format_api_error(e, "replace print template")
    except Exception as e:
        logger.error(f"Unexpected error replacing print template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def delete_print_template(
    ctx: Context,
    template_id: Union[int, str] = Field(..., description="Print template ID"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a print receipt template."""
    await ctx.info(f"Deleting print template: {template_id}")

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "Set confirm=True to proceed. This will remove the print template from ClearPass.",
            "warning": "Deleting a print template cannot be undone."
        }

    try:
        client = await get_clearpass_client()
        await client.delete_print_template(template_id)

        return {
            "success": True,
            "message": f"Print template {template_id} deleted successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete print template: {e}")
        return await format_api_error(e, "delete print template")
    except Exception as e:
        logger.error(f"Unexpected error deleting print template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


# ============================================================================
# Web Login Pages (Captive Portal)
# ============================================================================

@operation(domain="guest_configuration")
async def list_weblogin_pages(
    ctx: Context,
    filter: Optional[str] = Field(None, description="JSON filter expression"),
    sort: Optional[str] = Field(None, description="Sort ordering (default +name)"),
    offset: Optional[int] = Field(None, description="Zero based offset"),
    limit: Optional[int] = Field(None, description="Maximum number of items (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Calculate total item count")
) -> Dict[str, Any]:
    """
    List all web login pages (captive portals).

    Web login pages provide customizable captive portal interfaces for
    guest authentication and network access.

    Use cases:
    - Review available captive portal pages
    - Audit portal configuration
    - Find pages by filter criteria
    """
    await ctx.info(f"Listing web login pages (limit: {limit or 'default'})")

    try:
        client = await get_clearpass_client()
        response = await client.list_weblogin_pages(filter, sort, offset, limit, calculate_count)

        if "_embedded" in response and "items" in response["_embedded"]:
            pages = response["_embedded"]["items"]
        else:
            pages = response.get("items", [])

        return {
            "success": True,
            "total_count": len(pages),
            "pages": pages,
            "message": f"Retrieved {len(pages)} web login pages"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list web login pages: {e}")
        return await format_api_error(e, "list web login pages")
    except Exception as e:
        logger.error(f"Unexpected error listing web login pages: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def get_weblogin_page(
    ctx: Context,
    page_id: Union[int, str] = Field(..., description="Web login page ID")
) -> Dict[str, Any]:
    """Get details of a specific web login page by ID."""
    await ctx.info(f"Retrieving web login page: {page_id}")

    try:
        client = await get_clearpass_client()
        response = await client.get_weblogin_page(page_id)

        return {
            "success": True,
            "page": response,
            "message": f"Retrieved web login page {page_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get web login page: {e}")
        return await format_api_error(e, "get web login page")
    except Exception as e:
        logger.error(f"Unexpected error getting web login page: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def create_weblogin_page(
    ctx: Context,
    name: str = Field(..., description="Page name"),
    page_data: str = Field(..., description="Page configuration (JSON string)")
) -> Dict[str, Any]:
    """
    Create a new web login page (captive portal).

    Creates a customizable captive portal page with vendor presets,
    form configuration, HTTPS settings, and branding.

    Use cases:
    - Create branded captive portals
    - Configure vendor-specific login pages
    - Set up department or location-specific portals
    """
    await ctx.info(f"Creating web login page: {name}")

    try:
        data = json.loads(page_data)
        data["name"] = name

        client = await get_clearpass_client()
        response = await client.create_weblogin_page(data)

        return {
            "success": True,
            "page": response,
            "message": f"Web login page '{name}' created successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "page_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create web login page: {e}")
        return await format_api_error(e, "create web login page")
    except Exception as e:
        logger.error(f"Unexpected error creating web login page: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_weblogin_page(
    ctx: Context,
    page_id: Union[int, str] = Field(..., description="Web login page ID"),
    page_data: str = Field(..., description="Fields to update (JSON string)")
) -> Dict[str, Any]:
    """Update some fields of a web login page by ID (partial update)."""
    await ctx.info(f"Updating web login page: {page_id}")

    try:
        data = json.loads(page_data)

        client = await get_clearpass_client()
        response = await client.update_weblogin_page(page_id, data)

        return {
            "success": True,
            "page": response,
            "message": f"Web login page {page_id} updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "page_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update web login page: {e}")
        return await format_api_error(e, "update web login page")
    except Exception as e:
        logger.error(f"Unexpected error updating web login page: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def replace_weblogin_page(
    ctx: Context,
    page_id: Union[int, str] = Field(..., description="Web login page ID"),
    page_data: str = Field(..., description="Complete page configuration (JSON string)")
) -> Dict[str, Any]:
    """Replace a web login page by ID completely (full replacement)."""
    await ctx.info(f"Replacing web login page: {page_id}")

    try:
        data = json.loads(page_data)

        client = await get_clearpass_client()
        response = await client.replace_weblogin_page(page_id, data)

        return {
            "success": True,
            "page": response,
            "message": f"Web login page {page_id} replaced successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "page_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace web login page: {e}")
        return await format_api_error(e, "replace web login page")
    except Exception as e:
        logger.error(f"Unexpected error replacing web login page: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def delete_weblogin_page(
    ctx: Context,
    page_id: Union[int, str] = Field(..., description="Web login page ID"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a web login page by ID."""
    await ctx.info(f"Deleting web login page: {page_id}")

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "Set confirm=True to proceed. This will remove the web login page from ClearPass.",
            "warning": "Deleting a web login page cannot be undone."
        }

    try:
        client = await get_clearpass_client()
        await client.delete_weblogin_page(page_id)

        return {
            "success": True,
            "message": f"Web login page {page_id} deleted successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete web login page: {e}")
        return await format_api_error(e, "delete web login page")
    except Exception as e:
        logger.error(f"Unexpected error deleting web login page: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def get_weblogin_page_by_name(
    ctx: Context,
    page_name: str = Field(..., description="Web login page name")
) -> Dict[str, Any]:
    """Get details of a specific web login page by page name."""
    await ctx.info(f"Retrieving web login page by name: {page_name}")

    try:
        client = await get_clearpass_client()
        response = await client.get_weblogin_page_by_name(page_name)

        return {
            "success": True,
            "page": response,
            "message": f"Retrieved web login page '{page_name}'"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get web login page by name: {e}")
        return await format_api_error(e, "get web login page by name")
    except Exception as e:
        logger.error(f"Unexpected error getting web login page by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_weblogin_page_by_name(
    ctx: Context,
    page_name: str = Field(..., description="Web login page name"),
    page_data: str = Field(..., description="Fields to update (JSON string)")
) -> Dict[str, Any]:
    """Update some fields of a web login page by name (partial update)."""
    await ctx.info(f"Updating web login page by name: {page_name}")

    try:
        data = json.loads(page_data)

        client = await get_clearpass_client()
        response = await client.update_weblogin_page_by_name(page_name, data)

        return {
            "success": True,
            "page": response,
            "message": f"Web login page '{page_name}' updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "page_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update web login page by name: {e}")
        return await format_api_error(e, "update web login page by name")
    except Exception as e:
        logger.error(f"Unexpected error updating web login page by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def replace_weblogin_page_by_name(
    ctx: Context,
    page_name: str = Field(..., description="Web login page name"),
    page_data: str = Field(..., description="Complete page configuration (JSON string)")
) -> Dict[str, Any]:
    """Replace a web login page by name completely (full replacement)."""
    await ctx.info(f"Replacing web login page by name: {page_name}")

    try:
        data = json.loads(page_data)

        client = await get_clearpass_client()
        response = await client.replace_weblogin_page_by_name(page_name, data)

        return {
            "success": True,
            "page": response,
            "message": f"Web login page '{page_name}' replaced successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "page_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace web login page by name: {e}")
        return await format_api_error(e, "replace web login page by name")
    except Exception as e:
        logger.error(f"Unexpected error replacing web login page by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def delete_weblogin_page_by_name(
    ctx: Context,
    page_name: str = Field(..., description="Web login page name"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a web login page by name."""
    await ctx.info(f"Deleting web login page by name: {page_name}")

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "Set confirm=True to proceed. This will remove the web login page from ClearPass.",
            "warning": "Deleting a web login page cannot be undone."
        }

    try:
        client = await get_clearpass_client()
        await client.delete_weblogin_page_by_name(page_name)

        return {
            "success": True,
            "message": f"Web login page '{page_name}' deleted successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete web login page by name: {e}")
        return await format_api_error(e, "delete web login page by name")
    except Exception as e:
        logger.error(f"Unexpected error deleting web login page by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


# ============================================================================
# Guest Authentication Settings
# ============================================================================

@operation(domain="guest_configuration")
async def get_guest_authentication_settings(ctx: Context) -> Dict[str, Any]:
    """
    Get guest authentication global settings.

    Retrieves Configuration -> Authentication settings including HTTPS redirect,
    Change of Authorization, RADIUS vendor defaults, and internal auth type.

    Use cases:
    - Review current authentication configuration
    - Audit security settings
    - Check CoA and RADIUS configuration
    """
    await ctx.info("Retrieving guest authentication settings")

    try:
        client = await get_clearpass_client()
        response = await client.get_guest_authentication_settings()

        return {
            "success": True,
            "settings": response,
            "message": "Retrieved guest authentication settings"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get guest authentication settings: {e}")
        return await format_api_error(e, "get guest authentication settings")
    except Exception as e:
        logger.error(f"Unexpected error getting guest authentication settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def create_guest_authentication_settings(
    ctx: Context,
    settings_data: str = Field(..., description="Settings configuration (JSON string, requires g_radius_internal_auth_type)")
) -> Dict[str, Any]:
    """
    Initialize guest authentication global settings.

    Configures Configuration -> Authentication settings. Requires g_radius_internal_auth_type field.

    Use cases:
    - Initialize authentication configuration
    - Set HTTPS redirect policy
    - Configure Change of Authorization
    - Set RADIUS vendor defaults
    """
    await ctx.info("Creating guest authentication settings")

    try:
        data = json.loads(settings_data)

        if "g_radius_internal_auth_type" not in data:
            return {
                "success": False,
                "error": "Missing required field: g_radius_internal_auth_type",
                "message": "The g_radius_internal_auth_type field is required"
            }

        client = await get_clearpass_client()
        response = await client.create_guest_authentication_settings(data)

        return {
            "success": True,
            "settings": response,
            "message": "Guest authentication settings created successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "settings_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create guest authentication settings: {e}")
        return await format_api_error(e, "create guest authentication settings")
    except Exception as e:
        logger.error(f"Unexpected error creating guest authentication settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_guest_authentication_settings(
    ctx: Context,
    settings_data: str = Field(..., description="Settings to update (JSON string, requires g_radius_internal_auth_type)")
) -> Dict[str, Any]:
    """
    Update guest authentication global settings.

    Modifies Configuration -> Authentication settings. Requires g_radius_internal_auth_type field.

    Use cases:
    - Update HTTPS redirect policy
    - Enable/disable Change of Authorization
    - Modify RADIUS vendor defaults
    - Change internal auth type
    """
    await ctx.info("Updating guest authentication settings")

    try:
        data = json.loads(settings_data)

        if "g_radius_internal_auth_type" not in data:
            return {
                "success": False,
                "error": "Missing required field: g_radius_internal_auth_type",
                "message": "The g_radius_internal_auth_type field is required"
            }

        client = await get_clearpass_client()
        response = await client.update_guest_authentication_settings(data)

        return {
            "success": True,
            "settings": response,
            "message": "Guest authentication settings updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "settings_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update guest authentication settings: {e}")
        return await format_api_error(e, "update guest authentication settings")
    except Exception as e:
        logger.error(f"Unexpected error updating guest authentication settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


# ============================================================================
# Guest Manager Settings
# ============================================================================

@operation(domain="guest_configuration")
async def get_guest_manager_settings(ctx: Context) -> Dict[str, Any]:
    """
    Get guest manager global settings.

    Retrieves Configuration -> Guest Manager settings including username/password
    generation, expiration options, notifications, and site configuration.

    Use cases:
    - Review current guest manager configuration
    - Audit password complexity and generation settings
    - Check notification configuration
    - Review site WiFi settings
    """
    await ctx.info("Retrieving guest manager settings")

    try:
        client = await get_clearpass_client()
        response = await client.get_guest_manager_settings()

        return {
            "success": True,
            "settings": response,
            "message": "Retrieved guest manager settings"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get guest manager settings: {e}")
        return await format_api_error(e, "get guest manager settings")
    except Exception as e:
        logger.error(f"Unexpected error getting guest manager settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def create_guest_manager_settings(
    ctx: Context,
    settings_data: str = Field(..., description="Settings configuration (JSON string, requires multiple fields)")
) -> Dict[str, Any]:
    """
    Initialize guest manager global settings.

    Configures Configuration -> Guest Manager settings. Requires multiple fields
    for username/password generation and expiration options.

    Use cases:
    - Initialize guest manager configuration
    - Set username/password generation rules
    - Configure account expiration policies
    - Set up notification templates
    """
    await ctx.info("Creating guest manager settings")

    try:
        data = json.loads(settings_data)

        required_fields = [
            "random_username_method", "random_username_length",
            "random_password_method", "random_password_length",
            "guest_password_complexity", "guest_password_minimum",
            "guest_do_expire", "guest_account_expiry_options",
            "guest_modify_expire_time_options", "guest_lifetime_options"
        ]

        missing = [f for f in required_fields if f not in data]
        if missing:
            return {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing)}",
                "message": "Several fields are required for guest manager settings"
            }

        client = await get_clearpass_client()
        response = await client.create_guest_manager_settings(data)

        return {
            "success": True,
            "settings": response,
            "message": "Guest manager settings created successfully"
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "settings_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create guest manager settings: {e}")
        return await format_api_error(e, "create guest manager settings")
    except Exception as e:
        logger.error(f"Unexpected error creating guest manager settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }


@operation(domain="guest_configuration")
async def update_guest_manager_settings(
    ctx: Context,
    settings_data: str = Field(..., description="Settings to update (JSON string, requires multiple fields)")
) -> Dict[str, Any]:
    """
    Update guest manager global settings.

    Modifies Configuration -> Guest Manager settings. Requires multiple fields
    for username/password generation and expiration options.

    Use cases:
    - Update password complexity requirements
    - Modify username generation rules
    - Change expiration policies
    - Update notification settings
    - Configure site WiFi credentials
    """
    await ctx.info("Updating guest manager settings")

    try:
        data = json.loads(settings_data)

        required_fields = [
            "random_username_method", "random_username_length",
            "random_password_method", "random_password_length",
            "guest_password_complexity", "guest_password_minimum",
            "guest_do_expire", "guest_account_expiry_options",
            "guest_modify_expire_time_options", "guest_lifetime_options"
        ]

        missing = [f for f in required_fields if f not in data]
        if missing:
            return {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing)}",
                "message": "Several fields are required for guest manager settings"
            }

        client = await get_clearpass_client()
        response = await client.update_guest_manager_settings(data)

        return {
            "success": True,
            "settings": response,
            "message": "Guest manager settings updated successfully",
            "updated_fields": list(data.keys())
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Invalid JSON: {str(e)}",
            "message": "settings_data must be valid JSON"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update guest manager settings: {e}")
        return await format_api_error(e, "update guest manager settings")
    except Exception as e:
        logger.error(f"Unexpected error updating guest manager settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred"
        }
