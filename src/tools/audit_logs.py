"""
MCP tools for Audit, Logs, and Insight management.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error, format_clarification_needed
from ..models.audit import (
    SystemEventCreate,
    InsightAlertConfig,
    InsightReportConfig
)

logger = logging.getLogger(__name__)


# Insight collection endpoints, used to tell "the feature is missing" apart from
# "that particular id does not exist" -- both surface as a bare 404.
_INSIGHT_COLLECTIONS = {"alerts": "alert", "reports": "report"}


async def _insight_feature_available(feature: str) -> Optional[bool]:
    """Probe the Insight collection endpoint for ``feature``.

    Returns True if the collection responds, False if the collection itself is a
    404 (feature genuinely unavailable / unlicensed), and None if the probe could
    not decide (auth error, timeout, 5xx...).

    The client is fetched here rather than passed in: this runs from an ``except``
    handler, where a caller-local ``client`` may never have been bound.
    """
    endpoint = _INSIGHT_COLLECTIONS[feature]
    try:
        client = await get_clearpass_client()
        await client._make_request("GET", endpoint, params={"limit": 1})
        return True
    except ClearPassAPIError as probe_error:
        if probe_error.status_code == 404:
            return False
        return None
    except Exception:  # pragma: no cover - defensive
        return None


async def _handle_insight_item_404(feature: str, subject: str) -> Dict[str, Any]:
    """Build the response for a 404 on a *specific* Insight item.

    A 404 from ``alert/<id>`` or ``report/<id>`` used to be translated blindly to
    ``{"error": "Feature not available"}``, which made a genuine "no such alert
    id" indistinguishable from a licensing gap. The collection endpoint answers
    that question, so probe it before deciding.
    """
    available = await _insight_feature_available(feature)
    collection = _INSIGHT_COLLECTIONS[feature]

    if available is False:
        return {
            "success": False,
            "error": "Feature not available",
            "message": (
                f"Insight {feature} are not available on this ClearPass "
                f"installation: the '{collection}' collection endpoint also "
                "returns 404. This may require specific licenses or be "
                "unavailable in this version."
            ),
            "status_code": 404,
        }

    if available is True:
        return {
            "success": False,
            "error": "Not found",
            "message": (
                f"{subject} was not found. The Insight {feature} feature IS "
                f"available on this appliance (the '{collection}' collection "
                "endpoint responds), so this 404 means the requested item does "
                "not exist."
            ),
            "status_code": 404,
        }

    return {
        "success": False,
        "error": "Not found",
        "message": (
            f"{subject} was not found. Could not determine whether the Insight "
            f"{feature} feature is available -- the probe of the '{collection}' "
            "collection endpoint did not return a conclusive answer."
        ),
        "status_code": 404,
    }


@operation(domain="audit_logs")
async def get_admin_login_audit(
    ctx: Context,
    username: str = Field(..., description="Admin username to retrieve login audit for.")
) -> Dict[str, Any]:
    """
    Get previous login details for a specific admin user.
    Maps to 'get_login_audit_by_name' in pyclearpass.
    """
    await ctx.info(f"Getting login audit for admin: {username}")
    try:
        client = await get_clearpass_client()
        response = await client.get_admin_login_audit(username)
        # The response structure for login audit might be a list or a single object.
        # Adjust based on actual API response. Assuming it's a list of login attempts.
        if isinstance(response, list):
            audit_entries = response
        elif isinstance(response, dict):
            # If it's a dict, it might be a single record or a wrapped response.
            # For now, assume it's a list if not directly a list.
            # This might need adjustment based on actual API behavior.
            audit_entries = response.get("_embedded", {}).get("items", [response] if response else []) 
        else:
            audit_entries = []

        return {
            "success": True,
            "username": username,
            "login_audit_entries": audit_entries,
            "count": len(audit_entries),
            "message": f"Retrieved {len(audit_entries)} login audit entries for {username}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get admin login audit: {e}")
        return await format_api_error(e, "get admin login audit")
    except Exception as e:
        logger.error(f"Unexpected error getting admin login audit: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def list_system_events(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"level\": \"ERROR\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering. Note: The ClearPass API may not support sorting for system events. If sorting fails, omit this parameter."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000). Default 25."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    Get a list of system events with optional filtering and pagination.
    Maps to 'get_system_event' in pyclearpass.
    """
    await ctx.info("Listing system events...")
    try:
        client = await get_clearpass_client()
        params = {
            "filter_str": filter_str,
            "sort": sort,
            "offset": offset,
            "limit": limit,
            "calculate_count": calculate_count
        }
        active_params = {k: v for k, v in params.items() if v is not None}
        response = await client.list_system_events(**active_params)
        
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "system_events": items,
            "message": f"Retrieved {len(items)} system events."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list system events: {e}")
        return await format_api_error(e, "list system events")
    except Exception as e:
        logger.error(f"Unexpected error listing system events: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def create_system_event(
    ctx: Context,
    source: str = Field(..., description="Source of the event."),
    level: str = Field(..., description="Level of the event (e.g., INFO, WARN, ERROR, FATAL)."),
    category: str = Field(..., description="Category of the event."),
    action: str = Field(..., description="Action related to the event."),
    description: str = Field(..., description="Description of the event."),
    timestamp: str = Field(..., description="Timestamp for the event (ISO 8601 format e.g. YYYY-MM-DDTHH:mm:ss.sssZ).")
) -> Dict[str, Any]:
    """
    Create a new system event.
    Maps to 'new_system_event' in pyclearpass.
    """
    await ctx.info(f"Creating system event from source: {source}, level: {level}")
    try:
        client = await get_clearpass_client()
        event_data = SystemEventCreate(
            source=source, 
            level=level, 
            category=category, 
            action=action, 
            description=description, 
            timestamp=timestamp
        )
        response = await client.create_system_event(event_data.model_dump(exclude_none=True))
        # Expect 201 Created, response might contain the created event with its ID
        return {
            "success": True,
            "message": "System event created successfully.",
            "created_event": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create system event: {e}")
        return await format_api_error(e, "create system event")
    except Exception as e:
        logger.error(f"Unexpected error creating system event: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def list_insight_alerts(
    ctx: Context,
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000). Default 25."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    Get all Insight alert configurations.
    Maps to 'get_alert' in pyclearpass.
    Note: Insight features may not be available on all ClearPass installations or may require specific licenses.
    """
    await ctx.info("Listing Insight alerts...")
    try:
        client = await get_clearpass_client()
        params = {k:v for k,v in locals().items() if k not in ['ctx', 'client'] and v is not None}
        response = await client.list_insight_alerts(**params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "insight_alerts": items,
            "message": f"Retrieved {len(items)} Insight alerts."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Insight alerts: {e}")
        if e.status_code == 404:
            # Collection endpoint itself 404s -> the feature really is absent.
            return {
                "success": False,
                "error": "Feature not available",
                "message": "Insight alerts are not available on this ClearPass installation: the 'alert' collection endpoint returns 404. This may require specific licenses or be unavailable in this version.",
                "status_code": 404
            }
        return await format_api_error(e, "list insight alerts")
    except Exception as e:
        logger.error(f"Unexpected error listing Insight alerts: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def create_insight_alert(
    ctx: Context,
    name: str = Field(..., description="Name of the alert."),
    category: str = Field(..., description="Category of the alert (e.g., 'Authentication', 'Endpoint')."),
    subcategory: str = Field(..., description="Subcategory (template name) of the alert."),
    severity: str = Field(..., description="Severity: 'CRITICAL' or 'WARNING'. Ensure exact case match for API."),
    threshold: int = Field(..., description="Numeric threshold value to trigger the alert."),
    interval: int = Field(..., description="Numeric interval for checking the alert condition."),
    interval_unit: str = Field(..., description="Interval unit: 'MINUTE' or 'HOUR'. Ensure exact case match for API."),
    description: Optional[str] = Field(None, description="Description of the alert."),
    email_targets: Optional[List[str]] = Field(None, description="List of email addresses for notifications."),
    sms_targets: Optional[List[str]] = Field(None, description="List of SMS targets for notifications."),
    config: Optional[Dict[str, Any]] = Field(None, description="Alert filter configurations and CSV column settings. Refer to API docs for structure."),
    is_enabled: bool = Field(default=True, description="Enable/Disable the alert."),
    is_muted: bool = Field(default=False, description="Mute/Unmute the alert.")
) -> Dict[str, Any]:
    """
    Create an Insight alert configuration.
    Maps to 'new_alert' in pyclearpass.
    Requires specific values for severity ('CRITICAL', 'WARNING') and interval_unit ('MINUTE', 'HOUR').
    """
    await ctx.info(f"Creating Insight alert: {name}")
    # Validate severity and interval_unit
    if severity.upper() not in ["CRITICAL", "WARNING"]:
        return {"success": False, "error": "Invalid severity. Must be 'CRITICAL' or 'WARNING'."}
    if interval_unit.upper() not in ["MINUTE", "HOUR"]:
        return {"success": False, "error": "Invalid interval_unit. Must be 'MINUTE' or 'HOUR'."}
    
    try:
        client = await get_clearpass_client()
        alert_data = InsightAlertConfig(
            name=name, category=category, subcategory=subcategory, severity=severity.upper(),
            threshold=threshold, interval=interval, interval_unit=interval_unit.upper(),
            description=description, email_targets=email_targets, sms_targets=sms_targets,
            config=config, is_enabled=is_enabled, is_muted=is_muted
            # id is not passed for creation
        )
        response = await client.create_insight_alert(alert_data.model_dump(exclude_none=True, exclude={'id'}))
        return {
            "success": True,
            "message": "Insight alert created successfully.",
            "created_alert": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create Insight alert: {e}")
        if e.status_code == 404:
            # Collection endpoint itself 404s -> the feature really is absent.
            return {
                "success": False,
                "error": "Feature not available",
                "message": "Insight alerts are not available on this ClearPass installation: the 'alert' collection endpoint returns 404. This may require specific licenses or be unavailable in this version.",
                "status_code": 404
            }
        return await format_api_error(e, "create insight alert")
    except Exception as e:
        logger.error(f"Unexpected error creating Insight alert: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def get_insight_alert_details(
    ctx: Context,
    alert_id: Optional[int] = Field(None, description="ID of the Insight alert. Provide this or alert_name."),
    alert_name: Optional[str] = Field(None, description="Name of the Insight alert. Provide this or alert_id.")
) -> Dict[str, Any]:
    """
    Get details for a specific Insight alert configuration by ID or name.
    Maps to 'get_alert_by_id' or 'get_alert_by_name' in pyclearpass.
    """
    if alert_id is None and alert_name is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the Insight alert.",
            question="Please provide either 'alert_id' or 'alert_name'."
        )
    
    log_identifier = f"ID: {alert_id}" if alert_id is not None else f"name: {alert_name}"
    await ctx.info(f"Getting Insight alert details for {log_identifier}")
    try:
        client = await get_clearpass_client()
        if alert_id is not None:
            response = await client.get_insight_alert_by_id(alert_id)
        else: # alert_name must be present
            response = await client.get_insight_alert_by_name(alert_name)
        return {
            "success": True,
            "insight_alert_details": response,
            "message": f"Insight alert details retrieved successfully for {log_identifier}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Insight alert details: {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("alerts", f"Insight alert {log_identifier}")
        return await format_api_error(e, f"get insight alert details for {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error getting Insight alert details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def update_insight_alert(
    ctx: Context,
    alert_id: int = Field(..., description="ID of the Insight alert to update."),
    # Include all fields from InsightAlertConfig as optional for partial update
    name: Optional[str] = Field(None, description="New name for the alert."),
    description: Optional[str] = Field(None, description="New description for the alert."),
    category: Optional[str] = Field(None, description="New category for the alert."),
    subcategory: Optional[str] = Field(None, description="New subcategory for the alert."),
    email_targets: Optional[List[str]] = Field(None, description="New list of email targets."),
    sms_targets: Optional[List[str]] = Field(None, description="New list of SMS targets."),
    config: Optional[Dict[str, Any]] = Field(None, description="New filter/CSV configurations."),
    severity: Optional[str] = Field(None, description="New severity: 'CRITICAL' or 'WARNING'."),
    threshold: Optional[int] = Field(None, description="New numeric threshold value."),
    interval: Optional[int] = Field(None, description="New numeric interval."),
    interval_unit: Optional[str] = Field(None, description="New interval unit: 'MINUTE' or 'HOUR'."),
    is_enabled: Optional[bool] = Field(None, description="New enable/disable status."),
    is_muted: Optional[bool] = Field(None, description="New mute/unmute status."),
    replace_all: bool = Field(False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH). Default is PATCH.")
) -> Dict[str, Any]:
    """
    Update an existing Insight alert configuration by ID. Supports partial (PATCH) or full (PUT) update.
    Maps to 'update_alert_by_id' (PATCH) or 'replace_alert_by_id' (PUT) in pyclearpass.
    """
    await ctx.info(f"Updating Insight alert ID: {alert_id} (Replace all: {replace_all})")
    update_data = {
        k: v for k, v in {
            "name": name, "description": description, "category": category, "subcategory": subcategory,
            "email_targets": email_targets, "sms_targets": sms_targets, "config": config,
            "severity": severity.upper() if severity else None, 
            "threshold": threshold, "interval": interval, 
            "interval_unit": interval_unit.upper() if interval_unit else None, 
            "is_enabled": is_enabled, "is_muted": is_muted
        }.items() if v is not None
    }

    if not update_data:
        return {"success": False, "error": "No update parameters provided.", "message": "Please provide at least one field to update."}

    # Validate severity and interval_unit if provided
    if "severity" in update_data and update_data["severity"] not in ["CRITICAL", "WARNING"]:
        return {"success": False, "error": "Invalid severity. Must be 'CRITICAL' or 'WARNING'."}
    if "interval_unit" in update_data and update_data["interval_unit"] not in ["MINUTE", "HOUR"]:
        return {"success": False, "error": "Invalid interval_unit. Must be 'MINUTE' or 'HOUR'."}

    try:
        client = await get_clearpass_client()
        if replace_all:
            # For PUT, all required fields for InsightAlertConfig (excluding id) must be present or fetched first.
            # This tool currently only sends what the user provides. For a true PUT, one might need to fetch existing,
            # merge, then PUT. The pyclearpass `replace_alert_by_id` expects a full body.
            # The plan lists both update and replace, so this tool should support both intentions.
            # Current approach: if replace_all=True, the user MUST provide ALL required fields for a full alert object.
            # Let's verify all required fields for InsightAlertConfig for a PUT call (excluding 'id' which is path param)
            required_for_put = {'name', 'category', 'subcategory', 'severity', 'threshold', 'interval', 'interval_unit'}
            missing_for_put = required_for_put - set(update_data.keys())
            if missing_for_put:
                 return {
                    "success": False, 
                    "error": f"Missing required fields for full replacement (PUT): {', '.join(missing_for_put)}",
                    "message": "When replace_all is True, you must provide all required alert configuration fields."
                 }
            response = await client.replace_insight_alert_by_id(alert_id, update_data)
            action_taken = "replaced"
        else:
            response = await client.update_insight_alert_by_id(alert_id, update_data)
            action_taken = "updated"
        
        return {
            "success": True,
            "message": f"Insight alert {action_taken} successfully.",
            "updated_alert": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Insight alert: {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("alerts", f"Insight alert ID {alert_id}")
        return await format_api_error(e, f"update insight alert ID {alert_id}")
    except Exception as e:
        logger.error(f"Unexpected error updating Insight alert: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def delete_insight_alert(
    ctx: Context,
    alert_id: int = Field(..., description="ID of the Insight alert to delete."),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety). Default is False.")
) -> Dict[str, Any]:
    """
    Delete an Insight alert configuration by ID.
    Maps to 'delete_alert_by_id' in pyclearpass.
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete Insight alert ID {alert_id}? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting Insight alert ID: {alert_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_insight_alert_by_id(alert_id) # Usually returns 204 No Content
        return {
            "success": True,
            "message": f"Insight alert ID {alert_id} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete Insight alert: {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("alerts", f"Insight alert ID {alert_id}")
        return await format_api_error(e, f"delete insight alert ID {alert_id}")
    except Exception as e:
        logger.error(f"Unexpected error deleting Insight alert: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def list_insight_reports(
    ctx: Context,
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return. Default 25."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    Get all Insight report configurations.
    Maps to 'get_report' in pyclearpass.
    Note: Insight features may not be available on all ClearPass installations or may require specific licenses.
    """
    await ctx.info("Listing Insight reports...")
    try:
        client = await get_clearpass_client()
        params = {k:v for k,v in locals().items() if k not in ['ctx', 'client'] and v is not None}
        response = await client.list_insight_reports(**params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "insight_reports": items,
            "message": f"Retrieved {len(items)} Insight reports."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Insight reports: {e}")
        if e.status_code == 404:
            # Collection endpoint itself 404s -> the feature really is absent.
            return {
                "success": False,
                "error": "Feature not available",
                "message": "Insight reports are not available on this ClearPass installation: the 'report' collection endpoint returns 404. This may require specific licenses or be unavailable in this version.",
                "status_code": 404
            }
        return await format_api_error(e, "list insight reports")
    except Exception as e:
        logger.error(f"Unexpected error listing Insight reports: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def create_insight_report(
    ctx: Context,
    name: str = Field(..., description="Name of the report."),
    category: str = Field(..., description="Category of the report (e.g., 'Audit', 'Monitoring')."),
    subcategory: str = Field(..., description="Subcategory (template name) of the report."),
    format_type: str = Field(default="CSV", alias="format", description="Report format (e.g., 'CSV', 'PDF', 'XML', 'HTML'). Default CSV."),
    description: Optional[str] = Field(None, description="Description of the report."),
    email_targets: Optional[List[str]] = Field(None, description="List of email addresses for report delivery."),
    config: Optional[Dict[str, Any]] = Field(None, description="Report filter configurations and column settings. Refer to API docs for structure."),
    schedule: Optional[Dict[str, Any]] = Field(None, description="Report scheduling configuration. Refer to API docs for structure."),
    is_enabled: bool = Field(default=True, description="Enable/Disable the report generation.")
) -> Dict[str, Any]:
    """
    Create an Insight report configuration.
    Maps to 'new_report' in pyclearpass.
    """
    await ctx.info(f"Creating Insight report: {name}")
    # Validate format_type (renamed from 'format' due to keyword conflict)
    valid_formats = ["CSV", "PDF", "XML", "HTML"]
    if format_type.upper() not in valid_formats:
        return {"success": False, "error": f"Invalid format. Must be one of: {', '.join(valid_formats)}."}

    try:
        client = await get_clearpass_client()
        report_data = InsightReportConfig(
            name=name, category=category, subcategory=subcategory, format=format_type.upper(),
            description=description, email_targets=email_targets, config=config,
            schedule=schedule, is_enabled=is_enabled
            # id is not passed for creation
        )
        response = await client.create_insight_report(report_data.model_dump(exclude_none=True, exclude={'id'}))
        return {
            "success": True,
            "message": "Insight report configuration created successfully.",
            "created_report": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create Insight report: {e}")
        if e.status_code == 404:
            # Collection endpoint itself 404s -> the feature really is absent.
            return {
                "success": False,
                "error": "Feature not available",
                "message": "Insight reports are not available on this ClearPass installation: the 'report' collection endpoint returns 404. This may require specific licenses or be unavailable in this version.",
                "status_code": 404
            }
        return await format_api_error(e, "create insight report")
    except Exception as e:
        logger.error(f"Unexpected error creating Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def get_insight_report_details(
    ctx: Context,
    report_id: int = Field(..., description="ID of the Insight report configuration.")
) -> Dict[str, Any]:
    """
    Get details for a specific Insight report configuration by ID.
    Maps to 'get_report_by_id' in pyclearpass.
    """
    await ctx.info(f"Getting Insight report details for ID: {report_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_insight_report_by_id(report_id)
        return {
            "success": True,
            "insight_report_details": response,
            "message": f"Insight report details retrieved successfully for ID: {report_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Insight report details: {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report ID {report_id}")
        return await format_api_error(e, f"get insight report details for ID {report_id}")
    except Exception as e:
        logger.error(f"Unexpected error getting Insight report details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def run_insight_report(
    ctx: Context,
    report_id: int = Field(..., description="ID of the Insight report to run.")
) -> Dict[str, Any]:
    """
    Run an Insight report by its ID.
    Maps to 'new_report_by_id_run' in pyclearpass. The API usually returns 202 Accepted.
    """
    await ctx.info(f"Initiating run for Insight report ID: {report_id}")
    try:
        client = await get_clearpass_client()
        response = await client.run_insight_report_by_id(report_id)
        # A 202 response might not have a body or a minimal one. 
        # The actual report content is typically retrieved via other means (e.g., email, download link if API provides one later).
        return {
            "success": True,
            "message": f"Insight report ID {report_id} has been queued for execution.",
            "details": response # This might be empty or a status message
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to run Insight report: {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report ID {report_id}")
        return await format_api_error(e, f"run insight report ID {report_id}")
    except Exception as e:
        logger.error(f"Unexpected error running Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ---------------------------------------------------------------------------
# Insight alert state transitions (by name)
#
# Four body-less PATCH endpoints that differ only in the verb they apply, so
# they share one dispatcher. Each still gets its own operation so that the
# gateway exposes the enable/disable and mute/unmute pairs separately.
# ---------------------------------------------------------------------------


async def _alert_state_transition(
    ctx: Context,
    alert_name: str,
    action: str,
    client_method: str
) -> Dict[str, Any]:
    """Apply a body-less state transition to an Insight alert by name."""
    await ctx.info(f"Applying '{action}' to Insight alert: {alert_name}")
    try:
        client = await get_clearpass_client()
        response = await getattr(client, client_method)(alert_name)
        return {
            "success": True,
            "alert_name": alert_name,
            "action": action,
            "insight_alert": response,
            "message": f"Insight alert '{alert_name}' {action}d successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to {action} Insight alert '{alert_name}': {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("alerts", f"Insight alert '{alert_name}'")
        return await format_api_error(e, f"{action} insight alert '{alert_name}'")
    except Exception as e:
        logger.error(f"Unexpected error applying '{action}' to Insight alert: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def enable_insight_alert_by_name(
    ctx: Context,
    alert_name: str = Field(..., description="Name of the Insight alert to enable.")
) -> Dict[str, Any]:
    """
    Enable an Insight alert configuration by name.

    Re-activates an alert that was previously disabled, so it starts evaluating
    its condition again.

    Maps to 'update_alert_by_name_enable' in pyclearpass (PATCH /alert/{name}/enable).
    """
    return await _alert_state_transition(ctx, alert_name, "enable", "enable_insight_alert_by_name")


@operation(domain="audit_logs")
async def disable_insight_alert_by_name(
    ctx: Context,
    alert_name: str = Field(..., description="Name of the Insight alert to disable.")
) -> Dict[str, Any]:
    """
    Disable an Insight alert configuration by name.

    Stops the alert from being evaluated without deleting its configuration.

    Maps to 'update_alert_by_name_disable' in pyclearpass (PATCH /alert/{name}/disable).
    """
    return await _alert_state_transition(ctx, alert_name, "disable", "disable_insight_alert_by_name")


@operation(domain="audit_logs")
async def mute_insight_alert_by_name(
    ctx: Context,
    alert_name: str = Field(..., description="Name of the Insight alert to mute.")
) -> Dict[str, Any]:
    """
    Mute an Insight alert configuration by name.

    The alert keeps evaluating its condition but stops sending notifications to
    its email and SMS targets.

    Maps to 'update_alert_by_name_mute' in pyclearpass (PATCH /alert/{name}/mute).
    """
    return await _alert_state_transition(ctx, alert_name, "mute", "mute_insight_alert_by_name")


@operation(domain="audit_logs")
async def unmute_insight_alert_by_name(
    ctx: Context,
    alert_name: str = Field(..., description="Name of the Insight alert to unmute.")
) -> Dict[str, Any]:
    """
    Unmute an Insight alert configuration by name.

    Restores notifications to the alert's email and SMS targets.

    Maps to 'update_alert_by_name_unmute' in pyclearpass (PATCH /alert/{name}/unmute).
    """
    return await _alert_state_transition(ctx, alert_name, "unmute", "unmute_insight_alert_by_name")


# ---------------------------------------------------------------------------
# Insight report operations (by name)
# ---------------------------------------------------------------------------


async def _report_state_transition(
    ctx: Context,
    report_name: str,
    action: str,
    client_method: str
) -> Dict[str, Any]:
    """Apply a body-less state transition to an Insight report by name."""
    await ctx.info(f"Applying '{action}' to Insight report: {report_name}")
    try:
        client = await get_clearpass_client()
        response = await getattr(client, client_method)(report_name)
        return {
            "success": True,
            "report_name": report_name,
            "action": action,
            "insight_report": response,
            "message": f"Insight report '{report_name}' {action}d successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to {action} Insight report '{report_name}': {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report '{report_name}'")
        return await format_api_error(e, f"{action} insight report '{report_name}'")
    except Exception as e:
        logger.error(f"Unexpected error applying '{action}' to Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def enable_insight_report_by_name(
    ctx: Context,
    report_name: str = Field(..., description="Name of the Insight report to enable.")
) -> Dict[str, Any]:
    """
    Enable an Insight report configuration by name.

    Re-activates a report that was previously disabled, so its schedule starts
    producing runs again.

    Maps to 'update_report_by_name_enable' in pyclearpass (PATCH /report/{name}/enable).
    """
    return await _report_state_transition(ctx, report_name, "enable", "enable_insight_report_by_name")


@operation(domain="audit_logs")
async def disable_insight_report_by_name(
    ctx: Context,
    report_name: str = Field(..., description="Name of the Insight report to disable.")
) -> Dict[str, Any]:
    """
    Disable an Insight report configuration by name.

    Suspends the report's schedule without deleting its configuration.

    Maps to 'update_report_by_name_disable' in pyclearpass (PATCH /report/{name}/disable).
    """
    return await _report_state_transition(ctx, report_name, "disable", "disable_insight_report_by_name")


@operation(domain="audit_logs")
async def update_insight_report_by_name(
    ctx: Context,
    report_name: str = Field(..., description="Name of the Insight report to update."),
    report_data: Dict[str, Any] = Field(..., description="Report fields to change. 'id', 'name', 'category' and 'subcategory' are required by the API; other fields (description, language, email_targets, sms_targets, copy_remote, config, schedule, begin_dt, end_dt, is_enabled) are optional.")
) -> Dict[str, Any]:
    """
    Partially update an Insight report configuration by name.

    Only the supplied fields are changed. The API still requires 'id', 'name',
    'category' and 'subcategory' to be present in the body.

    Maps to 'update_report_by_name' in pyclearpass (PATCH /report/{name}).
    """
    await ctx.info(f"Updating Insight report: {report_name}")

    if not report_data:
        return {
            "success": False,
            "error": "No update parameters provided.",
            "message": "Please provide at least one field to update."
        }

    try:
        client = await get_clearpass_client()
        response = await client.update_insight_report_by_name(report_name, report_data)
        return {
            "success": True,
            "report_name": report_name,
            "updated_report": response,
            "updated_fields": list(report_data.keys()),
            "message": f"Insight report '{report_name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Insight report '{report_name}': {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report '{report_name}'")
        return await format_api_error(e, f"update insight report '{report_name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def replace_insight_report_by_name(
    ctx: Context,
    report_name: str = Field(..., description="Name of the Insight report to replace."),
    report_data: Dict[str, Any] = Field(..., description="Complete report definition. 'id', 'name', 'category' and 'subcategory' are required; other fields (description, language, email_targets, sms_targets, copy_remote, config, schedule, begin_dt, end_dt, is_enabled) are optional and any omitted field is reset.")
) -> Dict[str, Any]:
    """
    Completely update an Insight report configuration by name.

    Every field is overwritten by report_data, so it must carry the full report
    definition — omitted fields are not preserved. Use
    update_insight_report_by_name for a partial (PATCH) update instead.

    Maps to 'replace_report_by_name' in pyclearpass (PUT /report/{name}).
    """
    await ctx.info(f"Replacing Insight report: {report_name}")

    required = ("id", "name", "category", "subcategory")
    missing = [field for field in required if report_data.get(field) in (None, "")]
    if missing:
        return {
            "success": False,
            "error": f"Missing required body fields: {', '.join(missing)}",
            "message": "A full replacement (PUT) requires 'id', 'name', 'category' and 'subcategory' in report_data."
        }

    try:
        client = await get_clearpass_client()
        response = await client.replace_insight_report_by_name(report_name, report_data)
        return {
            "success": True,
            "report_name": report_name,
            "replaced_report": response,
            "message": f"Insight report '{report_name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace Insight report '{report_name}': {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report '{report_name}'")
        return await format_api_error(e, f"replace insight report '{report_name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def delete_insight_report_by_name(
    ctx: Context,
    report_name: str = Field(..., description="Name of the Insight report to delete."),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety). Default is False.")
) -> Dict[str, Any]:
    """
    Delete an Insight report configuration by name.

    Maps to 'delete_report_by_name' in pyclearpass (DELETE /report/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete Insight report '{report_name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting Insight report: {report_name}")
    try:
        client = await get_clearpass_client()
        await client.delete_insight_report_by_name(report_name)  # Usually returns 204 No Content
        return {
            "success": True,
            "report_name": report_name,
            "message": f"Insight report '{report_name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete Insight report '{report_name}': {e}")
        if e.status_code == 404:
            return await _handle_insight_item_404("reports", f"Insight report '{report_name}'")
        return await format_api_error(e, f"delete insight report '{report_name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting Insight report: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ---------------------------------------------------------------------------
# Insight endpoint lookups
#
# Read-only queries against the Insight endpoint database, keyed by IP, MAC,
# IP range, or the time window in which an endpoint was seen.
# ---------------------------------------------------------------------------


@operation(domain="audit_logs")
async def get_insight_endpoint_by_ip(
    ctx: Context,
    ip: str = Field(..., description="IPv4/IPv6 address to match with endpoints, e.g. 192.168.1.10.")
) -> Dict[str, Any]:
    """
    Look up Insight endpoints by IP address.

    Maps to 'get_insight_endpoint_ip_by_ip' in pyclearpass (GET /insight/endpoint/ip/{ip}).
    """
    await ctx.info(f"Looking up Insight endpoints for IP: {ip}")
    try:
        client = await get_clearpass_client()
        response = await client.get_insight_endpoint_by_ip(ip)
        return {
            "success": True,
            "ip": ip,
            "endpoints": response,
            "message": f"Retrieved Insight endpoint data for IP: {ip}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to look up Insight endpoints for IP {ip}: {e}")
        return await format_api_error(e, f"get insight endpoint by IP {ip}")
    except Exception as e:
        logger.error(f"Unexpected error looking up Insight endpoints by IP: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def get_insight_endpoint_by_mac(
    ctx: Context,
    mac: str = Field(..., description="MAC address of the endpoint to retrieve.")
) -> Dict[str, Any]:
    """
    Get a single Insight endpoint by MAC address.

    Maps to 'get_insight_endpoint_mac_by_mac' in pyclearpass (GET /insight/endpoint/mac/{mac}).
    """
    await ctx.info(f"Looking up Insight endpoint for MAC: {mac}")
    try:
        client = await get_clearpass_client()
        response = await client.get_insight_endpoint_by_mac(mac)
        return {
            "success": True,
            "mac": mac,
            "endpoint": response,
            "message": f"Retrieved Insight endpoint data for MAC: {mac}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to look up Insight endpoint for MAC {mac}: {e}")
        return await format_api_error(e, f"get insight endpoint by MAC {mac}")
    except Exception as e:
        logger.error(f"Unexpected error looking up Insight endpoint by MAC: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def get_insight_endpoints_by_ip_range(
    ctx: Context,
    ip_range: str = Field(..., description="IPv4/IPv6 address range, e.g. 192.168.1.1-255 or 2001:db8:a0b:12cd::a-f.")
) -> Dict[str, Any]:
    """
    Look up Insight endpoints by IP address range.

    Maps to 'get_insight_endpoint_ip_range_by_ip_range' in pyclearpass (GET /insight/endpoint/ip-range/{ip_range}).
    """
    await ctx.info(f"Looking up Insight endpoints for IP range: {ip_range}")
    try:
        client = await get_clearpass_client()
        response = await client.get_insight_endpoints_by_ip_range(ip_range)
        return {
            "success": True,
            "ip_range": ip_range,
            "endpoints": response,
            "message": f"Retrieved Insight endpoint data for IP range: {ip_range}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to look up Insight endpoints for IP range {ip_range}: {e}")
        return await format_api_error(e, f"get insight endpoints by IP range {ip_range}")
    except Exception as e:
        logger.error(f"Unexpected error looking up Insight endpoints by IP range: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="audit_logs")
async def get_insight_endpoints_by_time_range(
    ctx: Context,
    from_time: str = Field(..., description="Start time for the search, as a UNIX timestamp."),
    to_time: str = Field(..., description="End time for the search, as a UNIX timestamp.")
) -> Dict[str, Any]:
    """
    Look up Insight endpoints seen within a time range.

    Both bounds are UNIX timestamps (seconds since the epoch).

    Maps to 'get_insight_endpoint_time_range_by_from_time_to_time' in pyclearpass (GET /insight/endpoint/time-range/{from_time}/{to_time}).
    """
    await ctx.info(f"Looking up Insight endpoints between {from_time} and {to_time}")
    try:
        client = await get_clearpass_client()
        response = await client.get_insight_endpoints_by_time_range(from_time, to_time)
        return {
            "success": True,
            "from_time": from_time,
            "to_time": to_time,
            "endpoints": response,
            "message": f"Retrieved Insight endpoint data for the range {from_time} to {to_time}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to look up Insight endpoints for time range {from_time}-{to_time}: {e}")
        return await format_api_error(e, f"get insight endpoints by time range {from_time}-{to_time}")
    except Exception as e:
        logger.error(f"Unexpected error looking up Insight endpoints by time range: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}