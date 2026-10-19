"""
Shared response-inspection helpers for the guest domains.

ClearPass does not always signal failure with an HTTP status code. Several
guest endpoints answer **HTTP 200 with an error payload in the body**:

* ``GET  guest/<id>/pass/<template_id>``  -> ``{"message": "Pass downloads have
  been disabled."}`` for ANY guest id and ANY template id.
* ``PUT/PATCH print-template/<id>``       -> ``{"error": 1, "field": "id",
  "message": "There is no print template with ID %1"}`` for an id that does not
  exist.
* ``POST guest/<id>/sponsor``             -> a bare ``{"success": true}``
  acknowledgement that is returned regardless of token validity.

An operation that inspects only the HTTP status therefore reports
``success: True`` for a write that never landed. Every guest operation whose
appliance-side contract is known must run its response through
:func:`find_response_error` before claiming success.
"""

from typing import Any, Dict, Optional, Sequence

__all__ = ["find_response_error"]

# Keys whose presence (with a truthy value) means the body is an error report,
# whatever the HTTP status was.
_ERROR_MARKER_KEYS = ("error", "errors", "error_code", "validation_messages")


def _first_message(payload: Dict[str, Any], default: str) -> str:
    for key in ("message", "detail", "error_message", "title"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in _ERROR_MARKER_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (dict, list)) and value:
            return str(value)
    return default


def find_response_error(
    payload: Any,
    expected_keys: Sequence[str] = (),
    subject: str = "operation",
) -> Optional[str]:
    """Return an error string when ``payload`` is an HTTP-200 failure body.

    ``None`` means "no evidence of failure" — the caller may report success.

    Two independent checks are applied:

    1. **Explicit error markers.** A truthy ``error`` / ``errors`` /
       ``error_code`` / ``validation_messages`` key, or an HTTP-style
       ``status`` >= 400 carried inside the body.
    2. **Missing payload.** When ``expected_keys`` is supplied (the keys the
       appliance's documented response model is required to carry, e.g.
       ``digital_pass`` for a pass download), a body that carries none of them
       did not produce the artefact, however cheerful it looks.

    A non-dict payload is never judged: it is returned verbatim by the caller.
    """
    if not isinstance(payload, dict):
        return None

    for key in _ERROR_MARKER_KEYS:
        if payload.get(key):
            return _first_message(payload, f"The appliance rejected the {subject}.")

    status = payload.get("status")
    if isinstance(status, int) and status >= 400:
        return _first_message(payload, f"The appliance returned status {status}.")

    if expected_keys and not any(key in payload for key in expected_keys):
        return _first_message(
            payload,
            f"The appliance acknowledged the {subject} but returned none of "
            f"{list(expected_keys)}, so it cannot be confirmed.",
        )

    return None
