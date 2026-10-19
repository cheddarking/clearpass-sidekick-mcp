"""Hard denylist for the live-validation harness.

Operations listed here are NEVER dispatched against the live appliance, under
any circumstance. `harness.invoke()` raises `DenylistedOperation` before the
gateway is touched.

Rationale for each entry is carried in the mapping so it can be surfaced in
skip/failure messages rather than living only in a code comment.
"""

from typing import Dict

__all__ = ["DENYLIST", "DenylistedOperation", "is_denylisted", "denylist_reason"]


DENYLIST: Dict[str, str] = {
    # --- credential / access self-destruction -------------------------------
    "delete_api_client": (
        "Only ONE API client exists on this appliance and it is the credential "
        "we authenticate with; deleting it locks the harness out mid-run."
    ),
    "delete_admin_user": (
        "Only 2 admin users exist on this appliance; deleting one risks "
        "administrative lockout."
    ),
    # --- production infrastructure ------------------------------------------
    "delete_network_device": (
        "7 real NADs are configured on this appliance; deletion would break "
        "live RADIUS/TACACS authentication."
    ),
    "bulk_update_network_devices": (
        "Bulk write across all 7 real NADs; no way to scope it to our fixture "
        "prefix, so it can mutate pre-existing production devices."
    ),
    "leave_ad_domain": (
        "Leaving the AD domain breaks domain-backed authentication for the "
        "whole appliance and cannot be undone from the API."
    ),
    # --- licensing ----------------------------------------------------------
    "delete_application_license": (
        "Removing an application license disables licensed functionality "
        "appliance-wide and may not be re-addable without vendor action."
    ),
    "activate_application_license_online": (
        "Consumes/rebinds a real vendor license activation against Aruba's "
        "activation service."
    ),
    "activate_application_license_offline": (
        "Consumes/rebinds a real vendor license activation."
    ),
    # --- server / cluster configuration -------------------------------------
    "delete_file_backup_server": (
        "Removes real backup-target configuration; loss of backup destination "
        "is not recoverable from the API."
    ),
    "delete_server_policy_manager_zone": (
        "Policy Manager zones are cluster-wide topology; deletion affects "
        "device-to-zone mapping for real NADs."
    ),
    "delete_server_access_control_by_resource": (
        "Removes appliance access-control rules and can cut off API/GUI "
        "access for the network we are testing from."
    ),
    "delete_network_device_group": (
        "Device groups are referenced by real enforcement policies; deletion "
        "silently changes policy evaluation."
    ),
    # --- change-of-authorization (disrupts live user sessions) --------------
    "perform_coa_bulk": (
        "Issues real CoA against live authenticated user sessions."
    ),
    "perform_coa_by_username": (
        "Issues real CoA against a live authenticated user session."
    ),
    "perform_coa_by_mac": (
        "Issues real CoA against a live authenticated user session."
    ),
    "perform_coa_by_ip": (
        "Issues real CoA against a live authenticated user session."
    ),
    # --- outbound messaging to real humans ----------------------------------
    "send_guest_receipt_sms": (
        "Dispatches a real SMS to a real recipient via the configured gateway."
    ),
    "send_guest_receipt_email": (
        "Dispatches a real email to a real recipient via the configured SMTP "
        "relay."
    ),
    "send_email": (
        "POST /email/send hands a message to the appliance's real SMTP relay; "
        "there is no dry-run mode, so any dispatch delivers mail to a real "
        "mailbox and may burn relay reputation."
    ),
    "send_sms": (
        "POST /sms/send hands a message to the appliance's configured SMS "
        "handler, which delivers to a real mobile number and can bill a real "
        "SMS gateway account."
    ),
    # --- extension lifecycle (pulls code from Aruba's online store) ----------
    "install_extension_instance": (
        "POST /extension/instance pulls a container image from Aruba's online "
        "extension store and starts it as a real appliance service; the "
        "install is asynchronous and cannot be reliably undone mid-flight."
    ),
    "reinstall_extension_instance": (
        "POST /extension/instance/{id}/reinstall destroys and re-pulls the "
        "container backing a pre-existing extension; the harness can never "
        "own an extension instance, so any target is production state."
    ),
    "upgrade_extension_instance": (
        "POST /extension/instance/{id}/upgrade pulls a newer image from "
        "Aruba's store and replaces a running appliance service; there is no "
        "downgrade operation in the registry to roll it back."
    ),
    # --- cluster-wide state operations --------------------------------------
    "sync_cluster_database": (
        "POST /cluster/db-sync forces a subscriber to re-replicate from the "
        "publisher. It is a disruptive cluster-wide operation with no scoping "
        "to a fixture and no undo."
    ),
    # --- session actions against live sessions ------------------------------
    # Same policy as the four perform_coa_* entries above: anything that
    # re-authorizes or tears down a live authenticated session is never
    # dispatched, whatever route family it uses.
    "coa_active_session_by_mac": (
        "POST /session/mac/{mac}/coa issues a real Change of Authorization "
        "against whatever live session currently holds that MAC."
    ),
    "session_action_disconnect": (
        "POST session-action/disconnect tears down live authenticated "
        "sessions appliance-wide; with no filter it targets every session."
    ),
    "session_action_disconnect_by_mac": (
        "POST session-action/disconnect-by-mac tears down the live "
        "authenticated session(s) holding that MAC address."
    ),
    "session_action_disconnect_by_ip": (
        "POST session-action/disconnect-by-ip tears down the live "
        "authenticated session(s) holding that IP address."
    ),
    "session_action_disconnect_by_username": (
        "POST session-action/disconnect-by-username tears down every live "
        "authenticated session belonging to that user."
    ),
    # --- Onboard CA certificate state ---------------------------------------
    # These three act on certificate requests / certificates that the harness
    # did not create and cannot recreate: the Onboard CA has no fixture
    # namespace and signing, revoking or rejecting is irreversible.
    "onboard_sign_certificate_request": (
        "Signs a pending Onboard certificate request with the appliance CA, "
        "minting a real, trusted device certificate that cannot be un-issued."
    ),
    "onboard_revoke_certificate": (
        "Revokes a pre-existing Onboard certificate; the device holding it "
        "loses network access immediately and the revocation is permanent."
    ),
    "onboard_reject_certificate_request": (
        "Rejects a pending Onboard certificate request belonging to a real "
        "enrolling device; the request is destroyed and must be re-enrolled "
        "by hand on the device."
    ),
}


class DenylistedOperation(RuntimeError):
    """Raised when something attempts to dispatch a denylisted operation."""

    def __init__(self, name: str) -> None:
        self.operation = name
        super().__init__(
            f"DENYLISTED: refusing to dispatch '{name}' against the live "
            f"appliance. Reason: {DENYLIST.get(name, 'unspecified')}"
        )


def is_denylisted(name: str) -> bool:
    return name in DENYLIST


def denylist_reason(name: str) -> str:
    return DENYLIST.get(name, "")
