# src/client_methods/

## Purpose

Mixin classes that implement ClearPass REST API calls, organized by domain. Each file provides one mixin that is composed into `ClearPassClient` in `src/clearpass_client.py`.

## Ownership

One mixin file per ClearPass API domain. This folder is the only place REST HTTP calls are made (via the shared `httpx` client on `self`).

## Local Contracts

| File | Mixin | Domain |
|---|---|---|
| `api_clients.py` | `ApiClientMethodsMixin` | API client CRUD, OAuth client management |
| `network_devices.py` | `NetworkDeviceMethodsMixin` | Network device / NAD management |
| `guest_users.py` | `GuestUserMethodsMixin` | Guest user provisioning |
| `guest_actions.py` | `GuestActionMethodsMixin` | Digital passes, SMS/email delivery, sponsor workflows |
| `guest_configuration.py` | `GuestConfigurationMethodsMixin` | Portal customization, pass/print templates |
| `certificates.py` | `CertificateMethodsMixin` | Certificate lifecycle (CSR, trust lists, CA) |
| `audit_logs.py` | `AuditLogsMethodsMixin` | System events, login audits, insight alerts |
| `session_control.py` | `SessionControlMethodsMixin` | Active session monitoring, disconnect, CoA |
| `policy_elements.py` | `PolicyElementsMethodsMixin` | Roles, auth methods/sources, device groups, posture (192 methods) |
| `enforcement_profiles.py` | `EnforcementProfileMethodsMixin` | Enforcement profile management |
| `global_server_config.py` | `GlobalServerConfigMethodsMixin` | Admin users, licenses, SNMP, messaging, backup servers |
| `local_server_config.py` | `LocalServerConfigMethodsMixin` | Access control, AD integration, cluster management |

## Work Guidance

- Every public method must call `audit_logger` to record the operation
- Methods must not raise generic Python exceptions; use types from `src/exceptions.py`
- HTTP calls use `self._request(...)` or equivalent shared helper inherited from `ClearPassClient`
- When adding a new method, add the corresponding MCP tool in `src/tools/` and update `src/main.py`
- `policy_elements.py` is the largest file (192 methods); keep additions domain-coherent

## Verification

```bash
python -m pytest tests/
```
