# src/models/

## Purpose

Pydantic data models (schemas) for all ClearPass API request and response entities. Provides type-safe validation at MCP tool boundaries.

## Ownership

One model file per ClearPass API domain, mirroring the `client_methods/` and `tools/` structure.

## Local Contracts

| File | Domain |
|---|---|
| `api_client.py` | API client schemas |
| `network_device.py` | Network device schemas |
| `guest_user.py` | Guest user schemas |
| `certificates.py` | Certificate schemas |
| `audit.py` | Audit log schemas |
| `policy_elements.py` | Policy element schemas |
| `enforcement_profiles.py` | Enforcement profile schemas |
| `global_server_config.py` | Global config schemas |
| `local_server_config.py` | Local server config schemas |
| `__init__.py` | Package init; re-exports |

## Work Guidance

- All models use Pydantic v2 conventions
- Input validation belongs here, not in tool wrappers or mixin methods
- Sensitive fields (passwords, secrets) must use `SecretStr` or be excluded from serialization
- Keep models close to the ClearPass API contract; avoid adding business logic

## Verification

```bash
python -m pytest tests/
```
