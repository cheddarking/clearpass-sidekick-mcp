# tests/

## Purpose

pytest test suite covering all MCP tool modules, ClearPassClient integration, credential loading, and audit logger logic.

## Ownership

All files under `tests/`. Test configuration lives in `conftest.py`.

## Local Contracts

| File | Covers |
|---|---|
| `conftest.py` | pytest path setup, shared fixtures |
| `test_api_client_tools.py` | `src/tools/api_clients.py` |
| `test_certificate_tools.py` | `src/tools/certificates.py` |
| `test_guest_user_tools.py` | `src/tools/guest_users.py` |
| `test_audit_logger.py` | `src/audit_logger.py` |
| `test_credentials.py` | `src/credentials.py` |
| `test_clearpass_client_integration.py` | `src/clearpass_client.py` integration |
| `test_ambiguous_parameter_confirmation.py` | Ambiguous input handling |
| `test_feedback_error_reporting.py` | Error reporting / feedback paths |
| `live/` | Opt-in live-validation harness against a real appliance; see `tests/live/README.md` |

- Tests run from project root: `python -m pytest tests/`
- Mocking strategy: patch `httpx` calls; do not require a live ClearPass instance for unit tests
- Each new tool module must have a corresponding `test_*.py`
- `tests/live/` is gated behind the `--live` flag and skipped at collection time otherwise; the offline suite (`python -m pytest tests/ --ignore=tests/live`) must stay hermetic at **222 passed, 0 failed**

## Work Guidance

- Use `conftest.py` fixtures for the ClearPass client mock and credential stubs
- Test both success and error paths for every tool
- Do not import `src` modules directly with relative imports from test files; rely on `conftest.py` path setup

## Verification

```bash
python -m pytest tests/ --ignore=tests/live -v
```
