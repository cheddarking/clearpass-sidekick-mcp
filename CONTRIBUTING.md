# Contributing

Open an issue describing the change, then submit a pull request with focused changes.

## Local checks

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ --ignore=tests/live
```

The offline suite uses mocks. Live tests require an explicitly configured ClearPass lab;
see [tests/live/README.md](tests/live/README.md). Never run live tests against production.

Keep credentials and local MCP client configurations out of commits. Use `.env.example`
as the configuration reference. Run `gitleaks git .` before submitting changes.

Contributions are licensed under the [MIT License](LICENSE).
