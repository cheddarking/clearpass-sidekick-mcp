"""
Tests for the credentials management module.

CredentialsManager loads credentials from environment variables only — the
file-based (~/.clearpass/credentials.json) loading path was removed. These
tests exercise the real environment-variable contract:

    CLEARPASS_SERVER
    CLEARPASS_CLIENT_ID / CLEARPASS_CLIENT_SECRET   (OAuth2 client credentials)
    CLEARPASS_API_TOKEN                             (alternative auth)
    CLEARPASS_VERIFY_SSL                            (optional, default true)
"""

import inspect
from unittest.mock import patch, MagicMock

import pytest

from src.credentials import (
    CredentialsManager,
    CredentialsError,
    CredentialsNotFoundError,
    InvalidCredentialsError
)


ALL_ENV_VARS = (
    CredentialsManager.ENV_SERVER,
    CredentialsManager.ENV_CLIENT_ID,
    CredentialsManager.ENV_CLIENT_SECRET,
    CredentialsManager.ENV_API_TOKEN,
    CredentialsManager.ENV_VERIFY_SSL,
)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove every ClearPass env var so each test controls its own inputs."""
    for var in ALL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


@pytest.fixture
def manager():
    return CredentialsManager()


class TestCredentialsManagerConstruction:
    """The manager is env-var driven and takes no constructor arguments."""

    def test_init_takes_no_arguments(self):
        params = list(inspect.signature(CredentialsManager.__init__).parameters)
        assert params == ["self"]

    def test_init_starts_with_no_cached_credentials(self, manager):
        assert manager._credentials is None

    def test_env_var_names_are_the_documented_contract(self):
        assert CredentialsManager.ENV_SERVER == "CLEARPASS_SERVER"
        assert CredentialsManager.ENV_CLIENT_ID == "CLEARPASS_CLIENT_ID"
        assert CredentialsManager.ENV_CLIENT_SECRET == "CLEARPASS_CLIENT_SECRET"
        assert CredentialsManager.ENV_API_TOKEN == "CLEARPASS_API_TOKEN"
        assert CredentialsManager.ENV_VERIFY_SSL == "CLEARPASS_VERIFY_SSL"

    def test_file_based_loading_is_not_supported(self):
        """File-based credential loading was removed in favour of env vars."""
        with pytest.raises(TypeError):
            CredentialsManager(config_path="/some/path/credentials.json")
        assert not hasattr(CredentialsManager, "create_config_template")


class TestLoadCredentials:
    """load_credentials() reads os.environ."""

    def test_client_credentials(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_CLIENT_ID", "test_client")
        clean_env.setenv("CLEARPASS_CLIENT_SECRET", "test_secret")
        clean_env.setenv("CLEARPASS_VERIFY_SSL", "true")

        assert manager.load_credentials() == {
            "server": "https://test.example.com:443/api",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "granttype": "client_credentials",
            "verify_ssl": True,
        }

    def test_api_token(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_API_TOKEN", "test_token_12345")
        clean_env.setenv("CLEARPASS_VERIFY_SSL", "false")

        assert manager.load_credentials() == {
            "server": "https://test.example.com:443/api",
            "api_token": "test_token_12345",
            "verify_ssl": False,
        }

    def test_api_token_takes_precedence_over_client_credentials(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_API_TOKEN", "test_token_12345")
        clean_env.setenv("CLEARPASS_CLIENT_ID", "test_client")
        clean_env.setenv("CLEARPASS_CLIENT_SECRET", "test_secret")

        credentials = manager.load_credentials()
        assert credentials["api_token"] == "test_token_12345"
        assert "client_id" not in credentials
        assert "client_secret" not in credentials

    def test_loaded_credentials_are_cached_on_the_manager(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_API_TOKEN", "test_token_12345")

        credentials = manager.load_credentials()
        assert manager._credentials == credentials

    @pytest.mark.parametrize("raw,expected", [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("nonsense", False),
    ])
    def test_verify_ssl_parsing(self, manager, clean_env, raw, expected):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_API_TOKEN", "test_token_12345")
        clean_env.setenv("CLEARPASS_VERIFY_SSL", raw)

        assert manager.load_credentials()["verify_ssl"] is expected

    def test_verify_ssl_defaults_to_true_when_unset(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_API_TOKEN", "test_token_12345")

        assert manager.load_credentials()["verify_ssl"] is True

    def test_no_credentials_at_all_raises(self, manager, clean_env):
        with pytest.raises(CredentialsNotFoundError) as excinfo:
            manager.load_credentials()
        assert "No valid credentials found" in str(excinfo.value)

    def test_missing_auth_raises(self, manager, clean_env):
        """Server set but neither API token nor client credentials present."""
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")

        with pytest.raises(CredentialsNotFoundError):
            manager.load_credentials()

    def test_missing_server_raises(self, manager, clean_env):
        clean_env.setenv("CLEARPASS_CLIENT_ID", "test_client")
        clean_env.setenv("CLEARPASS_CLIENT_SECRET", "test_secret")

        with pytest.raises(CredentialsNotFoundError):
            manager.load_credentials()

    def test_partial_client_credentials_raise(self, manager, clean_env):
        """client_id without client_secret is not a usable credential pair."""
        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_CLIENT_ID", "test_client")

        with pytest.raises(CredentialsNotFoundError):
            manager.load_credentials()

    def test_error_message_names_the_env_vars(self, manager, clean_env):
        with pytest.raises(CredentialsNotFoundError) as excinfo:
            manager.load_credentials()
        message = str(excinfo.value)
        for var in ALL_ENV_VARS[:4]:
            if var != CredentialsManager.ENV_VERIFY_SSL:
                assert var in message


class TestValidateCredentials:

    def test_valid_client_creds(self, manager):
        assert manager.validate_credentials({
            "server": "https://clearpass.example.com:443/api",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "granttype": "client_credentials",
            "verify_ssl": True,
        }) is True

    def test_valid_api_token(self, manager):
        assert manager.validate_credentials({
            "server": "https://clearpass.example.com:443/api",
            "api_token": "test_token_12345",
            "verify_ssl": True,
        }) is True

    def test_http_server_url_is_accepted(self, manager):
        assert manager.validate_credentials({
            "server": "http://clearpass.example.com:80/api",
            "api_token": "test_token_12345",
        }) is True

    def test_missing_server(self, manager):
        with pytest.raises(InvalidCredentialsError) as excinfo:
            manager.validate_credentials({
                "client_id": "test_client",
                "client_secret": "test_secret",
            })
        assert "Missing 'server'" in str(excinfo.value)

    def test_invalid_server_url(self, manager):
        with pytest.raises(InvalidCredentialsError) as excinfo:
            manager.validate_credentials({
                "server": "invalid-url",
                "client_id": "test_client",
                "client_secret": "test_secret",
            })
        assert "must start with http://" in str(excinfo.value)

    def test_missing_auth(self, manager):
        with pytest.raises(InvalidCredentialsError) as excinfo:
            manager.validate_credentials({
                "server": "https://clearpass.example.com:443/api",
            })
        assert "must contain either 'api_token'" in str(excinfo.value)

    def test_none_falls_back_to_cached_credentials(self, manager):
        manager._credentials = {
            "server": "https://clearpass.example.com:443/api",
            "api_token": "test_token_12345",
        }
        assert manager.validate_credentials(None) is True

    def test_none_with_no_cached_credentials(self, manager):
        with pytest.raises(InvalidCredentialsError) as excinfo:
            manager.validate_credentials(None)
        assert "No credentials to validate" in str(excinfo.value)


class TestGetClearPassLogin:

    @patch('src.credentials.ClearPassAPILogin')
    def test_client_creds(self, mock_login_class, manager):
        mock_login = MagicMock()
        mock_login_class.return_value = mock_login

        manager._credentials = {
            "server": "https://clearpass.example.com:443/api",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "granttype": "client_credentials",
            "verify_ssl": True,
        }

        result = manager.get_clearpass_login()

        mock_login_class.assert_called_once_with(
            server="https://clearpass.example.com:443/api",
            granttype="client_credentials",
            clientid="test_client",
            clientsecret="test_secret",
            verify_ssl=True,
        )
        assert result is mock_login

    @patch('src.credentials.ClearPassAPILogin')
    def test_api_token(self, mock_login_class, manager):
        mock_login = MagicMock()
        mock_login_class.return_value = mock_login

        manager._credentials = {
            "server": "https://clearpass.example.com:443/api",
            "api_token": "test_token_12345",
            "verify_ssl": True,
        }

        result = manager.get_clearpass_login()

        mock_login_class.assert_called_once_with(
            server="https://clearpass.example.com:443/api",
            api_token="test_token_12345",
            verify_ssl=True,
        )
        assert result is mock_login

    @patch('src.credentials.ClearPassAPILogin')
    def test_loads_credentials_from_environment_when_not_cached(
        self, mock_login_class, manager, clean_env
    ):
        mock_login = MagicMock()
        mock_login_class.return_value = mock_login

        clean_env.setenv("CLEARPASS_SERVER", "https://test.example.com:443/api")
        clean_env.setenv("CLEARPASS_CLIENT_ID", "test_client")
        clean_env.setenv("CLEARPASS_CLIENT_SECRET", "test_secret")

        assert manager._credentials is None
        result = manager.get_clearpass_login()

        assert manager._credentials is not None
        mock_login_class.assert_called_once()
        assert result is mock_login

    @patch('src.credentials.ClearPassAPILogin')
    def test_raises_when_environment_has_no_credentials(
        self, mock_login_class, manager, clean_env
    ):
        with pytest.raises(CredentialsNotFoundError):
            manager.get_clearpass_login()
        mock_login_class.assert_not_called()


class TestMaskSensitiveData:

    def test_sensitive_fields_are_masked(self, manager):
        sensitive_data = {
            "server": "https://clearpass.example.com:443/api",
            "client_id": "test_client",
            "client_secret": "secret_value",
            "api_token": "token_value",
            "password": "password_value",
            "verify_ssl": True,
        }

        masked = manager.mask_sensitive_data(sensitive_data)

        assert masked["client_secret"] == "***MASKED***"
        assert masked["api_token"] == "***MASKED***"
        assert masked["password"] == "***MASKED***"

        # Non-sensitive fields survive untouched
        assert masked["server"] == sensitive_data["server"]
        assert masked["client_id"] == "test_client"
        assert masked["verify_ssl"] is True

        # The caller's dict is not mutated
        assert sensitive_data["client_secret"] == "secret_value"

    def test_absent_and_empty_sensitive_fields_are_left_alone(self, manager):
        masked = manager.mask_sensitive_data({"server": "https://x/api", "api_token": ""})
        assert masked["api_token"] == ""
        assert "client_secret" not in masked


class TestCredentialsExceptions:

    def test_inheritance(self):
        assert issubclass(CredentialsError, Exception)
        assert issubclass(CredentialsNotFoundError, CredentialsError)
        assert issubclass(InvalidCredentialsError, CredentialsError)

    def test_exception_messages(self):
        message = "Test error message"
        for exc_class in (CredentialsError, CredentialsNotFoundError, InvalidCredentialsError):
            with pytest.raises(exc_class) as excinfo:
                raise exc_class(message)
            assert str(excinfo.value) == message
