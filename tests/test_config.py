"""nexus.config 配置管理单元测试。"""

import pytest

import nexus.config as config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in (
        "SYMPAS_MCP_URL", "SYMPAS_MCP_SCHEME", "SYMPAS_MCP_HOST", "SYMPAS_MCP_PORT",
        "SYMPAS_MCP_TOKEN", "SYMPAS_MCP_TOKEN_FILE",
        "LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY", "LLM_BASE_URL",
        "OPENAI_API_KEY", "DASHSCOPE_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY",
        "OPENAI_BASE_URL", "DASHSCOPE_BASE_URL", "DEEPSEEK_BASE_URL", "QWEN_BASE_URL",
        "NEXUS_COMPLIANCE_MODE", "LLM_TIMEOUT", "LLM_MAX_RETRIES",
    ):
        monkeypatch.delenv(key, raising=False)


def test_default_provider_is_deepseek():
    assert config.get_llm_provider() == "deepseek"


def test_default_model():
    assert config.get_llm_model() == "deepseek-chat"


def test_compliant_providers():
    assert config.get_compliant_providers() == ["tongyi", "deepseek", "qwen"]


def test_llm_provider_env_lowercased(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "DEEPSEEK")
    assert config.get_llm_provider() == "deepseek"


def test_sympas_base_url_default():
    assert config.get_sympas_base_url() == "http://YOUR_SYMPAS_IP:6240"


def test_sympas_base_url_explicit_env(monkeypatch):
    monkeypatch.setenv("SYMPAS_MCP_URL", "http://YOUR_SYMPAS_INTERNAL_IP:6239/")
    assert config.get_sympas_base_url() == "http://YOUR_SYMPAS_INTERNAL_IP:6239"


def test_sympas_base_url_env_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("SYMPAS_MCP_URL", "http://host:1///")
    assert config.get_sympas_base_url() == "http://host:1"


def test_sympas_token_default(monkeypatch):
    monkeypatch.setenv("SYMPAS_MCP_TOKEN_FILE", "/nonexistent/sympas_token")
    assert config.get_sympas_token() == "your-sympas-token"


def test_sympas_token_env(monkeypatch):
    monkeypatch.setenv("SYMPAS_MCP_TOKEN", "abc123")
    assert config.get_sympas_token() == "abc123"


def test_auth_headers():
    headers = config.get_sympas_auth_headers()
    assert headers["X-API-Key"] == "your-sympas-token"
    assert "Authorization" not in headers


def test_compliance_mode_off_by_default():
    assert config.is_compliance_mode() is False


def test_compliance_mode_on(monkeypatch):
    monkeypatch.setenv("NEXUS_COMPLIANCE_MODE", "1")
    assert config.is_compliance_mode() is True


def test_resolve_endpoint_placeholder():
    assert (
        config.resolve_sympas_endpoint("{{SYMPAS_MCP_URL}}/tools/x")
        == "http://YOUR_SYMPAS_IP:6240/tools/x"
    )


def test_resolve_endpoint_absolute_passthrough():
    assert config.resolve_sympas_endpoint("http://other:9/t") == "http://other:9/t"
