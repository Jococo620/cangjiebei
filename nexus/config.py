import os
from pathlib import Path
from typing import Dict, Optional

DEFAULT_SYMPAS_SCHEME = "http"
# SymPas（本组自研静态分析工具）MCP 默认地址；可通过 SYMPAS_MCP_URL 覆盖。
# 内网：http://YOUR_SYMPAS_INTERNAL_IP:6240  外网：http://YOUR_SYMPAS_IP:6240
#
# 端口说明：6239 和 6240 是两个不同的后端实例，返回结构不一样
#   :6239  sympas_slice 产出 data.taint.taint_traces（source→sink 污点路径）
#   :6240  sympas_slice 产出 data.backward_slices（变量→依赖行）
# `_extract_sympas_slice` 读的是 backward_slices，所以默认连 6240；
# 连 6239 会永远解析不到切片。
DEFAULT_SYMPAS_HOST = "YOUR_SYMPAS_IP"
DEFAULT_SYMPAS_PORT = "6240"
DEFAULT_SYMPAS_TOKEN = "your-sympas-token"
DEFAULT_SYMPAS_TOKEN_FILE = Path.home() / ".config" / "sympas" / "local_token"

DEFAULT_LLM_PROVIDER = "deepseek"
DEFAULT_LLM_MODEL = "deepseek-chat"
DEFAULT_LLM_BASE_URL = "https://api.deepseek.com"
DEFAULT_LLM_TIMEOUT = 60
DEFAULT_LLM_MAX_RETRIES = 3


def get_sympas_base_url() -> str:
    explicit = os.environ.get("SYMPAS_MCP_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")

    scheme = os.environ.get("SYMPAS_MCP_SCHEME", DEFAULT_SYMPAS_SCHEME).strip()
    host = os.environ.get("SYMPAS_MCP_HOST", DEFAULT_SYMPAS_HOST).strip()
    port = os.environ.get("SYMPAS_MCP_PORT", DEFAULT_SYMPAS_PORT).strip()

    if not scheme:
        scheme = DEFAULT_SYMPAS_SCHEME
    if not host:
        host = DEFAULT_SYMPAS_HOST
    if port:
        return f"{scheme}://{host}:{port}".rstrip("/")
    return f"{scheme}://{host}".rstrip("/")


def get_sympas_token() -> str:
    token = os.environ.get("SYMPAS_MCP_TOKEN", "").strip()
    if token:
        return token

    token_file = os.environ.get("SYMPAS_MCP_TOKEN_FILE", "").strip()
    path = Path(token_file).expanduser() if token_file else DEFAULT_SYMPAS_TOKEN_FILE
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return DEFAULT_SYMPAS_TOKEN


def get_sympas_auth_headers(extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = dict(extra_headers or {})
    token = get_sympas_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def resolve_sympas_endpoint(endpoint: str, base_url: Optional[str] = None) -> str:
    base = (base_url or get_sympas_base_url()).rstrip("/")
    if not endpoint:
        return base
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    if endpoint.startswith("{{SYMPAS_MCP_URL}}"):
        return endpoint.replace("{{SYMPAS_MCP_URL}}", base, 1)
    if endpoint.startswith("${SYMPAS_MCP_URL}"):
        return endpoint.replace("${SYMPAS_MCP_URL}", base, 1)
    if endpoint.startswith("/"):
        return f"{base}{endpoint}"
    return f"{base}/{endpoint.lstrip('/')}"


def get_llm_provider() -> str:
    return os.environ.get("LLM_PROVIDER", DEFAULT_LLM_PROVIDER).lower()


def get_llm_model() -> str:
    return os.environ.get("LLM_MODEL", DEFAULT_LLM_MODEL)


def get_llm_api_key() -> str:
    explicit = os.environ.get("LLM_API_KEY", "").strip()
    if explicit:
        return explicit
    provider = get_llm_provider()
    provider_keys = {
        "openai": os.environ.get("OPENAI_API_KEY", "").strip(),
        "tongyi": os.environ.get("DASHSCOPE_API_KEY", "").strip(),
        "deepseek": os.environ.get("DEEPSEEK_API_KEY", "").strip(),
        "qwen": os.environ.get("QWEN_API_KEY", "").strip(),
    }
    return provider_keys.get(provider, "")


def get_llm_base_url() -> str:
    explicit = os.environ.get("LLM_BASE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    provider = get_llm_provider()
    provider_urls = {
        "openai": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com").strip(),
        "tongyi": os.environ.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com").strip(),
        "deepseek": os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip(),
        "qwen": os.environ.get("QWEN_BASE_URL", "https://api.qwen.chat").strip(),
    }
    return provider_urls.get(provider, DEFAULT_LLM_BASE_URL).rstrip("/")


def get_llm_timeout() -> int:
    return int(os.environ.get("LLM_TIMEOUT", DEFAULT_LLM_TIMEOUT))


def get_llm_max_retries() -> int:
    return int(os.environ.get("LLM_MAX_RETRIES", DEFAULT_LLM_MAX_RETRIES))


def is_compliance_mode() -> bool:
    mode = os.environ.get("NEXUS_COMPLIANCE_MODE", "false").lower()
    return mode in ("true", "1", "yes", "on")


def get_compliant_providers() -> list:
    return ["tongyi", "deepseek", "qwen"]