import os
from typing import Optional, Dict, Any

from nexus.llm.llm_adapter import LLMAdapter
from nexus.llm.openai_adapter import OpenAIAdapter
from nexus.llm.tongyi_adapter import TongyiAdapter


def get_llm_adapter(
    provider: str = None,
    model: str = None,
    api_key: str = None,
    base_url: str = None,
    **kwargs,
) -> LLMAdapter:
    provider = provider or os.environ.get("LLM_PROVIDER", "deepseek").lower()
    model = model or os.environ.get("LLM_MODEL", "deepseek-chat")
    api_key = api_key or os.environ.get("LLM_API_KEY", "")
    base_url = base_url or os.environ.get("LLM_BASE_URL", "")

    if not base_url:
        base_urls = {
            "openai": os.environ.get("OPENAI_BASE_URL", "https://api.openai.com"),
            "tongyi": os.environ.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com"),
            "deepseek": os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            "qwen": os.environ.get("QWEN_BASE_URL", "https://dashscope.aliyuncs.com"),
        }
        base_url = base_urls.get(provider, "")

    if not api_key:
        api_keys = {
            "openai": os.environ.get("OPENAI_API_KEY", ""),
            "tongyi": os.environ.get("DASHSCOPE_API_KEY", ""),
            "deepseek": os.environ.get("DEEPSEEK_API_KEY", ""),
            "qwen": os.environ.get("QWEN_API_KEY", ""),
        }
        api_key = api_keys.get(provider, "")

    adapter_kwargs = {
        "timeout": int(os.environ.get("LLM_TIMEOUT", "60")),
        "max_retries": int(os.environ.get("LLM_MAX_RETRIES", "3")),
        "retry_delay": float(os.environ.get("LLM_RETRY_DELAY", "1.0")),
    }
    adapter_kwargs.update(kwargs)

    if provider == "openai":
        return OpenAIAdapter(model=model, api_key=api_key, base_url=base_url, **adapter_kwargs)
    elif provider == "tongyi":
        return TongyiAdapter(model=model, api_key=api_key, base_url=base_url, **adapter_kwargs)
    elif provider == "deepseek":
        return OpenAIAdapter(model=model, api_key=api_key, base_url=base_url, **adapter_kwargs)
    elif provider == "qwen":
        return OpenAIAdapter(model=model, api_key=api_key, base_url=base_url, **adapter_kwargs)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


def get_default_llm() -> LLMAdapter:
    return get_llm_adapter()


def list_supported_providers() -> Dict[str, Dict[str, Any]]:
    return {
        "openai": {
            "name": "OpenAI",
            "description": "OpenAI 大语言模型",
            "env_prefix": "OPENAI",
            "default_base_url": "https://api.openai.com",
            "default_model": "gpt-4o",
            "compliant": False,
        },
        "tongyi": {
            "name": "通义千问",
            "description": "阿里云通义千问大语言模型",
            "env_prefix": "DASHSCOPE",
            "default_base_url": "https://dashscope.aliyuncs.com",
            "default_model": "qwen-turbo",
            "compliant": True,
        },
        "deepseek": {
            "name": "DeepSeek",
            "description": "深度求索大语言模型，支持代码理解与推理",
            "env_prefix": "DEEPSEEK",
            "default_base_url": "https://api.deepseek.com",
            "default_model": "deepseek-chat",
            "compliant": True,
        },
        "qwen": {
            "name": "Qwen",
            "description": "阿里通义千问 Qwen 系列模型",
            "env_prefix": "QWEN",
            "default_base_url": "https://dashscope.aliyuncs.com",
            "default_model": "qwen-max",
            "compliant": True,
        },
    }