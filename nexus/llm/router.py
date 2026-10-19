"""LLM 模型路由器——根据任务类型和负载自动选择最优模型，支持合规模式。"""

import os
from typing import Any, Dict, Optional

from nexus.llm.factory import get_llm_adapter, list_supported_providers


class ModelRouter:
    """模型路由层：根据任务类型选择合适的LLM模型，支持合规模式。"""

    COMPLIANT_PROVIDERS = {"tongyi", "deepseek", "qwen"}
    NON_COMPLIANT_PROVIDERS = {"openai", "anthropic"}

    def __init__(self):
        self._adapters: Dict[str, Any] = {}
        self._compliance_mode = self._detect_compliance_mode()

    def _detect_compliance_mode(self) -> bool:
        mode = os.environ.get("NEXUS_COMPLIANCE_MODE", "false").lower()
        return mode in ("true", "1", "yes", "on")

    @property
    def compliance_mode(self) -> bool:
        return self._compliance_mode

    @compliance_mode.setter
    def compliance_mode(self, value: bool) -> None:
        self._compliance_mode = value
        self._adapters.clear()

    def _get_provider_for_task(self, task_type: str) -> str:
        user_provider = os.environ.get("LLM_PROVIDER", "")
        if user_provider:
            return user_provider

        task_provider_map = {
            "security_analysis": "deepseek",
            "vulnerability_detection": "deepseek",
            "attack_simulation": "deepseek",
            "code_review": "deepseek",
            "natural_language": "qwen",
            "operations": "deepseek",
            "rag_retrieval": "deepseek",
        }

        if self._compliance_mode:
            return task_provider_map.get(task_type, "deepseek")

        fallback_map = {
            "security_analysis": "openai",
            "vulnerability_detection": "openai",
            "attack_simulation": "openai",
            "code_review": "openai",
            "natural_language": "openai",
            "operations": "openai",
            "rag_retrieval": "openai",
        }
        return task_provider_map.get(task_type, fallback_map.get(task_type, "deepseek"))

    def get_adapter(self, task_type: str = "default") -> Any:
        if task_type not in self._adapters:
            provider = self._get_provider_for_task(task_type)
            self._adapters[task_type] = get_llm_adapter(provider=provider)
        return self._adapters[task_type]

    def chat(self, messages: Any, task: str = "default", **kwargs) -> Dict[str, Any]:
        adapter = self.get_adapter(task)
        return adapter.chat(messages, **kwargs)

    def list_providers(self) -> Dict[str, Dict[str, Any]]:
        providers = list_supported_providers()
        for provider, info in providers.items():
            info["compliant"] = provider in self.COMPLIANT_PROVIDERS
            info["available"] = self._is_provider_available(provider)
        return providers

    def _is_provider_available(self, provider: str) -> bool:
        from nexus.config import get_llm_api_key, get_llm_base_url

        if self._compliance_mode and provider not in self.COMPLIANT_PROVIDERS:
            return False

        env_keys = {
            "openai": "OPENAI_API_KEY",
            "tongyi": "DASHSCOPE_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "qwen": "QWEN_API_KEY",
        }

        api_key = os.environ.get(env_keys.get(provider, "LLM_API_KEY"), "")
        return bool(api_key)

    def switch_provider(self, provider: str, task_type: str = "default") -> bool:
        if self._compliance_mode and provider not in self.COMPLIANT_PROVIDERS:
            return False

        try:
            self._adapters[task_type] = get_llm_adapter(provider=provider)
            return True
        except Exception:
            return False


_router: Optional[ModelRouter] = None


def get_model_router() -> ModelRouter:
    global _router
    if _router is None:
        _router = ModelRouter()
    return _router


def set_compliance_mode(enabled: bool) -> None:
    router = get_model_router()
    router.compliance_mode = enabled


def is_compliance_mode() -> bool:
    return get_model_router().compliance_mode


__all__ = ["ModelRouter", "get_model_router", "set_compliance_mode", "is_compliance_mode"]