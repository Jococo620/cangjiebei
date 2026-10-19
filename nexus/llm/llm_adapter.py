import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ChatMessage:
    role: str
    content: str
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        return result


@dataclass
class ToolCall:
    id: str
    type: str
    function_name: str
    function_args: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ToolCall':
        func = data.get("function", {})
        return cls(
            id=data.get("id", ""),
            type=data.get("type", "function"),
            function_name=func.get("name", ""),
            function_args=func.get("arguments", {})
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "function": {
                "name": self.function_name,
                "arguments": self.function_args
            }
        }


@dataclass
class LLMResponse:
    content: str
    model: str
    finish_reason: str
    usage: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        return self.error is None

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class LLMAdapter:
    def __init__(self, model: str, api_key: str, base_url: str, **kwargs):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = int(kwargs.get("timeout", 60))
        self.max_retries = int(kwargs.get("max_retries", 3))
        self.retry_delay = float(kwargs.get("retry_delay", 1.0))

    def _normalize_messages(self, messages: Any) -> List[ChatMessage]:
        normalized = []
        for m in messages:
            if isinstance(m, ChatMessage):
                normalized.append(m)
            elif isinstance(m, dict):
                normalized.append(ChatMessage(
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    name=m.get("name"),
                ))
            else:
                normalized.append(ChatMessage(role="user", content=str(m)))
        return normalized

    def chat(self, messages: Any, **kwargs) -> LLMResponse:
        raise NotImplementedError("Subclasses must implement chat()")

    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        messages = [ChatMessage(role="user", content=prompt)]
        return self.chat(messages, **kwargs)

    def stream_chat(self, messages: List[ChatMessage], **kwargs):
        raise NotImplementedError("Subclasses must implement stream_chat()")

    def _build_headers(self) -> Dict[str, str]:
        return {}

    def _retry_request(self, fn, *args, **kwargs):
        last_error = None
        for attempt in range(self.max_retries):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                last_error = exc
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
        raise last_error