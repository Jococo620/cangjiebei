import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ChatMessage:
    role: str
    content: str
    name: Optional[str] = None
    # 标准 OpenAI tool 协议字段。
    # assistant 消息带上模型返回的 tool_calls，随后的 tool 消息用 tool_call_id 与之配对。
    # 缺这两个字段时服务端会直接拒收：
    #   assistant 缺 tool_calls  -> 400 Messages with role 'tool' must be a response
    #                               to a preceding message with 'tool_calls'
    #   tool 缺 tool_call_id     -> 422 missing field `tool_call_id`
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {"role": self.role, "content": self.content or ""}
        if self.name:
            result["name"] = self.name
        # 空值不输出：单轮调用不应该多出 "tool_calls": null 这类字段，
        # 部分兼容 OpenAI 的服务端会因此报错。
        if self.tool_calls:
            result["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
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
        # OpenAI 协议要求 arguments 是 JSON 字符串，不是对象。
        # 实测 DeepSeek 返回的就是 '{"code": "..."}' 这种字符串。
        args = self.function_args
        if not isinstance(args, str):
            args = json.dumps(args, ensure_ascii=False)
        return {
            "id": self.id,
            "type": self.type,
            "function": {
                "name": self.function_name,
                "arguments": args
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
                # 必须带上 tool_calls / tool_call_id，否则多轮 tool 消息会被静默丢掉，
                # 再发给服务端就是 400/422。
                normalized.append(ChatMessage(
                    role=m.get("role", "user"),
                    content=m.get("content", ""),
                    name=m.get("name"),
                    tool_calls=m.get("tool_calls"),
                    tool_call_id=m.get("tool_call_id"),
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