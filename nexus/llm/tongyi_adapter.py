import json
from typing import List, Dict, Any

import requests

from nexus.llm.llm_adapter import LLMAdapter, LLMResponse, ChatMessage


class TongyiAdapter(LLMAdapter):
    def __init__(self, model: str, api_key: str, base_url: str = "https://dashscope.aliyuncs.com", **kwargs):
        super().__init__(model, api_key, base_url, **kwargs)

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        return headers

    def chat(self, messages: Any, **kwargs) -> LLMResponse:
        messages = self._normalize_messages(messages)
        url = f"{self.base_url}/api/v1/chat/completions"
        headers = self._build_headers()

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
            "top_p": kwargs.get("top_p", 0.9),
        }

        if "stop" in kwargs:
            payload["stop"] = kwargs["stop"]
        if "stream" in kwargs:
            payload["stream"] = kwargs["stream"]

        def make_request():
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()

        try:
            result = self._retry_request(make_request)
            return self._parse_response(result)
        except Exception as exc:
            return LLMResponse(
                content="",
                model=self.model,
                finish_reason="error",
                error=str(exc),
            )

    def _parse_response(self, result: Dict[str, Any]) -> LLMResponse:
        if "error" in result:
            return LLMResponse(
                content="",
                model=self.model,
                finish_reason="error",
                error=result["error"].get("message", str(result["error"])),
            )

        choice = result["choices"][0]
        content = choice["message"]["content"]
        finish_reason = choice.get("finish_reason", "unknown")
        usage = result.get("usage", {})

        return LLMResponse(
            content=content,
            model=self.model,
            finish_reason=finish_reason,
            usage=usage,
        )

    def stream_chat(self, messages: List[ChatMessage], **kwargs):
        kwargs["stream"] = True
        url = f"{self.base_url}/api/v1/chat/completions"
        headers = self._build_headers()

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
            "top_p": kwargs.get("top_p", 0.9),
            "stream": True,
        }

        try:
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=self.timeout) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line:
                        line_str = line.decode("utf-8").strip()
                        if line_str.startswith("data: "):
                            data_str = line_str[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data_str)
                                delta = chunk["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
                            except json.JSONDecodeError:
                                continue
        except Exception as exc:
            yield f"[ERROR] {exc}"