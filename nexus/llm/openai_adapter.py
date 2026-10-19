import json
from typing import List, Dict, Any

import requests

from nexus.llm.llm_adapter import LLMAdapter, LLMResponse, ChatMessage, ToolCall


class OpenAIAdapter(LLMAdapter):
    def __init__(self, model: str, api_key: str, base_url: str = "https://api.openai.com", **kwargs):
        super().__init__(model, api_key, base_url, **kwargs)

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        return headers

    def chat(self, messages: Any, **kwargs) -> LLMResponse:
        messages = self._normalize_messages(messages)
        url = f"{self.base_url}/v1/chat/completions"
        headers = self._build_headers()

        payload = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 4096),
            "top_p": kwargs.get("top_p", 0.9),
            "frequency_penalty": kwargs.get("frequency_penalty", 0.0),
            "presence_penalty": kwargs.get("presence_penalty", 0.0),
        }

        if "stop" in kwargs:
            payload["stop"] = kwargs["stop"]
        if "stream" in kwargs:
            payload["stream"] = kwargs["stream"]
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]
        if "tools" in kwargs:
            payload["tools"] = kwargs["tools"]
        if "tool_choice" in kwargs:
            payload["tool_choice"] = kwargs["tool_choice"]

        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"[OpenAIAdapter] Sending request: url={url}, model={self.model}, tools_count={len(payload.get('tools', []))}")
        logger.info(f"[OpenAIAdapter] Message content preview: {messages[0].content[:100]}...")
        if len(messages) > 1:
            logger.info(f"[OpenAIAdapter] User message preview: {messages[1].content[:100]}...")

        def make_request():
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()

        try:
            result = self._retry_request(make_request)
            logger.info(f"[OpenAIAdapter] Response received: finish_reason={result['choices'][0].get('finish_reason')}, has_tool_calls={'tool_calls' in result['choices'][0].get('message', {})}")
            return self._parse_response(result)
        except Exception as exc:
            logger.error(f"[OpenAIAdapter] Request failed: {exc}")
            return LLMResponse(
                content="",
                model=self.model,
                finish_reason="error",
                error=str(exc),
            )

    def _parse_response(self, result: Dict[str, Any]) -> LLMResponse:
        import logging
        logger = logging.getLogger(__name__)
        
        if "error" in result:
            return LLMResponse(
                content="",
                model=self.model,
                finish_reason="error",
                error=result["error"].get("message", str(result["error"])),
            )

        choice = result["choices"][0]
        message = choice["message"]
        content = message.get("content", "")
        finish_reason = choice.get("finish_reason", "unknown")
        usage = result.get("usage", {})

        tool_calls_data = message.get("tool_calls", [])
        logger.info(f"[OpenAIAdapter] Raw tool_calls_data: {tool_calls_data}")
        
        tool_calls = []
        for tc in tool_calls_data:
            try:
                func = tc.get("function", {})
                func_name = func.get("name", "")
                func_args = func.get("arguments", "{}")
                logger.info(f"[OpenAIAdapter] Tool call: name={func_name}, args_type={type(func_args)}, args={func_args}")
                
                if isinstance(func_args, str):
                    func_args = json.loads(func_args)
                
                tool_calls.append(ToolCall.from_dict({
                    "id": tc.get("id", ""),
                    "type": tc.get("type", "function"),
                    "function": {
                        "name": func_name,
                        "arguments": func_args
                    }
                }))
                logger.info(f"[OpenAIAdapter] Tool call added successfully")
            except Exception as e:
                logger.error(f"[OpenAIAdapter] Failed to parse tool call: {e}")
                continue

        logger.info(f"[OpenAIAdapter] Final tool_calls count: {len(tool_calls)}")
        
        return LLMResponse(
            content=content,
            model=self.model,
            finish_reason=finish_reason,
            usage=usage,
            tool_calls=tool_calls,
        )

    def stream_chat(self, messages: List[ChatMessage], **kwargs):
        kwargs["stream"] = True
        url = f"{self.base_url}/v1/chat/completions"
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