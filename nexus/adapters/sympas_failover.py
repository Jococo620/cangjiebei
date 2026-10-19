from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from nexus.config import get_sympas_auth_headers, get_sympas_base_url


def _tool_name(endpoint: str) -> str:
    path = urlparse(endpoint).path
    if "/tools/" in path:
        return path.split("/tools/", 1)[1].strip("/")
    return path.strip("/") or "agent_context"


def _remote_post(tool_name: str, params: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    import requests
    base = get_sympas_base_url().rstrip("/")
    url = f"{base}/tools/{tool_name}"
    headers = get_sympas_auth_headers({"Content-Type": "application/json"})
    resp = requests.post(url, json=params, headers=headers, timeout=(2, timeout))
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and str(data.get("status", "success")).lower() == "error":
        raise RuntimeError(data.get("message", "remote returned error"))
    data.setdefault("source", "sympas")
    return data


def call_sympas_tool(tool_name: str, params: Optional[Dict[str, Any]] = None,
                     endpoint: Optional[str] = None, timeout: int = 120) -> Dict[str, Any]:
    name = tool_name or _tool_name(endpoint or "")
    payload = dict(params or {})

    try:
        return _remote_post(name, payload, timeout)
    except Exception as exc:
        return {
            "status": "error",
            "message": f"SymPas 工具 {name} 调用失败: {type(exc).__name__}: {exc}",
            "tool": name,
            "source": "sympas",
        }
