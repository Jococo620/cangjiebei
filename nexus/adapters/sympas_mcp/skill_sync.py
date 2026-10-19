import json
import logging
import os
from typing import Any, Dict, Optional

import requests

from nexus.config import get_sympas_auth_headers, get_sympas_base_url

logger = logging.getLogger("nexus.adapters.skill_sync")


def fetch_sympas_tools(base_url: str, auth_headers: dict) -> Dict[str, Any]:
    try:
        resp = requests.get(f"{base_url}/tools", headers=auth_headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"Failed to fetch Sympas tools: {exc}")
        return {}


def fetch_tool_schema(base_url: str, tool_name: str, auth_headers: dict) -> Dict[str, Any]:
    try:
        resp = requests.get(f"{base_url}/tools/schema/{tool_name}", headers=auth_headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"Failed to fetch schema for {tool_name}: {exc}")
        return {}


def sync_sympas_skills(registry: Any, mcp_base_url: str, local_manifest: str) -> int:
    auth_headers = get_sympas_auth_headers()
    tools = fetch_sympas_tools(mcp_base_url, auth_headers)

    if os.path.exists(local_manifest):
        try:
            with open(local_manifest, "r", encoding="utf-8-sig") as f:
                local_tools = json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to load local manifest: {exc}")
            local_tools = {}
    else:
        local_tools = {}

    registered = 0

    # 远端 /tools 返回格式容错：可能是 dict（{tool_id: info}）、list（[info, ...]）或空
    # 远端是 SSE 协议时通常没有 HTTP REST /tools 端点，fetch 会失败返回 {}，这里要避免崩溃
    remote_tools_raw = tools.get("tools", {}) if isinstance(tools, dict) else {}
    if isinstance(remote_tools_raw, dict):
        remote_tool_ids = set(remote_tools_raw.keys())
        remote_tools_iter = remote_tools_raw.items()
    elif isinstance(remote_tools_raw, list):
        # list 格式：每个元素是 {name/id: ..., ...}
        remote_tool_ids = set()
        remote_tools_iter = []
        for item in remote_tools_raw:
            if isinstance(item, dict):
                tid = item.get("name") or item.get("id") or item.get("skill_id", "")
                if tid:
                    remote_tool_ids.add(tid)
                    remote_tools_iter.append((tid, item))
    else:
        remote_tool_ids = set()
        remote_tools_iter = []

    # 1. 注册本地 manifest 里的所有工具（已手动配置好 provider_type/endpoint）
    for tool_id, skill_data in local_tools.items():
        endpoint = skill_data.get("endpoint", "")
        if "{{SYMPAS_MCP_URL}}" in endpoint:
            skill_data["endpoint"] = endpoint.replace("{{SYMPAS_MCP_URL}}", mcp_base_url)

        if registry.register_skill(skill_data):
            registered += 1

    # 2. 注册远端有但本地没有的工具（仅当远端 fetch 成功时）
    for tool_id, tool_info in remote_tools_iter:
        if tool_id in local_tools:
            continue
        schema = fetch_tool_schema(mcp_base_url, tool_id, auth_headers)
        skill_data = {
            "skill_id": tool_id,
            "name": tool_info.get("name", tool_id) if isinstance(tool_info, dict) else tool_id,
            "description": tool_info.get("description", "") if isinstance(tool_info, dict) else "",
            "provider_type": "mcp_http",
            "endpoint": f"{mcp_base_url}/tools/{tool_id}",
            "danger_level": tool_info.get("danger_level", "safe") if isinstance(tool_info, dict) else "safe",
            "input_schema": schema.get("input_schema", {}),
        }

        if registry.register_skill(skill_data):
            registered += 1

    logger.info(f"Synced {registered} Sympas skills")
    return registered


__all__ = ["sync_sympas_skills"]