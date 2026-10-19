import os
import json
import subprocess
import time
import hashlib
import logging
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs
import uuid

try:
    from jsonschema import validate, ValidationError
    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

from nexus.core.hooks import PreToolUseGuard, PostToolUseObserver
from nexus.config import get_sympas_auth_headers, resolve_sympas_endpoint

logger = logging.getLogger("nexus.registry")

PATH_PARAM_KEYS = {
    "file", "files", "path", "dir", "target_dir", "project_path", "workspace",
    "workspace_root", "results_dir", "trace_dir", "trace_file", "output_dir",
    "local_manifest", "spec_path", "artifact_path", "binary_path", "archive_path",
}


class NexusPluginRegistry:
    def __init__(self, workspace_root: str,
                 project_hash: str = "default",
                 agent_id: str = "nexus_agent"):
        self.workspace_root = os.path.abspath(workspace_root)
        self.skills: Dict[str, Dict[str, Any]] = {}
        self._guard = PreToolUseGuard()
        self._observer = PostToolUseObserver(project_hash)
        self._agent_id = agent_id

    def register_skill_from_json(self, json_path: str) -> bool:
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                skill_data = json.load(f)
            skill_id = skill_data.get("skill_id")
            if not skill_id:
                logger.error(f"Failed to load plugin: missing skill_id in {json_path}")
                return False
            self.skills[skill_id] = skill_data
            logger.info(f"Registered UASP Skill: {skill_id} [{skill_data.get('name')}]")
            return True
        except Exception as exc:
            logger.error(f"Error registering plugin {json_path}: {exc}")
            return False

    def register_skill(self, skill_data: Dict[str, Any]) -> bool:
        skill_id = skill_data.get("skill_id")
        if not skill_id:
            return False
        self.skills[skill_id] = skill_data
        return True

    def load_skills_dir(self, skills_dir: str) -> int:
        count = 0
        for fname in os.listdir(skills_dir):
            if fname.endswith(".json"):
                if self.register_skill_from_json(os.path.join(skills_dir, fname)):
                    count += 1
        return count

    def list_skills(self) -> list:
        return list(self.skills.values())

    def get_skill(self, skill_id: str):
        return self.skills.get(skill_id)

    def execute_skill(self, skill_id: str, params: Dict[str, Any],
                      context: Dict[str, Any] = None) -> Dict[str, Any]:
        ctx = context or {}
        event_sink = ctx.get("event_sink")
        session_id = str(ctx.get("session_id", ""))
        agent_id = str(ctx.get("agent_id", self._agent_id))
        params_hash = hashlib.sha256(
            json.dumps(params, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
        ).hexdigest()

        pre_event = {
            "event_id": uuid.uuid4().hex,
            "event_type": "PreToolUse",
            "session_id": session_id,
            "agent_id": agent_id,
            "skill_id": skill_id,
            "params_hash": params_hash,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._emit_hook_event(event_sink, pre_event)

        skill = self.skills.get(skill_id)
        if not skill:
            result = {"status": "error", "message": f"Skill {skill_id} not registered."}
            self._emit_post_tool_use(event_sink, session_id, agent_id, skill_id, params_hash, result)
            return result

        passed, reason = self._guard.validate(skill_id, params, ctx)
        if not passed:
            result = {"status": "blocked", "message": reason}
            self._emit_post_tool_use(event_sink, session_id, agent_id, skill_id, params_hash, result)
            return result

        if _HAS_JSONSCHEMA:
            schema = skill.get("input_schema", {})
            if schema:
                try:
                    validate(instance=params, schema=schema)
                except ValidationError as val_err:
                    result = {"status": "error", "message": f"UASP Parameter Validation Failed: {val_err.message}"}
                    self._emit_post_tool_use(event_sink, session_id, agent_id, skill_id, params_hash, result)
                    return result

        provider_type = skill.get("provider_type")

        for key, val in params.items():
            if not self._should_validate_path_param(key, val):
                continue
            if isinstance(val, str):
                if provider_type in ("mcp_http", "mcp_rest") and self._is_remote_posix_path(val):
                    continue
                resolved = os.path.realpath(os.path.join(self.workspace_root, val.lstrip("/\\")))
                if (not resolved.startswith(self.workspace_root) or os.path.islink(resolved)):
                    result = {"status": "error", "message": f"Security Violation: Path traversal or Symlink detected on parameter '{key}': {val}"}
                    self._emit_post_tool_use(event_sink, session_id, agent_id, skill_id, params_hash, result)
                    return result

        endpoint = skill.get("endpoint", "")
        t0 = time.time()

        if provider_type == "local_subprocess":
            result = self._run_local_subprocess(endpoint, params)
        elif provider_type in ("mcp_http", "mcp_rest"):
            result = self._run_mcp_http(endpoint, params)
        elif provider_type == "mcp_sse":
            result = self._run_mcp_sse(endpoint, params, skill_id=skill_id)
        elif provider_type == "cloud_api":
            result = self._run_cloud_api_connector(endpoint, params)
        else:
            result = {"status": "error", "message": f"Provider '{provider_type}' not supported."}

        duration_ms = int((time.time() - t0) * 1000)
        self._emit_post_tool_use(event_sink, session_id, agent_id, skill_id, params_hash, result, duration_ms)
        return result

    def _emit_hook_event(self, event_sink: Any, event: Dict[str, Any]) -> None:
        if not callable(event_sink):
            return
        try:
            event_sink(event.get("event_type", "event"), event)
        except Exception:
            logger.debug("Hook event sink unavailable", exc_info=True)

    def _emit_post_tool_use(self, event_sink: Any, session_id: str, agent_id: str,
                            skill_id: str, params_hash: str, result: Dict[str, Any],
                            duration_ms: int = 0, eat_frame_id: Any = None) -> None:
        status_raw = str(result.get("status", "error"))
        status = "ok" if status_raw == "success" else (status_raw if status_raw in {"blocked", "timeout"} else "error")

        event_id = uuid.uuid4().hex
        post_event = {
            "event_id": event_id,
            "event_type": "PostToolUse",
            "session_id": session_id,
            "agent_id": agent_id,
            "skill_id": skill_id,
            "status": status,
            "duration_ms": duration_ms,
            "params_hash": params_hash,
            "eat_frame_id": eat_frame_id,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "result_summary": {
                "has_findings": bool(result.get("findings") or result.get("data")),
                "error_hint": result.get("message") if status != "ok" else None,
            },
            "hitl_correction": result.get("_hitl_correction"),
        }
        self._emit_hook_event(event_sink, post_event)
        self._observer.record(skill_id, {}, result, agent_id, duration_ms, session_id, event_id, params_hash, eat_frame_id)

    def _should_validate_path_param(self, key: str, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        lower_key = key.lower()
        if value.startswith(("http://", "https://")):
            return False
        if lower_key in PATH_PARAM_KEYS:
            return True
        return lower_key.endswith(("_file", "_path", "_dir"))

    def _is_remote_posix_path(self, value: str) -> bool:
        if not value or not value.startswith("/"):
            return False
        if ".." in value or "\\" in value:
            return False
        return True

    def _run_mcp_http(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse
        from nexus.adapters.sympas_failover import call_sympas_tool
        uri = resolve_sympas_endpoint(endpoint)
        path = urlparse(uri).path
        tool_name = path.split("/tools/", 1)[1].strip("/") if "/tools/" in path else path.strip("/")
        return call_sympas_tool(tool_name, params, endpoint=uri, timeout=300)

    def _run_mcp_sse(self, endpoint: str, params: Dict[str, Any], skill_id: str = "") -> Dict[str, Any]:
        """调用 SSE 类型 MCP 工具

        endpoint 格式: sse_url?method=xxx
        params: 工具调用参数（智能体传入）
        skill_id: 调用的工具 ID；当 method=tools/call 且 params 没有 tool_name 时，
                  用 skill_id 作为云端工具名（用于把本地 2266 工具迁移到云端 6239）。
        """
        try:
            from nexus.adapters.sse_mcp_client import call_sse_mcp
            parsed = urlparse(endpoint)
            qs = parse_qs(parsed.query)
            method = qs.get("method", ["tools/call"])[0]

            # 去掉 method 参数，保留 api_key 等
            clean_query = "&".join(
                f"{k}={v[0]}" for k, v in parse_qs(parsed.query).items()
                if k != "method"
            )
            sse_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if clean_query:
                sse_url = f"{sse_url}?{clean_query}"

            # 根据 method 构造 MCP 参数
            if method == "tools/call":
                # 智能体传入的 params 是工具参数
                # 如果有 tool_name，构造标准 MCP 格式（cloud_sse_query 等通用入口工具走这里）
                if "tool_name" in params:
                    mcp_params = {
                        "name": params.pop("tool_name"),
                        "arguments": params,
                    }
                elif "name" in params:
                    mcp_params = {
                        "name": params["name"],
                        "arguments": params.get("arguments", {}),
                    }
                elif skill_id:
                    # 本地迁移工具：skill_id 与云端工具名一致（如 memory_risk_audit）
                    # 自动用 skill_id 作为云端工具名，LLM 不需要传 tool_name
                    mcp_params = {"name": skill_id, "arguments": params}
                else:
                    mcp_params = {"name": "agent_context", "arguments": params}
            else:
                # tools/list 等，params 直接用
                mcp_params = params

            result = call_sse_mcp(
                sse_url=sse_url,
                method=method,
                params=mcp_params,
                timeout=120,
            )
            return result
        except Exception as exc:
            logger.error(f"SSE MCP call failed: {exc}")
            return {"status": "error", "message": f"SSE MCP 调用失败: {exc}"}

    def _run_cloud_api_connector(self, endpoint: str, params: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        headers = {
            "Authorization": f"Bearer {os.environ.get('HUAWEI_CLOUD_TOKEN', '')}",
            "Content-Type": "application/json",
        }
        try:
            resp = requests.post(endpoint, json=params, headers=headers, timeout=120)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            return {"status": "error", "message": f"Cloud API failed: {exc}"}

    def _run_local_subprocess(self, binary_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        cmd = [binary_path]
        for k, v in params.items():
            cmd.append(f"--{k}")
            cmd.append(str(v))

        max_retries = 3
        for attempt in range(max_retries):
            try:
                result = subprocess.run(
                    cmd, cwd=self.workspace_root, capture_output=True, text=True, timeout=60, env=os.environ.copy()
                )
                if result.returncode == 0:
                    try:
                        return {"status": "success", "data": json.loads(result.stdout)}
                    except json.JSONDecodeError:
                        return {"status": "success", "raw_stdout": result.stdout}
                else:
                    logger.warning(f"Process failed (attempt {attempt + 1}): {result.stderr}")
                    if attempt == max_retries - 1:
                        return {"status": "error", "message": f"Process exited with code {result.returncode}", "stderr": result.stderr}
            except subprocess.TimeoutExpired:
                logger.warning(f"Subprocess timeout on attempt {attempt + 1}")
                if attempt == max_retries - 1:
                    return {"status": "error", "message": "Subprocess execution timed out (limit=60s)."}
            except Exception as exc:
                return {"status": "error", "message": f"Subprocess launch failed: {exc}"}
        return {"status": "error", "message": "All retry attempts exhausted"}


__all__ = ["NexusPluginRegistry"]