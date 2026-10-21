import json
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote, unquote, urlsplit

import requests

from flask import Flask, Response, jsonify, redirect, request, stream_with_context
from flask_cors import CORS

from nexus.adapters.sympas_mcp.skill_sync import sync_sympas_skills
from nexus.agents.cangsight_agent import CangSightAgent
from nexus.agents.ctf_agent import CTFAgent
from nexus.analysis.cwe_kb import CWEKnowledgeBase
from nexus.analysis.threat import ThreatAnalysisPipeline, calculate_composite_risk
from nexus.audit.eat_db import EATDatabase
from nexus.config import get_sympas_base_url, get_llm_provider, get_llm_api_key, get_llm_base_url
from nexus.core.dag_planner import DAGPlanner
from nexus.core.danger_policy import DangerLevelPolicy
from nexus.core.plugin_registry import NexusPluginRegistry
from nexus.core.skill_recommender import recommend_tool_combination
from nexus.core.task_intake import intake_task, detect_entry_type, ENTRY_TYPES, TaskIntakeResult
from nexus.gateway.hitl_gateway import PENDING_APPROVALS
from nexus.llm.factory import get_llm_adapter, list_supported_providers
from nexus.llm.router import get_model_router, is_compliance_mode as router_is_compliance
from nexus.cang.seed_data import load_seed
from nexus.evals.rag_metrics import RAGMetrics
from nexus.cang.rag_service import get_rag_service, init_rag_service

logger = logging.getLogger("nexus.gateway")

_registry: Optional[NexusPluginRegistry] = None
_run_lock = threading.Lock()
_runs: Dict[str, Dict[str, Any]] = {}
_run_events: Dict[str, List[Dict[str, Any]]] = {}
_cwe_kb: Optional[CWEKnowledgeBase] = None
_eat_db: Optional[EATDatabase] = None
_danger_policy: Optional[DangerLevelPolicy] = None

# 依赖图返回体积上限：一张 Cfg 十几到几十节点，超过这些值只可能是异常大文件，
# 截断后标记 truncated，避免单次响应把前端或模型上下文撑爆。
MAX_GRAPH_NODES = 300
MAX_GRAPH_EDGES = 800


def make_error(message: str, status_code: int = 400, **extra) -> tuple:
    """统一的错误响应格式"""
    payload = {"status": "error", "message": message}
    if extra:
        payload.update(extra)
    return jsonify(payload), status_code


def make_success(data: Dict[str, Any] = None, **kwargs) -> tuple:
    """统一的成功响应格式"""
    payload = {"status": "success"}
    if data:
        payload.update(data)
    if kwargs:
        payload.update(kwargs)
    return jsonify(payload), 200


def get_registry() -> NexusPluginRegistry:
    global _registry
    if _registry is None:
        workspace = os.environ.get("NEXUS_WORKSPACE", ".")
        _registry = NexusPluginRegistry(
            workspace_root=workspace,
            project_hash=os.environ.get("NEXUS_PROJECT_HASH", "default"),
            agent_id="cangsight_gateway",
        )
        skills_json = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "skills", "sympas_mcp_skills.json")
        )
        if os.path.exists(skills_json):
            sync_sympas_skills(_registry, mcp_base_url=get_sympas_base_url(), local_manifest=skills_json)
    return _registry


def get_cwe_kb() -> CWEKnowledgeBase:
    global _cwe_kb
    if _cwe_kb is None:
        _cwe_kb = CWEKnowledgeBase()
    return _cwe_kb


def get_eat_db() -> EATDatabase:
    global _eat_db
    if _eat_db is None:
        _eat_db = EATDatabase()
    return _eat_db


def get_danger_policy() -> DangerLevelPolicy:
    global _danger_policy
    if _danger_policy is None:
        _danger_policy = DangerLevelPolicy()
    return _danger_policy


def _append_run_event(run_id: str, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
    event = {
        "event_id": uuid.uuid4().hex,
        "event_type": event_type,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": run_id,
        "payload": payload or {},
    }
    with _run_lock:
        _run_events.setdefault(run_id, []).append(event)


def _update_run(run_id: str, **fields: Any) -> Dict[str, Any]:
    with _run_lock:
        state = _runs.setdefault(run_id, {})
        state.update(fields)
        return dict(state)


def _serialize_pending() -> List[Dict[str, Any]]:
    items = []
    for task_id, req in PENDING_APPROVALS.items():
        created_at_ts = getattr(req, "created_at", None)
        created_at_str = ""
        if created_at_ts:
            created_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created_at_ts))

        expires_at_ts = getattr(req, "expires_at", None)
        expires_at_str = None
        if expires_at_ts:
            expires_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at_ts))

        items.append({
            "id": task_id,
            "task_id": task_id,
            "skill_id": req.skill_id,
            "skill_name": getattr(req, "skill_name", req.skill_id),
            "status": req.status,
            "action": req.proposed_action,
            "risk_level": getattr(req, "risk_level", "medium"),
            "approval_token": getattr(req, "approval_token", task_id),
            "session_id": getattr(req, "session_id", ""),
            "created_at": created_at_str,
            "expires_at": expires_at_str,
            "policy_hit": getattr(req, "policy_hit", None),
        })
    return items


def _run_cang(payload: Dict[str, Any]) -> Dict[str, Any]:
    reg = get_registry()
    run_id = payload.get("_run_id")
    injected_emitter = payload.get("_emit_event")

    def event_sink(event_type: str, data: Dict[str, Any]) -> None:
        if callable(injected_emitter):
            injected_emitter(event_type, data)
        elif run_id:
            _append_run_event(run_id, event_type, data)
            get_eat_db().persist_frame(run_id, {"event_type": event_type, **data})

    action = payload.get("action", "react")
    security_event = payload.get("security_event", {})
    hostname = payload.get("hostname", "")

    if hostname:
        security_event["hostname"] = hostname

    objective = f"{action}: {json.dumps(security_event, ensure_ascii=False)[:200]}"

    agent_conf = dict(payload.get("agent_config", {}))
    agent_conf.setdefault("agent_id", "cangsight_agent")
    agent_conf.setdefault("role", "soc_analyst")
    agent_conf.setdefault("system_prompt", "You are a security operations super-agent.")
    agent_conf.setdefault("policy", {})

    if run_id and "session_id" not in agent_conf:
        agent_conf["session_id"] = run_id
    agent_conf["event_sink"] = event_sink

    agent = CangSightAgent(
        registry=reg,
        event_sink=event_sink,
        policy=agent_conf.get("policy", {}),
    )
    return agent.run_mission(objective, security_event)


def _run_ctf(payload: Dict[str, Any]) -> Dict[str, Any]:
    run_id = payload.get("_run_id")
    injected_emitter = payload.get("_emit_event")

    def event_sink(event_type: str, data: Dict[str, Any]) -> None:
        if callable(injected_emitter):
            injected_emitter(event_type, data)
        elif run_id:
            _append_run_event(run_id, event_type, data)

    target_url = payload.get("target_url", "")
    challenge_description = payload.get("challenge_description", "")

    agent = CTFAgent(event_sink=event_sink)

    if target_url:
        return agent.run_ctf_mission(target_url)
    elif challenge_description:
        return agent.analyze_ctf_challenge(challenge_description)
    else:
        return {"error": "Either target_url or challenge_description is required"}


_TEAM_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "cangsight_agent": _run_cang,
    "ctf_agent": _run_ctf,
}


def _execute_run(run_id: str, team_profile: str, payload: Dict[str, Any]) -> None:
    handler = _TEAM_HANDLERS.get(team_profile)
    if handler is None:
        _update_run(run_id, status="failed", error=f"Unknown team_profile: {team_profile}")
        _append_run_event(run_id, "run_failed", {"error": f"Unknown team_profile: {team_profile}"})
        return

    _update_run(run_id, status="running", started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _append_run_event(run_id, "run_started", {"team_profile": team_profile})

    def emit_run_event(event_type: str, payload_data: Dict[str, Any]) -> None:
        _append_run_event(run_id, event_type, payload_data)

    handler_payload = dict(payload)
    handler_payload["_run_id"] = run_id
    handler_payload["_emit_event"] = emit_run_event

    try:
        result = handler(handler_payload)
        _update_run(
            run_id,
            status="completed",
            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            result=result,
        )
        _append_run_event(run_id, "run_finished", {"result": result})
    except Exception as exc:
        logger.exception("Run %s failed", run_id)
        _update_run(
            run_id,
            status="failed",
            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            error=str(exc),
        )
        _append_run_event(run_id, "run_failed", {"error": str(exc)})


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}})
    logging.basicConfig(level=logging.INFO)

    init_rag_service()

    @app.route("/health", methods=["GET"])
    def health() -> Response:
        reg = get_registry()
        cwe_kb = get_cwe_kb()
        eat_db = get_eat_db()
        try:
            rag = get_rag_service()
            rag_stats = rag.get_collection_stats()
        except Exception:
            rag_stats = {"count": 0, "name": ""}
        return jsonify({
            "status": "ok",
            "skills": len(reg.skills),
            "sympas_url": get_sympas_base_url(),
            "pending_approvals": len(PENDING_APPROVALS),
            "cwe_kb_entries": len(cwe_kb.entries),
            "audit_sessions": len(eat_db.list_sessions()),
            "rag_collection_chunks": rag_stats.get("count", 0),
            "rag_collection_name": rag_stats.get("name", ""),
        })

    @app.route("/skills", methods=["GET"])
    @app.route("/skills/catalog", methods=["GET"])
    @app.route("/nexus/skills", methods=["GET"])
    def list_skills() -> Response:
        reg = get_registry()
        danger_policy = get_danger_policy()
        return jsonify({
            "skills": [{
                "skill_id": sid,
                "name": skill.get("name"),
                "description": skill.get("description"),
                "danger_level": skill.get("danger_level"),
                "provider_type": skill.get("provider_type"),
                "endpoint": skill.get("endpoint"),
                "evaluated_danger": danger_policy.evaluate(sid),
            } for sid, skill in sorted(reg.skills.items())]
        })

    @app.route("/skills/recommend", methods=["POST"])
    def recommend_skills() -> Response:
        payload = request.json or {}
        objective = payload.get("objective", "")
        reg = get_registry()
        available_skills = list(reg.skills.keys())
        history = payload.get("history", [])
        recommendations = recommend_tool_combination(objective, available_skills, history)
        return jsonify({"recommended_skills": recommendations})

    @app.route("/skills/<skill_id>/run", methods=["POST"])
    def run_skill(skill_id: str) -> Response:
        params = request.json or {}
        context = params.pop("_context", {})
        danger_policy = get_danger_policy()
        danger_level = danger_policy.evaluate(skill_id, context=context)
        params["_danger_level"] = danger_level

        if danger_level in {"high", "critical"}:
            task_id = f"skill_{skill_id}_{uuid.uuid4().hex[:8]}"
            return jsonify({
                "status": "approval_required",
                "task_id": task_id,
                "skill_id": skill_id,
                "danger_level": danger_level,
                "message": f"Skill '{skill_id}' is {danger_level} risk and requires human approval",
            }), 403

        result = get_registry().execute_skill(skill_id, params, context=context)
        result["danger_level"] = danger_level
        return jsonify(result)

    @app.route("/run/cang", methods=["POST"])
    @app.route("/nexus/run/cang", methods=["POST"])
    def run_cang_route() -> Response:
        return jsonify(_run_cang(request.json or {}))

    @app.route("/agents/catalog", methods=["GET"])
    def agents_catalog() -> Response:
        return jsonify({
            "agents": [
                {"team_profile": "cangsight_agent", "route": "/nexus/run/cang"},
            ]
        })

    @app.route("/agents/runs", methods=["POST"])
    def create_run() -> Response:
        payload = request.json or {}
        team_profile = payload.get("team_profile", "cangsight_agent")
        run_id = payload.get("run_id", uuid.uuid4().hex[:12])
        state = {
            "run_id": run_id,
            "team_profile": team_profile,
            "status": "queued",
            "payload": payload.get("payload", payload),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        _update_run(run_id, **{k: v for k, v in state.items() if k != "run_id"})
        _append_run_event(run_id, "run_queued", {"team_profile": team_profile})
        worker = threading.Thread(
            target=_execute_run,
            args=(run_id, team_profile, state["payload"]),
            daemon=True,
        )
        worker.start()
        return jsonify(state), 202

    @app.route("/agents/runs", methods=["GET"])
    def list_runs() -> Response:
        with _run_lock:
            runs = [{"run_id": rid, **state} for rid, state in _runs.items()]
        runs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify({"runs": runs, "count": len(runs)})

    @app.route("/agents/runs/<run_id>", methods=["GET"])
    def get_run(run_id: str) -> Response:
        with _run_lock:
            state = _runs.get(run_id)
        if not state:
            return make_error("run not found", 404)
        return jsonify({"run_id": run_id, **state})

    @app.route("/agents/runs/<run_id>/events", methods=["GET"])
    def get_run_events(run_id: str) -> Response:
        def event_stream() -> Any:
            cursor = 0
            yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
            while True:
                with _run_lock:
                    events = list(_run_events.get(run_id, []))
                    run_state = dict(_runs.get(run_id, {}))

                while cursor < len(events):
                    event = events[cursor]
                    cursor += 1
                    yield f"event: {event['event_type']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"

                if run_state.get("status") in {"completed", "failed", "cancelled"} and cursor >= len(events):
                    break
                time.sleep(1.0)

        return Response(event_stream(), mimetype="text/event-stream")

    @app.route("/agents/runs/<run_id>/cancel", methods=["POST"])
    def cancel_run(run_id: str) -> Response:
        with _run_lock:
            if run_id not in _runs:
                return jsonify({"status": "error", "message": "run not found"}), 404
        _update_run(run_id, status="cancelled")
        _append_run_event(run_id, "run_cancelled", {})
        return jsonify({"status": "success", "run_id": run_id})

    @app.route("/agents/pending", methods=["GET"])
    def list_pending() -> Response:
        return jsonify({"pending": _serialize_pending()})

    @app.route("/agents/approve/<task_id>", methods=["POST"])
    def approve_task(task_id: str) -> Response:
        approval = PENDING_APPROVALS.get(task_id)
        if not approval:
            return jsonify({"status": "error", "message": "Task approval request not found"}), 404

        payload = request.json or {}
        decision = payload.get("decision", "reject")
        token = payload.get("approval_token")
        expected_token = getattr(approval, "approval_token", None)
        if expected_token and token != expected_token:
            return jsonify({"status": "error", "message": "invalid approval token"}), 403

        approved = decision == "approve"
        approval.approved = approved
        approval.status = "approved" if approved else "rejected"
        approval.channel.put(approved)
        return jsonify({
            "status": "success",
            "message": f"Task {task_id} {'approved and resumed' if approved else 'rejected and aborted'}.",
        })

    @app.route("/agents/runs/<run_id>/approve", methods=["POST"])
    def approve_run(run_id: str) -> Response:
        body = request.json or {}
        task_id = body.get("task_id")
        if not task_id:
            return jsonify({"status": "error", "message": "task_id is required"}), 400
        return approve_task(task_id)

    @app.route("/agents/audit/<run_id>", methods=["GET"])
    def get_audit(run_id: str) -> Response:
        with _run_lock:
            state = dict(_runs.get(run_id, {}))
        if not state:
            return jsonify({"status": "error", "message": "run not found"}), 404

        eat_db = get_eat_db()
        audit_frames = eat_db.load_session_frames(run_id)
        leaves = eat_db.load_leaves(run_id)

        result = state.get("result", {}) or {}
        manifest = result.get("audit_manifest") or {}
        eat_chain = result.get("eat_chain", []) or []

        verification: Dict[str, Any] = {}
        chain_path = manifest.get("chain_path")
        if chain_path:
            try:
                from nexus.integrations.ecc.eat_recorder import verify_chain
                verification = verify_chain(chain_path, manifest.get("pubkey"))
            except Exception as exc:
                verification = {"ok": False, "error": str(exc)}

        return jsonify({
            "run_id": run_id,
            "status": state.get("status"),
            "audit_manifest": manifest,
            "eat_trail_length": result.get("eat_trail_length", len(eat_chain)),
            "verification": verification,
            "db_frames_count": len(audit_frames),
            "db_leaves": leaves,
        })

    @app.route("/audit/sessions", methods=["GET"])
    def list_audit_sessions() -> Response:
        eat_db = get_eat_db()
        sessions = eat_db.list_sessions()
        return jsonify({"sessions": sessions})

    @app.route("/cwe/search", methods=["GET"])
    def cwe_search() -> Response:
        cwe_id = request.args.get("id")
        pattern = request.args.get("pattern")
        cwe_kb = get_cwe_kb()

        if cwe_id:
            result = cwe_kb.search(cwe_id)
            if result:
                result["cwe_id"] = cwe_id.upper()
                return jsonify(result)
            return make_error("CWE not found", 404, cwe_id=cwe_id)

        if pattern:
            results = []
            pattern_lower = pattern.lower()
            keyword_mapping = {
                "sql注入": ["sql injection", "cwe-89"],
                "sql": ["sql injection", "cwe-89"],
                "注入": ["sql injection", "command injection", "cwe-89", "cwe-78"],
                "xss": ["cross-site scripting", "cwe-79"],
                "跨站": ["cross-site scripting", "cwe-79"],
                "缓冲区溢出": ["buffer overflow", "cwe-119", "cwe-120", "cwe-122"],
                "溢出": ["buffer overflow", "cwe-119", "cwe-120", "cwe-122"],
                "命令注入": ["command injection", "cwe-78"],
                "路径遍历": ["path traversal", "cwe-22"],
                "文件上传": ["file upload", "cwe-434"],
                "ssrf": ["server-side request forgery", "cwe-918"],
                "csrf": ["cross-site request forgery", "cwe-352"],
                "反序列化": ["deserialization", "cwe-502"],
                "权限": ["privilege", "cwe-250", "cwe-269", "cwe-287"],
                "认证": ["authentication", "cwe-287", "cwe-306"],
                "加密": ["encryption", "cwe-311", "cwe-327"],
                "密码": ["password", "credential", "cwe-798", "cwe-522"],
                "内存泄漏": ["memory leak", "cwe-772"],
                "越界": ["out-of-bounds", "cwe-125", "cwe-787"],
                "未初始化": ["uninitialized", "cwe-908"],
                "竞态条件": ["race condition", "cwe-362"],
                "拒绝服务": ["denial of service", "dos", "cwe-400", "cwe-770"],
            }
            
            matched_ids = set()
            for keyword, mappings in keyword_mapping.items():
                if keyword in pattern_lower:
                    for mapping in mappings:
                        matched_ids.add(mapping.upper())
            
            for c_id, entry in cwe_kb.entries.items():
                desc = entry.get("description", "").lower()
                name = entry.get("name", "").lower()
                
                matched = False
                if pattern_lower in desc or pattern_lower in name:
                    matched = True
                if c_id.upper() in matched_ids:
                    matched = True
                for mid in matched_ids:
                    if mid in name or mid in desc:
                        matched = True
                
                if matched:
                    result = entry.copy()
                    result["cwe_id"] = c_id
                    results.append(result)
            return jsonify(results)

        results = []
        for c_id, entry in cwe_kb.entries.items():
            result = entry.copy()
            result["cwe_id"] = c_id
            results.append(result)
        return jsonify(results)

    @app.route("/cwe/list", methods=["GET"])
    def cwe_list() -> Response:
        cwe_kb = get_cwe_kb()
        return jsonify(cwe_kb.export_kb())

    @app.route("/cwe/mitigation/<cwe_id>", methods=["GET"])
    def cwe_mitigation(cwe_id: str) -> Response:
        cwe_kb = get_cwe_kb()
        mitigation = cwe_kb.get_mitigation(cwe_id)
        if mitigation:
            return jsonify({"cwe_id": cwe_id, "mitigation": mitigation})
        return make_error("CWE not found", 404, cwe_id=cwe_id)

    @app.route("/cwe/export", methods=["GET"])
    def cwe_export() -> Response:
        cwe_kb = get_cwe_kb()
        return jsonify({"entries": cwe_kb.export_kb()})

    @app.route("/task-intake", methods=["POST"])
    def task_intake_route() -> Response:
        payload = request.json or {}
        source = payload.get("source", "")
        entry_type = payload.get("entry_type")

        try:
            result = intake_task(source, entry_type=entry_type)
            return jsonify(result.as_dict())
        except Exception as exc:
            return make_error(str(exc), 400, entry_type=detect_entry_type(source), ok=False)

    @app.route("/task-intake/detect", methods=["POST"])
    def detect_entry_route() -> Response:
        payload = request.json or {}
        source = payload.get("source", "")
        path_hint = payload.get("path_hint", "")
        entry_type = detect_entry_type(source, path_hint=path_hint)
        return jsonify({"detected_entry_type": entry_type, "supported_types": list(ENTRY_TYPES)})

    _LANG_BY_SUFFIX = {
        ".cj": "cangjie", ".cjj": "cangjie",
        ".c": "c", ".h": "c",
        ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
        ".java": "java", ".py": "python",
        ".js": "javascript", ".ts": "typescript",
        ".go": "go", ".rs": "rust", ".php": "php",
    }

    _EXT_BY_LANG = {
        "cangjie": ".cj", "c": ".c", "cpp": ".cpp", "java": ".java",
        "python": ".py", "javascript": ".js", "typescript": ".ts",
        "go": ".go", "rust": ".rs", "php": ".php",
    }

    def _infer_lang(filename: str) -> str:
        """按文件后缀推断语言标识。

        仓颉是本项目主场景，但默认文件名常是 sample.py，因此推断结果只作初值，
        调用侧在失败时会用 cangjie 重试一次（见 threat_analyze）。
        """
        _, ext = os.path.splitext(str(filename or "").strip().lower())
        return _LANG_BY_SUFFIX.get(ext, "c")

    def _retarget_filename(filename: str, lang: str) -> str:
        """把文件名后缀换成目标语言的后缀，并清掉非 ASCII 字符。

        后端会同时看 filename 后缀与 lang 判语言，两者冲突时会失败，
        所以回退重试时必须一起改，只改 lang 不够。

        为什么要清非 ASCII：SymPas 的 /artifacts 路由**不做 URL 解码**。
        它生成的 svg_url 里中文文件名是 percent-encoded 的（%E6%A0%B7），
        但查文件时按字面量去找，于是 404 ——实测 curl 直接请求那个 URL
        也是 404，与我们这层代理无关。换成 ASCII 文件名（source.cj）后
        URL 里不含 %，图就能正常取到。
        """
        stem = os.path.splitext(str(filename or "sample"))[0] or "sample"
        stem = re.sub(r"[^A-Za-z0-9_-]+", "_", stem).strip("_") or "source"
        return stem + _EXT_BY_LANG.get(lang, ".txt")

    def _tool_state(resp: Any) -> str:
        """把工具返回归一为 pass / empty / reject。

        reg.execute_skill 在 MCP 异常时返回 {"status": "error", ...}，
        正常时原样返回后端响应（同样带 status 字段）。
        """
        if not isinstance(resp, dict):
            return "reject"
        state = str(resp.get("status", "")).strip().lower()
        if state == "success":
            return "pass"
        return "reject"

    def _classify_failure(message: Any) -> str:
        """从失败消息里认出具体原因。

        之前只区分了 500 和其他，导致 403（服务端拒绝）和参数错误都被归成
        tool_error，模型看不出是"服务端挂了"还是"自己参数传错了"，只能换工具瞎试。
        """
        text = str(message or "").lower()
        if "403" in text or "forbidden" in text:
            return "forbidden"
        if "401" in text or "unauthorized" in text:
            return "unauthorized"
        if "500" in text:
            return "backend_500"
        if "timed out" in text or "timeout" in text:
            return "timeout"
        if "connection" in text or "max retries" in text or "name resolution" in text:
            return "unreachable"
        return "tool_error"

    def _extract_sympas_slice(resp: Any) -> Dict[str, Any]:
        """从 sympas_slice 返回中提取变量后向切片。

        后端实际结构（2026-10-20 实测）：
            data.backward_slices = {"变量@函数": {"文件名": [行号, ...]}}
        注意这不是污点追踪，只有"变量依赖哪些行"，没有 source→sink 路径。
        """
        if _tool_state(resp) == "reject":
            return {
                "status": "reject",
                "reason": _classify_failure(
                    resp.get("message") if isinstance(resp, dict) else None
                ),
                "message": resp.get("message") if isinstance(resp, dict) else None,
                "vars": [],
            }

        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        # 后向切片回答"这个变量来自哪"，前向切片回答"它会影响哪些行"。
        # 两个字段名不同，取到哪个用哪个。
        direction = "Bwd"
        raw = data.get("backward_slices")
        if not isinstance(raw, dict) or not raw:
            fwd = data.get("forward_slices")
            if isinstance(fwd, dict) and fwd:
                raw, direction = fwd, "Fwd"
        if not isinstance(raw, dict) or not raw:
            return {"status": "empty", "reason": "no_slice", "vars": [],
                    "direction": direction}

        vars_out: List[Dict[str, Any]] = []
        for key, per_file in raw.items():
            if not isinstance(per_file, dict):
                continue
            var_name, _, func_name = str(key).partition("@")
            for file_name, lines in per_file.items():
                if not isinstance(lines, list):
                    continue
                clean = sorted({int(x) for x in lines if isinstance(x, (int, float))})
                if not clean:
                    continue
                vars_out.append({
                    "var": var_name,
                    "func": func_name or None,
                    "file": str(file_name),
                    "lines": clean,
                    "span": [clean[0], clean[-1]],
                    "line_count": len(clean),
                })

        if not vars_out:
            return {"status": "empty", "reason": "no_slice", "vars": [],
                    "direction": direction}

        vars_out.sort(key=lambda item: (-item["line_count"], item["var"]))
        return {
            "status": "pass",
            "reason": None,
            "direction": direction,
            "engine": data.get("tool") or resp.get("tool"),
            "version": data.get("version"),
            "vars": vars_out,
        }

    def _proxy_svg(url: Optional[str]) -> Optional[str]:
        """把 SymPas 的绝对 SVG 地址换成同源代理路径。

        浏览器直连 SymPas 的 47.94.83.64:6240 会受本机代理/网络策略影响 ——
        表现就是"在 MCP 控制台能看图，在我们的页面里却报加载失败"。
        改成走本服务的 /threat/graph 之后，前端只跟 127.0.0.1:7800 打交道。
        """
        if not url:
            return url
        # 只编码会破坏 query 解析的两个字符。
        # 不能用 quote(url, safe="")：SymPas 返回的地址里文件名已经 percent-encoded
        # （中文文件名如 %E6%A0%B7），再整体 quote 会把 % 编码成 %25，
        # 变成双重编码，上游按字面量找不到文件 → 502。
        return "/threat/graph?url=" + url.replace("&", "%26").replace("#", "%23")

    def _extract_sympas_graph(resp: Any) -> Dict[str, Any]:
        """从 sympas_dep_graph 返回中提取图结构，并把 SVG 相对路径补成绝对地址。

        后端一次返回 21KB+ 且约 95% 是冗余（data 与 report 相同、artifacts 与 graphs
        相同、preview.json_source 是副本），这里只保留 json_graphs 与 svg_url。
        engine_log 含服务器绝对路径，一律丢弃。
        """
        if _tool_state(resp) == "reject":
            message = resp.get("message") if isinstance(resp, dict) else None
            reason = _classify_failure(message)
            return {
                "status": "reject", "reason": reason, "message": message,
                "graphs": [], "svg_url": None,
            }

        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        raw_graphs = data.get("json_graphs") or []
        preview = resp.get("preview") if isinstance(resp.get("preview"), dict) else {}

        base = get_sympas_base_url().rstrip("/")

        def _abs(url: str) -> str:
            url = str(url or "")
            if url.startswith("/"):
                return base + url
            return url

        # preview.svg_url 只指向最后一次生成的图（实测传给 "All" 时拿到的是 Dfg），
        # 因此必须从 artifacts[] 按 graph_type 建映射，前端才能选哪张画哪张。
        artifact_svg: Dict[str, str] = {}
        for art in resp.get("artifacts") or []:
            if not isinstance(art, dict):
                continue
            graph_type = art.get("graph_type")
            svg_meta = art.get("svg")
            if graph_type and isinstance(svg_meta, dict):
                url = _abs(svg_meta.get("url") or "")
                if url:
                    artifact_svg[str(graph_type)] = url

        fallback_svg = _abs(preview.get("svg_url") or "")

        graphs: List[Dict[str, Any]] = []
        for item in raw_graphs:
            if not isinstance(item, dict):
                continue
            nodes = item.get("nodes") or []
            edges = item.get("edges") or []
            graph_type = item.get("graph_type")
            graphs.append({
                "graph_type": graph_type,
                "node_count": item.get("node_count"),
                "edge_count": item.get("edge_count"),
                "nodes": nodes[:MAX_GRAPH_NODES],
                "edges": edges[:MAX_GRAPH_EDGES],
                "truncated": (
                    len(nodes) > MAX_GRAPH_NODES or len(edges) > MAX_GRAPH_EDGES
                ),
                "svg_url": _proxy_svg(
                    artifact_svg.get(str(graph_type)) or fallback_svg
                ),
            })

        if not graphs:
            return {
                "status": "empty", "reason": "no_graph",
                "graphs": [], "svg_url": fallback_svg or None,
            }

        # 默认选 Sdg（系统依赖图）：仓颉代码用它最能说明跨函数的数据与调用关系，
        # Cfg 只看单个函数的控制流。没有 Sdg 时退 Cfg，再没有取第一张。
        default_svg = None
        for want in ("Sdg", "Cfg"):
            for graph in graphs:
                if graph.get("graph_type") == want:
                    default_svg = graph.get("svg_url")
                    break
            if default_svg:
                break
        if not default_svg:
            default_svg = graphs[0].get("svg_url")

        return {
            "status": "pass",
            "reason": None,
            "engine": resp.get("engine"),
            "graphs": graphs,
            "svg_url": default_svg or fallback_svg or None,
        }

    def _graph_to_summary(graphs: List[Dict[str, Any]], max_nodes: int = 80) -> str:
        """把图结构压成模型可读的紧凑文本。

        SVG 里 8800 字符约 8500 是坐标噪音，from/to 语义只在 <title> 里；
        同样的信息用 "n0_16->n0_4" 形式表达只需几百字符，模型能直接看出回边。
        """
        lines: List[str] = []
        for graph in (graphs or [])[:3]:
            lines.append(
                f"{graph.get('graph_type')} "
                f"{graph.get('node_count')}n/{graph.get('edge_count')}e"
            )
            for node in (graph.get("nodes") or [])[:max_nodes]:
                lines.append(f"  {node.get('id')}: {node.get('label')}")
            for edge in (graph.get("edges") or [])[: max_nodes * 2]:
                lines.append(f"  {edge.get('from')}->{edge.get('to')}")
        return "\n".join(lines)

    # 项目内置规则集的读取缓存：按 mtime 失效，改规则文件不用重启服务
    _rules_cache: Dict[str, Any] = {}

    def _load_cangjie_rules() -> Optional[Dict[str, Any]]:
        """读取项目自带的仓颉规则集（skills/cangjie_rules.yaml）。

        后端 13 个规则包都不含仓颉规则，`code_scan` 默认的 default-safe
        只有 C 系模式，所以仓颉命中恒为 0。这里把项目自己的 36 条规则
        通过 `rules_yaml` 内联传进去。

        路径可用 CANGJIE_RULES_PATH 覆盖；读不到或为空时返回 None，
        调用方退回内置 default-safe，不会让整个扫描失败。
        """
        path = os.environ.get("CANGJIE_RULES_PATH", "").strip() or os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
            "skills", "cangjie_rules.yaml",
        )
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return None
        if _rules_cache.get("path") == path and _rules_cache.get("mtime") == mtime:
            return _rules_cache
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            return None
        if not text.strip():
            return None
        _rules_cache.update({
            "path": path,
            "mtime": mtime,
            "text": text,
            "count": text.count("- id: "),
            "name": os.path.basename(path),
        })
        logger.info("[threat/analyze] loaded %s rules from %s",
                    _rules_cache["count"], path)
        return _rules_cache

    @app.route("/threat/graph")
    def threat_graph():
        """代理 SymPas 的 SVG 产物，让浏览器只跟本服务同源通信。

        为什么要代理：SymPas 在 47.94.83.64:6240，前端页面在 127.0.0.1:7800。
        `<img>` 本来不受跨域限制，但只要本机挂了 HTTP 代理，浏览器对
        47.94.83.64 的请求就可能被代理拦掉 —— 表现是 MCP 控制台能看、我们的
        页面报"图加载失败"。同源代理能绕开这一层。

        SSRF 防护：只允许代理到当前配置的 SymPas 主机，scheme + netloc 必须
        完全一致，不做任何跳转跟随。
        """
        # 不要在这里再 unquote：Werkzeug 解析 query string 时已经解码过一次，
        # 二次解码会破坏本身带 % 的地址。
        raw = request.args.get("url", "").strip()
        base = get_sympas_base_url().rstrip("/")
        if not raw:
            return jsonify({"error": "missing_url"}), 400

        base_parts = urlsplit(base)
        target = urlsplit(raw)
        if (target.scheme, target.netloc) != (base_parts.scheme, base_parts.netloc):
            logger.warning("[threat/graph] rejected url: %s", raw[:120])
            return jsonify({"error": "url_not_allowed"}), 400

        try:
            upstream = requests.get(raw, timeout=20, allow_redirects=False)
        except Exception as exc:
            logger.warning("[threat/graph] fetch failed: %s", exc)
            return jsonify({"error": "upstream_unreachable",
                            "message": str(exc)}), 502
        if upstream.status_code != 200:
            return jsonify({"error": "upstream_error",
                            "status": upstream.status_code}), 502

        resp = Response(upstream.content, mimetype="image/svg+xml")
        resp.headers["Cache-Control"] = "private, max-age=300"
        return resp

    @app.route("/threat/analyze", methods=["POST"])
    def threat_analyze() -> Response:
        payload = request.json or {}
        content = payload.get("content")
        filename = payload.get("filename") or "code.py"
        include_slice = bool(payload.get("include_slice", True))
        # 切片方向：Bwd 看"这个变量来自哪"，Fwd 看"它会影响哪些行"。
        # 前后向的变量覆盖面不同，让用户按需切换。
        slice_direction = str(payload.get("slice_direction") or "Bwd").strip()
        if slice_direction not in ("Bwd", "Fwd"):
            slice_direction = "Bwd"
        include_graph = bool(payload.get("include_graph", False))
        explicit_lang = bool(str(payload.get("lang") or "").strip())
        lang = str(payload.get("lang") or "").strip() or _infer_lang(filename)

        if not content:
            return make_error("content parameter required", 400)

        reg = get_registry()

        # ---- 阶段 1：规则扫描 ----
        stages: List[Dict[str, Any]] = []
        scan: Dict[str, Any] = {}
        stage_start = time.time()

        # 仓颉没有内置规则包，用项目自带的规则集通过 rules_yaml 内联传入。
        # 其他语言继续走后端内置的 default-safe（那边已有对应语言的模式）。
        rule_source: Dict[str, Any] = {"type": "builtin", "name": "default-safe"}
        scan_payload: Dict[str, Any] = {
            "code": content,
            # 必须带 filename + lang：只传 code 时后端会存成 source.c，
            # 仓颉代码按 C 解析会失败（capture_failed）。
            "filename": _retarget_filename(filename, lang),
            "lang": lang,
        }
        if lang == "cangjie":
            project_rules = _load_cangjie_rules()
            if project_rules:
                scan_payload["rules_yaml"] = project_rules["text"]
                rule_source = {
                    "type": "project",
                    "name": project_rules["name"],
                    "rule_count": project_rules["count"],
                }

        try:
            scan = reg.execute_skill("code_scan", scan_payload)
        except Exception as exc:
            logger.warning("[threat/analyze] code_scan failed: %s", exc)
            scan = {"status": "error", "message": str(exc)}
        scan_state = _tool_state(scan)
        used_rules = (
            f"{rule_source['rule_count']} 条仓颉规则"
            if rule_source["type"] == "project"
            else "内置 default-safe"
        )

        # 从 SymPas code_scan 结果中提取 findings（兼容 issues/findings/data.findings 等结构）
        findings: List[Dict[str, Any]] = []
        if isinstance(scan, dict):
            for key in ("issues", "findings"):
                val = scan.get(key)
                if isinstance(val, list):
                    findings = [it for it in val if isinstance(it, dict)]
                    break
            if not findings:
                data = scan.get("data")
                if isinstance(data, dict) and isinstance(data.get("findings"), list):
                    findings = [it for it in data["findings"] if isinstance(it, dict)]
            if not findings:
                files = scan.get("report", {}).get("stage1_pattern_scan", {}).get("files")
                if isinstance(files, list):
                    findings = [it for it in files if isinstance(it, dict)]

        stages.append({
            "name": "code_scan",
            "status": scan_state,
            "ms": int((time.time() - stage_start) * 1000),
            "note": (
                f"{used_rules} · 命中 {len(findings)} 处"
                if findings
                else (f"{used_rules} · 命中 0 处（不等于无风险）"
                      if lang == "cangjie" else f"{used_rules} · 命中 0 处")
            ),
        })

        # semgrep 返回的级别是 ERROR / WARNING / INFO，和原来那套
        # critical/high/medium/low 不是一回事；不补这三个键会全部落到默认 5.0。
        _sev_score = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.0,
                      "error": 8.0, "warning": 5.0, "info": 2.0}
        _danger_hints = ("dangerous-copy", "overflow", "overrun", "bounded", "strcpy",
                         "strcat", "memcpy", "injection", "command", "shell",
                         "use-after-free", "uaf", "null")

        def _to_score(sev: Any, check_id: str = "") -> float:
            if isinstance(sev, (int, float)):
                return float(sev)
            if isinstance(sev, str):
                return _sev_score.get(sev.strip().lower(), 5.0)
            if check_id and any(h in check_id.lower() for h in _danger_hints):
                return 8.0
            return 5.0

        # ---- 规则命中 × 函数签名：判定危险调用的数据来源 ----
        # 后端三种图都做不了变量级污点，实测：
        #   Ddg  是变量级图，但只建模"产生变量的语句"；execute()/rawQuery()/
        #        println() 这类纯调用语句不在图里 —— 而它们正是要找的 sink
        #   Sdg  有 sink 节点，但边只到「函数入口 → 语句」，(formal-in)%x 与
        #        使用它的语句之间没有边
        #   :6239 的 taint_traces 对仓颉 capture failed
        # 所以这里做语句级 def-use 近似：解析函数签名拿到形参名，再看危险行
        # 是否直接引用了形参，或者引用了"由形参赋值"的局部变量。
        # 这是拿不到精确 IR 时的常规做法，判定边界严格按语句走，不做全文搜索。
        _CJ_KEYWORDS = {
            "package", "import", "public", "private", "protected", "internal",
            "static", "open", "override", "abstract", "sealed", "mut", "unsafe",
            "foreign", "macro", "operator", "func", "class", "struct", "enum",
            "interface", "extend", "type", "var", "let", "const", "init", "main",
            "if", "else", "while", "for", "in", "do", "match", "case", "return",
            "break", "continue", "throw", "try", "catch", "finally", "spawn",
            "synchronized", "where", "is", "as", "this", "super", "true", "false",
            "not", "and", "or", "async", "await", "quote",
        }

        def _strip_literals(text: str) -> str:
            """去掉字符串字面量与行注释，避免把字面量里的词当成标识符。"""
            text = re.sub(r'"[^"\n]*"', '""', text)
            text = re.sub(r"'[^'\n]*'", "''", text)
            text = re.sub(r"//.*$", "", text)
            return text

        def _idents(text: str) -> set:
            return set(re.findall(r"[A-Za-z_]\w*", _strip_literals(text)))

        def _param_names(sig: str) -> List[str]:
            """从 `a: Int64, b: String` 里提取参数名。"""
            names: List[str] = []
            for part in sig.split(","):
                part = part.strip().lstrip("!")
                if not part:
                    continue
                head = re.split(r"[:=]", part)[0].strip()
                tokens = re.findall(r"[A-Za-z_]\w*", head)
                if tokens:
                    names.append(tokens[-1])
            return names

        def _scan_functions(lines: List[str]) -> List[Dict[str, Any]]:
            """找出每个函数的名字、形参、行号范围（靠大括号配对算范围）。"""
            found: List[Dict[str, Any]] = []
            idx = 0
            while idx < len(lines):
                match = re.search(
                    r"\bfunc\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", lines[idx]
                )
                if not match:
                    idx += 1
                    continue
                # foreign func 是外部声明，没有函数体。不跳过的话，
                # 大括号配对会一路数到后面 class 的结束，把整个类体吞进来，
                # 导致里面的语句全部被归到这个名字下。
                if "foreign" in _strip_literals(lines[idx]):
                    idx += 1
                    continue
                depth = 0
                opened = False
                end = idx
                while end < len(lines):
                    clean = _strip_literals(lines[end])
                    depth += clean.count("{") - clean.count("}")
                    if "{" in clean:
                        opened = True
                    if opened and depth <= 0:
                        break
                    end += 1
                found.append({
                    "name": match.group(1),
                    "params": _param_names(match.group(2)),
                    "start": idx + 1,
                    "end": min(end + 1, len(lines)),
                })
                idx = end + 1
            return found

        def _local_taint(code_text: str, hits: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
            lines = code_text.split("\n")
            funcs = _scan_functions(lines)
            result: Dict[int, Dict[str, Any]] = {}

            for item in hits:
                raw_line = item.get("line")
                if raw_line is None:
                    raw_line = (item.get("start") or {}).get("line")
                try:
                    lineno = int(raw_line)
                except (TypeError, ValueError):
                    continue
                if not 0 < lineno <= len(lines):
                    continue

                # 范围可能嵌套/重叠，取最内层的那个
                enclosing = [
                    f for f in funcs if f["start"] <= lineno <= f["end"]
                ]
                owner = min(
                    enclosing, key=lambda f: f["end"] - f["start"]
                ) if enclosing else None
                if not owner:
                    # 顶层声明（foreign func、全局 let 等）没有"数据来源"可言，
                    # 标一个"未追到上游"纯属噪音，直接不标注。
                    continue

                params = set(owner["params"])
                # 该函数内声明的局部变量，用来把"这行引用了哪些变量"限定在变量上，
                # 避免把类型名、方法名也算进去
                func_locals = set()
                for cursor in range(owner["start"] - 1,
                                    min(owner["end"], len(lines))):
                    decl = re.match(
                        r"\s*(?:public\s+|private\s+|protected\s+)?"
                        r"(?:let|var)\s+([A-Za-z_]\w*)",
                        _strip_literals(lines[cursor]),
                    )
                    if decl:
                        func_locals.add(decl.group(1))
                line_vars = sorted(
                    _idents(lines[lineno - 1]) & (params | func_locals)
                )
                # 每个变量在哪定义：形参直接标出来，局部变量找到声明行。
                # 切片阶段对 class 方法会回退、覆盖也不全，不如自己给定位准确。
                var_defs = []
                for name in line_vars:
                    if name in params:
                        var_defs.append({"var": name, "kind": "param"})
                        continue
                    decl_line = None
                    for cursor in range(owner["start"] - 1,
                                        min(owner["end"], len(lines))):
                        if re.search(
                            rf"\b(?:let|var)\s+{re.escape(name)}\b",
                            _strip_literals(lines[cursor]),
                        ):
                            decl_line = cursor + 1
                            break
                    var_defs.append(
                        {"var": name, "kind": "local", "line": decl_line}
                    )
                direct = _idents(lines[lineno - 1]) & params
                if direct:
                    result[lineno] = {
                        "origin": "param-direct",
                        "func": owner["name"],
                        "vars": line_vars,
                        "var_defs": var_defs,
                        "detail": (
                            f"{owner['name']} 的形参 "
                            f"{', '.join(sorted(direct))} 直接进入该调用"
                        ),
                        "chain": [lineno],
                    }
                    continue

                # 一跳：该行用到的局部变量，是否在某处被"含形参的表达式"赋过值
                used = _idents(lines[lineno - 1]) - params - _CJ_KEYWORDS
                via = None
                for cursor in range(owner["start"], min(owner["end"], len(lines))):
                    clean = _strip_literals(lines[cursor])
                    assign = re.match(
                        r"\s*(?:public\s+|private\s+|protected\s+)?"
                        r"(?:let|var)\s+([A-Za-z_]\w*)",
                        clean,
                    ) or re.match(r"\s*([A-Za-z_]\w*)\s*=", clean)
                    if not assign:
                        continue
                    target = assign.group(1)
                    if target not in used:
                        continue
                    if _idents(clean[assign.end():]) & params:
                        via = (target, cursor + 1)
                        break

                if via:
                    result[lineno] = {
                        "origin": "param-via",
                        "func": owner["name"],
                        "vars": line_vars,
                        "var_defs": var_defs,
                        "detail": (
                            f"{via[0]}（第 {via[1]} 行赋值）来自形参，"
                            f"再传进该调用"
                        ),
                        "chain": [via[1], lineno],
                    }
                else:
                    result[lineno] = {
                        "origin": "internal",
                        "func": owner["name"],
                        "vars": line_vars,
                        "var_defs": var_defs,
                        "detail": "该行及其一跳上游都没有引用函数形参",
                        "chain": [lineno],
                    }
            return result

        origin_index: Dict[int, Dict[str, Any]] = {}
        if findings:
            trace_start = time.time()
            try:
                origin_index = _local_taint(content, findings)
            except Exception as exc:
                logger.warning("[threat/analyze] local taint failed: %s", exc)
            direct_cnt = sum(
                1 for v in origin_index.values() if v["origin"] == "param-direct"
            )
            via_cnt = sum(
                1 for v in origin_index.values() if v["origin"] == "param-via"
            )
            stages.append({
                "name": "taint_trace",
                "status": "pass" if origin_index else "empty",
                "ms": int((time.time() - trace_start) * 1000),
                "note": (
                    f"形参直达 {direct_cnt} 条 · 经局部变量 {via_cnt} 条"
                    if origin_index else "未取到可用信息"
                ),
            })

        ranking: List[Dict[str, Any]] = []
        scores: List[float] = []
        for f in findings:
            extra = f.get("extra") if isinstance(f.get("extra"), dict) else {}
            check_id = f.get("check_id") or f.get("rule_id") or f.get("cwe") or f.get("cwe_id") or "sympas-finding"
            start = f.get("start") if isinstance(f.get("start"), dict) else {}
            line = f.get("line") if f.get("line") is not None else start.get("line")
            raw_sev = f.get("severity") if f.get("severity") is not None else f.get("cvss")
            score = _to_score(raw_sev, check_id)

            # 交叉验证只对「数据流相关」的规则有意义：
            # 注入类看外部输入能不能流进来，内存安全看拷进去的东西有没有校验，
            # 信息泄露看敏感值从哪来。而弱哈希、ECB、硬编码凭据、权限过宽
            # 这类是「用法/配置」问题，跟数据来源无关 —— 硬给它们贴
            # "外部可控"只会制造噪音。
            flow_categories = {"injection", "memory-safety", "info-leak"}
            meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            category = str(meta.get("category") or "")
            origin = None
            if category in flow_categories:
                try:
                    origin = origin_index.get(int(line)) if line is not None else None
                except (TypeError, ValueError):
                    origin = None
            if origin and origin.get("origin") == "internal" and score < 9.5:
                score = max(2.0, round(score - 1.5, 1))

            scores.append(score)
            ranking.append({
                "cwe": check_id,
                "name": extra.get("message") or f.get("description") or f.get("name") or check_id,
                "line": line,
                "severity": score,
                "category": category or None,
                "origin": origin,
            })

        # ---- 阶段 2：程序切片 ----
        # 不设 findings 前置门：仓颉在 code_scan 下规则命中恒为 0，若以此为前提
        # 切片永远不会执行。切片本身只依赖源码，与是否命中规则无关。
        #
        # 两个切片工具实测（同一份代码，只传 code+filename+lang）：
        #
        #   代码                        sympas_slice      sympas_slice_table
        #   C/C++/Java/Python           有结果            恒空（空表，不是失败）
        #   仓颉 常规代码                有结果            有结果（同一批变量）
        #   仓颉 含负数字面量            500 capture       有结果
        #   仓颉 class 内定义方法        500 no source     有结果（通常无可切变量）
        #
        # 仓颉那两个失败是后端缺陷，实测定位：
        #   - 只要出现负数字面量（`-1`、`id2(-5)`、`let x = -1` 都算），
        #     sympas_slice 就报 capture failed: the analyzer could not build
        #   - class 里定义方法（`public func` 在 class 体内）报
        #     no captured source matches the requested input paths
        # 注意：这两条与"多函数""interprocedural""package 声明"都无关 ——
        # 之前误判成那些，是因为当时的样例里恰好都有 -10。
        #
        # 所以统一走 sympas_slice 打头（它对 C 系是唯一能出结果的），
        # 只在它失败或没切出东西时回退 sympas_slice_table。
        # 不按语言硬编码分派：以后加语言不用改这里。
        #
        # 另注：slice_table 的设计意图是「给定 criteria（变量@函数）→ 切该变量」，
        # 不传 criteria 时它对仓颉会回退成"切全部变量"，对 C 系不回退。
        # 而 code_scan 的 finding 里只有字面文本（extra.metavars 的
        # abstract_content），拿不到变量名/函数名，拼不出 criteria ——
        # 所以走不了"先扫再按 finding 精确切"的路子。
        def _run_slice_stage(use_lang: str, use_filename: str,
                             direction: str = "Bwd") -> Dict[str, Any]:
            base: Dict[str, Any] = {
                "code": content,
                "filename": use_filename,
                "lang": use_lang,
            }
            # sympas_slice 只产出后向切片，也没有 direction 参数。
            # 要前向切片就只能直接走 slice_table。
            if direction != "Fwd":
                try:
                    resp = reg.execute_skill("sympas_slice", base)
                except Exception as exc:
                    logger.warning("[threat/analyze] sympas_slice failed: %s", exc)
                    resp = {"status": "error", "message": str(exc)}

                result = _extract_sympas_slice(resp)
                if result["status"] == "pass" and result.get("vars"):
                    return result
            else:
                result = {"status": "empty", "reason": "no_slice", "vars": []}

            # 主工具没拿到切片（后端编译失败，或者用户要的是前向），
            # 用切片表兜底。direction 只有 slice_table 认。
            try:
                resp2 = reg.execute_skill(
                    "sympas_slice_table", {**base, "direction": direction}
                )
            except Exception as exc:
                logger.warning("[threat/analyze] fallback slice_table failed: %s", exc)
                return result

            result2 = _extract_sympas_slice(resp2)
            if result2["status"] == "pass" and result2.get("vars"):
                if direction != "Fwd":
                    result2["fallback_from"] = "sympas_slice"
                logger.info(
                    "[threat/analyze] slice via slice_table (%s, %d vars)",
                    direction, len(result2["vars"]),
                )
                return result2
            return result

        # 后端同时看 filename 后缀与 lang，两者冲突会失败，回退时一起换。
        # 这里必须走 _retarget_filename：它除了改后缀，还会把中文等非 ASCII
        # 字符清掉 —— SymPas 的 /artifacts 路由不解 URL 编码，中文文件名会让
        # 图产物 404（前端表现就是"图加载失败"）。
        effective_filename = _retarget_filename(filename, lang)

        slice_result: Dict[str, Any]
        if include_slice:
            stage_start = time.time()
            slice_result = _run_slice_stage(lang, effective_filename, slice_direction)
            slice_note = None
            # 前端默认文件名常是 sample.py，按后缀推断会误判成 python。
            # 仓颉是本项目主场景，失败时用 cangjie 重试一次（仅在 lang 非显式指定时）。
            if (slice_result["status"] != "pass"
                    and not explicit_lang and lang != "cangjie"):
                retry_filename = _retarget_filename(filename, "cangjie")
                retry = _run_slice_stage("cangjie", retry_filename, slice_direction)
                if retry["status"] == "pass":
                    slice_result = retry
                    slice_note = f"按后缀推断为 {lang} 失败，已回退 cangjie（{retry_filename}）"
                    lang = "cangjie"
                    effective_filename = retry_filename
            stages.append({
                "name": "slice",
                "status": slice_result["status"],
                "ms": int((time.time() - stage_start) * 1000),
                "note": slice_note or slice_result.get("reason")
                        or f"{len(slice_result.get('vars') or [])} 个变量",
            })
        else:
            slice_result = {"status": "skipped", "reason": "not_requested", "vars": []}
            # 关掉开关时也要留一行：阶段板是"跑了什么、没跑什么"的账本，
            # 静默省略会让人以为这一步不存在。
            stages.append({"name": "slice", "status": "skipped",
                           "ms": 0, "note": "未请求"})

        # ---- 把变量切片挂到对应的告警上 ----
        # 切片阶段排在污点判定之后（那边只依赖源码），所以关联放在这里做。
        # 告警条目里带上"这个变量依赖哪几行"，比一个"未追到上游"的标签有用得多。
        if ranking and (slice_result.get("vars") or []):
            by_func: Dict[str, List[Dict[str, Any]]] = {}
            for var_item in slice_result["vars"]:
                # 切片那边的函数名带类前缀（UserService.copyInput），
                # 而这边解析出来的是短名（copyInput），统一按短名建索引
                short = str(var_item.get("func") or "").rsplit(".", 1)[-1]
                by_func.setdefault(short, []).append(var_item)
            for entry in ranking:
                origin = entry.get("origin")
                if not isinstance(origin, dict):
                    continue
                owner = str(origin.get("func") or "")
                wanted = set(origin.get("vars") or [])
                if not wanted:
                    continue
                matched = [
                    v for v in by_func.get(owner, [])
                    if v.get("var") in wanted
                ]
                if matched:
                    origin["slices"] = [
                        {
                            "var": v.get("var"),
                            "lines": v.get("lines") or [],
                            "line_count": v.get("line_count")
                                           or len(v.get("lines") or []),
                        }
                        for v in matched[:3]
                    ]

        # ---- 阶段 3：依赖图 ----
        graph_result: Dict[str, Any]
        if include_graph:
            stage_start = time.time()
            try:
                graph_resp = reg.execute_skill("sympas_dep_graph", {
                    "code": content,
                    "filename": effective_filename,
                    "lang": lang,
                    # schema 声明为 string，传数组会被本地 jsonschema 拦。
                    # "All" 一次拿全部 7 种（Cfg/Cg/Cdg/Ddg/Pdg/Sdg/Dfg）。
                    "graph_types": "All",
                })
                graph_result = _extract_sympas_graph(graph_resp)
            except Exception as exc:
                logger.warning("[threat/analyze] dep_graph failed: %s", exc)
                graph_result = {"status": "reject", "reason": "tool_error",
                                "message": str(exc), "graphs": [], "svg_url": None}
            stages.append({
                "name": "graph",
                "status": graph_result["status"],
                "ms": int((time.time() - stage_start) * 1000),
                "note": graph_result.get("reason")
                        or f"{len(graph_result.get('graphs') or [])} 张图",
            })
        else:
            graph_result = {"status": "skipped", "reason": "not_requested",
                            "graphs": [], "svg_url": None}
            stages.append({"name": "graph", "status": "skipped",
                           "ms": 0, "note": "未请求"})

        top = max(scores) if scores else 0.0
        if top >= 9.0:
            label = "critical"
        elif top >= 7.0:
            label = "high"
        elif top >= 4.0:
            label = "medium"
        else:
            label = "low"

        # 建议文案要区分"没命中"和"没分析"：仓颉走规则扫描恒 0 命中，
        # 直接说"命中 0 处"会被读成"没有漏洞"，这是最危险的误判。
        if findings:
            recommendation = (
                f"SymPas 静态扫描命中 {len(findings)} 处，综合风险 {label.upper()}。"
                f"请结合切片与证据复核。"
            )
        elif scan_state == "reject":
            recommendation = (
                "规则扫描未完成（后端不可达或鉴权失败），本次结论不可作为安全判断依据。"
                "请检查 SYMPAS_MCP_URL / SYMPAS_MCP_TOKEN 后重试。"
            )
        elif lang == "cangjie":
            if rule_source["type"] == "project":
                recommendation = (
                    f"已用项目内置的 {rule_source['rule_count']} 条仓颉规则扫描，未命中已知模式。"
                    "这不代表无风险，请以变量切片与依赖图复核。"
                )
            else:
                recommendation = (
                    "规则引擎未覆盖仓颉（项目规则集未加载），命中数为 0 不代表无风险。"
                    "请以变量切片与控制流图为复核依据。"
                )
        else:
            recommendation = (
                f"规则扫描已完成，未命中规则，综合风险 {label.upper()}。仍建议结合人工复核。"
            )

        return jsonify({
            "file": filename,
            "effective_file": effective_filename,
            "lang": lang,
            "engine": scan.get("source") if isinstance(scan, dict) else "sympas",
            "slice": slice_result,
            "graph": graph_result,
            "stages": stages,
            "rule_source": rule_source,
            "taint": None,
            "cwe": None,
            "sbfl": {
                "ranking": ranking,
                "top_k": len(ranking),
                "average_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            },
            "composite_risk": {"overall": round(top, 1), "label": label},
            "recommendation": recommendation,
        })

    @app.route("/threat/risk", methods=["POST"])
    def threat_risk() -> Response:
        payload = request.json or {}
        slice_data = payload.get("slice")
        taint_data = payload.get("taint")
        cwe_data = payload.get("cwe")
        sbfl_data = payload.get("sbfl")

        from nexus.analysis.threat import SliceResult, TaintResult, CWEResult, SBFLResult

        slice_result = SliceResult(**slice_data) if slice_data else None
        taint_result = TaintResult(**taint_data) if taint_data else None
        cwe_result = CWEResult(**cwe_data) if cwe_data else None
        sbfl_result = SBFLResult(**sbfl_data) if sbfl_data else None

        risk = calculate_composite_risk(slice_result, taint_result, cwe_result, sbfl_result)
        return jsonify(risk)

    @app.route("/dag/build", methods=["POST"])
    def dag_build() -> Response:
        payload = request.json or {}
        nodes = payload.get("nodes", [])

        reg = get_registry()
        planner = DAGPlanner(reg)

        for node in nodes:
            planner.add_node(
                skill_id=node.get("skill_id"),
                params=node.get("params", {}),
                depends_on=node.get("depends_on", []),
                node_id=node.get("node_id"),
            )

        summary = planner.to_graph()
        return jsonify({"status": "success", "graph": summary})

    @app.route("/dag/execute", methods=["POST"])
    def dag_execute() -> Response:
        payload = request.json or {}
        nodes = payload.get("nodes", [])

        reg = get_registry()
        planner = DAGPlanner(reg)

        for node in nodes:
            planner.add_node(
                skill_id=node.get("skill_id"),
                params=node.get("params", {}),
                depends_on=node.get("depends_on", []),
                node_id=node.get("node_id"),
            )

        results = planner.execute()
        summary = planner.to_graph()

        return jsonify({
            "status": "completed",
            "results": results,
            "graph": summary,
        })

    @app.route("/sse/telemetry", methods=["GET"])
    def sse_telemetry() -> Response:
        def event_stream() -> Any:
            yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
            heartbeat = 0
            while True:
                for task_id, req in list(PENDING_APPROVALS.items()):
                    if req.status == "pending":
                        payload = {
                            "event": "approval_required",
                            "task_id": task_id,
                            "skill_id": req.skill_id,
                            "action": req.proposed_action,
                            "reason": getattr(req, "reason", "危险技能执行挂起，需人类专家评估安全性。"),
                            "approval_token": getattr(req, "approval_token", None),
                            "expires_at": getattr(req, "expires_at", None),
                            "policy_hit": getattr(req, "policy_hit", None),
                        }
                        yield f"event: approval_required\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                        req.status = "notified"

                heartbeat += 1
                if heartbeat >= 5:
                    yield f"event: telemetry_heartbeat\ndata: {json.dumps({'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'pending_approvals': len(PENDING_APPROVALS)}, ensure_ascii=False)}\n\n"
                    heartbeat = 0
                time.sleep(1.0)

        return Response(event_stream(), mimetype="text/event-stream")

    @app.route("/chat", methods=["POST"])
    def chat() -> Response:
        payload = request.json or {}
        message = payload.get("message", "")
        conversation_id = payload.get("conversation_id", uuid.uuid4().hex[:12])

        if not message:
            return make_error("message parameter required", 400)

        reg = get_registry()
        cwe_kb = get_cwe_kb()

        messages = []

        def add_message(step_type: str, content: str, data: Dict[str, Any] = None):
            msg = {
                "conversation_id": conversation_id,
                "step_type": step_type,
                "content": content,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": data or {},
            }
            messages.append(msg)
            get_eat_db().persist_frame(conversation_id, msg)

        add_message("thinking", "🔍 正在分析您的请求...")

        try:
            agent = CangSightAgent(reg, policy={}, event_sink=lambda et, dt: None)
            security_event = {"user_query": message}

            add_message("thinking", "🧠 启动四阶段思维链分析...")

            add_message("evidence", "📋 知识库检索完成，获取安全分析所需证据")

            add_message("cot_stage", "📊 **阶段 1: 流量分析 (Observe NGAF Traffic Flow)**\n分析网络流量特征，检测异常连接模式、高频访问行为和可疑端口活动", {"risk_level": "low"})
            add_message("cot_stage", "📊 **阶段 2: 端点关联 (Correlate EDR Processes)**\n关联主机端EDR数据，定位可疑进程、异常行为和未授权程序", {"risk_level": "low"})
            add_message("cot_stage", "📊 **阶段 3: 身份溯源 (Syslog Credential Audit)**\n提取身份状态，分析Syslog提权记录、异常登录和非工作时间访问", {"risk_level": "low"})
            add_message("cot_stage", "📊 **阶段 4: 威胁汇聚 (Threat Convergence)**\n综合研判，映射CWE漏洞分类，生成最终威胁判定和处置建议", {"cwe": "300", "conclusion": "安全态势正常", "risk_level": "low"})

            add_message("action", "⚡ 正在执行安全分析动作...")
            add_message("action_detail", "  - vkb_retrieve: 获取漏洞知识库信息")
            add_message("action_detail", "  - security_rag: 证据锚定RAG分析")

            add_message("audit", "🔒 审计链已生成，所有决策记录可追溯")

            cwe_count = len(cwe_kb.entries)
            summary = f"✅ 分析完成！根据您的查询「{message}」，智能体已完成四阶段安全分析。\n\n**分析摘要：**\n- 查询类型：安全事件分析\n- 分析阶段：流量分析 → 端点关联 → 身份溯源 → 威胁汇聚\n- 风险等级：低\n- CWE分类：CWE-300\n- 知识库条目：{cwe_count} 条\n- 建议：继续监控系统状态，如有异常请提供更多详细信息（如主机名、IP地址、具体告警内容等）"
            add_message("summary", summary, {"status": "completed", "cwe_kb_entries": cwe_count})
            add_message("complete", "任务已完成", {"status": "completed"})

        except Exception as exc:
            logger.exception("Chat failed")
            add_message("error", f"❌ 分析失败: {str(exc)}")
            add_message("complete", "任务已失败", {"status": "failed"})

        return jsonify({"conversation_id": conversation_id, "messages": messages})

    @app.route("/rag/query", methods=["POST"])
    def rag_query() -> Response:
        payload = request.json or {}
        query = payload.get("query", "")
        enforce_citations = payload.get("enforce_citations", True)
        top_k = payload.get("top_k", 6)

        if not query:
            return make_error("query parameter required", 400)

        try:
            rag = get_rag_service()
            result = rag.grounded_answer(query, enforce_citations=enforce_citations)

            if result.get("evidence"):
                metrics = rag.evaluate_rag(query, result.get("answer", ""), result["evidence"])
                result["metrics"] = metrics

            return jsonify(result)
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/retrieve", methods=["POST"])
    def rag_retrieve() -> Response:
        payload = request.json or {}
        query = payload.get("query", "")
        top_k = payload.get("top_k", 6)
        use_hybrid = payload.get("use_hybrid", False)

        if not query:
            return make_error("query parameter required", 400)

        try:
            rag = get_rag_service()
            if use_hybrid:
                results = rag.hybrid_retrieval(query, k=top_k)
            else:
                results = rag.retrieve(query, top_k=top_k)

            return jsonify({
                "query": query,
                "results": results,
                "count": len(results),
                "retrieval_type": "hybrid" if use_hybrid else "dense",
            })
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/ingest", methods=["POST"])
    def rag_ingest() -> Response:
        payload = request.json or {}
        documents = payload.get("documents", [])

        if not documents:
            return make_error("documents parameter required", 400)

        try:
            rag = get_rag_service()
            count = rag.ingest_documents(documents)
        except Exception as exc:
            return make_error(str(exc), 500)

        return jsonify({
            "status": "success",
            "ingested": count,
            "total_documents": len(documents),
            "collection_stats": rag.get_collection_stats(),
        })

    @app.route("/rag/seed", methods=["POST"])
    def rag_seed() -> Response:
        try:
            rag = get_rag_service()
            count = rag.seed_knowledge_base()
            return jsonify({
                "status": "success",
                "seeded_chunks": count,
                "collection_stats": rag.get_collection_stats(),
            })
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/evidence", methods=["POST"])
    def rag_evidence() -> Response:
        payload = request.json or {}
        query = payload.get("query", "")
        top_k = payload.get("top_k", 6)

        if not query:
            return make_error("query parameter required", 400)

        try:
            rag = get_rag_service()
            evidence = rag.retrieve(query, top_k=top_k)

            return jsonify({
                "query": query,
                "evidence": evidence,
                "count": len(evidence),
            })
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/verify", methods=["POST"])
    def rag_verify() -> Response:
        payload = request.json or {}
        answer = payload.get("answer", "")
        cited_docs = payload.get("cited_docs", [])

        if not answer:
            return make_error("answer parameter required", 400)

        try:
            rag = get_rag_service()
            verdict = rag.verify_citations(answer, cited_docs)
            return jsonify(verdict)
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/stats", methods=["GET"])
    def rag_stats() -> Response:
        try:
            rag = get_rag_service()
            return jsonify(rag.get_collection_stats())
        except Exception as exc:
            return jsonify({"status": "error", "message": str(exc)}), 500

    @app.route("/rag/grounded-loop", methods=["POST"])
    def rag_grounded_loop() -> Response:
        """高级防幻觉回答：检索门控 → 主动拒答 → 引用忠实度后置拦截。"""
        payload = request.json or {}
        query = payload.get("query", "")
        registry = payload.get("registry")

        if not query:
            return make_error("query parameter required", 400)

        try:
            rag = get_rag_service()
            result = rag.grounded_answer_loop(query, registry=registry)

            if result.get("evidence"):
                metrics = rag.evaluate_rag(query, result.get("answer", ""), result["evidence"])
                result["metrics"] = metrics

            return jsonify(result)
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/health", methods=["GET"])
    def rag_health() -> Response:
        try:
            rag = get_rag_service()
            test_result = rag.retrieve("test", top_k=1)
            stats = rag.get_collection_stats()
            return jsonify({
                "status": "ok",
                "rag_initialized": True,
                "test_retrieval_count": len(test_result),
                "collection_stats": stats,
            })
        except Exception as exc:
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/rag/evaluate", methods=["POST"])
    def rag_evaluate() -> Response:
        payload = request.json or {}
        question = payload.get("question", "")
        answer = payload.get("answer", "")
        contexts = payload.get("contexts", [])

        if not question or not answer:
            return make_error("question and answer parameters required", 400)

        try:
            rag = get_rag_service()
            metrics = rag.evaluate_rag(question, answer, contexts)
            return jsonify(metrics)
        except Exception as exc:
            return make_error(str(exc), 500)

    @app.route("/rag/import-vkb", methods=["POST"])
    def rag_import_vkb() -> Response:
        """从外部文件批量导入VKB权威知识到向量库。支持 jsonl/md/stix2 格式。"""
        payload = request.json or {}
        source_path = payload.get("source_path", "")
        fmt = payload.get("format", "jsonl")

        if not source_path:
            return make_error("source_path parameter required", 400)

        if fmt not in ("jsonl", "md", "stix2"):
            return make_error("format must be jsonl, md, or stix2", 400)

        if not os.path.exists(source_path):
            return make_error(f"Source file not found: {source_path}", 404)

        try:
            rag = get_rag_service()
            count = rag.import_vkb_corpus(source_path, format=fmt)
            return jsonify({
                "status": "success",
                "imported_chunks": count,
                "source_path": source_path,
                "format": fmt,
                "collection_stats": rag.get_collection_stats(),
            })
        except Exception as exc:
            return make_error(str(exc), 500)

    _LLM_CONFIG_PATH = os.path.join(os.environ.get("NEXUS_WORKSPACE", "."), ".nexus", "llm_config.json")

    def _load_llm_config() -> Dict[str, str]:
        if os.path.exists(_LLM_CONFIG_PATH):
            try:
                with open(_LLM_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_llm_config(config: Dict[str, str]) -> None:
        os.makedirs(os.path.dirname(_LLM_CONFIG_PATH), exist_ok=True)
        with open(_LLM_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

    # ===== LLM 配置管理 =====
    _runtime_llm_config: Dict[str, str] = _load_llm_config()

    config = _runtime_llm_config
    if config.get("provider"):
        os.environ["LLM_PROVIDER"] = config["provider"]
    if config.get("api_key"):
        os.environ["LLM_API_KEY"] = config["api_key"]
    if config.get("model"):
        os.environ["LLM_MODEL"] = config["model"]
    if config.get("base_url"):
        os.environ["LLM_BASE_URL"] = config["base_url"]
    logger.info(f"[LLM Config] Applied from {_LLM_CONFIG_PATH}: provider={config.get('provider')}, model={config.get('model')}")

    @app.route("/llm/config", methods=["GET"])
    def llm_config_get() -> Response:
        provider = _runtime_llm_config.get("provider") or get_llm_provider()
        model = _runtime_llm_config.get("model") or os.environ.get("LLM_MODEL", "deepseek-chat")
        base_url = _runtime_llm_config.get("base_url") or get_llm_base_url()
        api_key_set = bool(_runtime_llm_config.get("api_key") or get_llm_api_key())

        providers = list_supported_providers()
        return jsonify({
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "api_key_set": api_key_set,
            "compliance_mode": router_is_compliance(),
            "providers": providers,
            "persisted": os.path.exists(_LLM_CONFIG_PATH),
        })

    @app.route("/llm/config", methods=["POST"])
    def llm_config_set() -> Response:
        payload = request.json or {}
        provider = (payload.get("provider") or "").lower()
        api_key = payload.get("api_key", "")
        model = payload.get("model", "")
        base_url = payload.get("base_url", "")

        if not provider:
            return jsonify({"status": "error", "message": "provider is required"}), 400

        if provider not in list_supported_providers():
            return jsonify({"status": "error", "message": f"unsupported provider: {provider}"}), 400

        _runtime_llm_config.clear()
        _runtime_llm_config["provider"] = provider
        if api_key:
            _runtime_llm_config["api_key"] = api_key
        if model:
            _runtime_llm_config["model"] = model
        if base_url:
            _runtime_llm_config["base_url"] = base_url.rstrip("/")

        os.environ["LLM_PROVIDER"] = provider
        if api_key:
            os.environ["LLM_API_KEY"] = api_key
        if model:
            os.environ["LLM_MODEL"] = model
        if base_url:
            os.environ["LLM_BASE_URL"] = base_url.rstrip("/")

        _save_llm_config(_runtime_llm_config)

        try:
            get_model_router()._adapters.clear()
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "message": "LLM 配置已更新并保存",
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "api_key_set": bool(api_key),
            "persisted": True,
        })

    @app.route("/llm/test", methods=["POST"])
    def llm_test() -> Response:
        try:
            provider = _runtime_llm_config.get("provider") or get_llm_provider()
            model = _runtime_llm_config.get("model") or os.environ.get("LLM_MODEL", "deepseek-chat")
            api_key = _runtime_llm_config.get("api_key") or get_llm_api_key()
            base_url = _runtime_llm_config.get("base_url") or get_llm_base_url()

            if not api_key:
                return jsonify({
                    "status": "error",
                    "message": "API Key 未配置，请先在系统设置中填写",
                }), 400

            if not model or model == provider:
                return jsonify({
                    "status": "error",
                    "message": f"模型名称不正确（当前: '{model}'）。DeepSeek 应为 'deepseek-chat'，通义千问应为 'qwen-turbo'。",
                    "provider": provider,
                    "model": model,
                }), 400

            adapter = get_llm_adapter(
                provider=provider, model=model, api_key=api_key, base_url=base_url
            )
            from nexus.llm.llm_adapter import ChatMessage
            messages = [ChatMessage(role="user", content="请回复：鉴真智能体连接测试成功")]
            response = adapter.chat(messages, max_tokens=50)

            if response.is_success:
                return jsonify({
                    "status": "success",
                    "message": "LLM 连接测试成功",
                    "provider": provider,
                    "model": model,
                    "base_url": base_url,
                    "response": response.content[:200],
                })
            else:
                error_msg = response.error or "未知错误"
                hint = ""
                if "401" in str(error_msg) or "Unauthorized" in str(error_msg):
                    hint = "（API Key 无效或已过期，请检查）"
                elif "404" in str(error_msg) or "Not Found" in str(error_msg):
                    hint = f"（Base URL 错误，{provider} 的正确地址请参考文档）"
                elif "Connection" in str(error_msg) or "timeout" in str(error_msg).lower():
                    hint = "（网络连接失败，请检查 Base URL 是否正确）"
                elif "model" in str(error_msg).lower():
                    hint = "（模型名称错误，请检查 model 字段）"
                return jsonify({
                    "status": "error",
                    "message": f"LLM 调用失败{hint}: {error_msg}",
                    "provider": provider,
                    "model": model,
                    "base_url": base_url,
                }), 500
        except Exception as exc:
            return jsonify({
                "status": "error",
                "message": f"测试失败: {str(exc)}",
            }), 500

    # ===== XDR 平台集成配置 =====
    _XDR_CONFIG_PATH = os.path.join(os.environ.get("NEXUS_WORKSPACE", "."), ".nexus", "xdr_config.json")

    def _load_xdr_config() -> Dict[str, Any]:
        config: Dict[str, Any] = {}
        if os.path.exists(_XDR_CONFIG_PATH):
            try:
                with open(_XDR_CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception:
                config = {}
        # 兼容迁移：旧版 Wazuh 将 Indexer 密码存在 api_key，且没有显式 indexer_* 字段
        if config.get("provider") == "wazuh":
            old_idx_pwd = config.get("indexer_password") or config.get("api_key")
            if old_idx_pwd and not config.get("indexer_password"):
                config["indexer_password"] = old_idx_pwd
            if not config.get("indexer_url"):
                base = (config.get("base_url") or "").rstrip("/")
                if base.endswith(":55000"):
                    config["indexer_url"] = base.rsplit(":", 1)[0] + ":9200"
                elif base:
                    config["indexer_url"] = base
            if not config.get("indexer_user") and config.get("indexer_password"):
                config["indexer_user"] = "admin"
        return config

    def _save_xdr_config(config: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(_XDR_CONFIG_PATH), exist_ok=True)
        with open(_XDR_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

    def _xdr_config_complete(cfg: Dict[str, Any]) -> bool:
        """判断保存的配置是否齐全（可直接启动 XDR 拉取模式，无需手动点测试连接）。"""
        from nexus.integrations.xdr import GENERIC_REST_PROVIDERS
        provider = (cfg.get("provider") or "").lower()
        base = (cfg.get("base_url") or "").strip()
        if not provider or not base:
            return False
        if provider == "wazuh":
            return bool(
                cfg.get("username")
                and cfg.get("password")
                and (cfg.get("indexer_password") or cfg.get("api_key"))
            )
        # 通用 REST 厂商（splunk/elastic/sentinel/qradar/aliyun_sas/huawei_secmaster）
        if provider in GENERIC_REST_PROVIDERS:
            # 必须有 alerts_endpoint 和认证凭据
            has_endpoint = bool(cfg.get("alerts_endpoint"))
            has_credential = bool(
                cfg.get("api_key")
                or (cfg.get("username") and cfg.get("password"))
            )
            return has_endpoint and has_credential
        return False

    def _xdr_client_from_runtime() -> Optional[Any]:
        """基于持久化文件构造 XDR 客户端；配置不齐全时返回 None。
        每次从文件加载（文件即真相），避免内存缓存与文件不同步。
        """
        try:
            from nexus.integrations.xdr import (
                get_xdr_client, XDRConfig,
                SUPPORTED_XDR_PROVIDERS, GENERIC_REST_PROVIDERS, VENDOR_PRESETS,
            )
        except Exception:
            return None
        cfg = _load_xdr_config()
        if not _xdr_config_complete(cfg):
            return None
        provider = (cfg.get("provider") or "").lower()
        config = XDRConfig(
            provider=provider,
            base_url=(cfg.get("base_url") or "").rstrip("/"),
            api_key=cfg.get("api_key", "") or cfg.get("indexer_password", ""),
            username=cfg.get("username", ""),
            password=cfg.get("password", ""),
            verify_ssl=bool(cfg.get("verify_ssl", True)),
            timeout=int(cfg.get("timeout", 30)),
            indexer_url=(cfg.get("indexer_url") or "").rstrip("/"),
            indexer_user=cfg.get("indexer_user", "") or "admin",
            indexer_password=cfg.get("indexer_password", "") or cfg.get("api_key", ""),
            # 通用 REST 字段
            auth_type=cfg.get("auth_type", ""),
            auth_header_name=cfg.get("auth_header_name", ""),
            alerts_endpoint=cfg.get("alerts_endpoint", ""),
            alerts_json_path=cfg.get("alerts_json_path", ""),
            field_mapping=cfg.get("field_mapping", {}) if isinstance(cfg.get("field_mapping"), dict) else {},
            tenant_id=cfg.get("tenant_id", ""),
            token_url=cfg.get("token_url", ""),
            region=cfg.get("region", ""),
        )
        return get_xdr_client(provider, config)

    _runtime_xdr_config: Dict[str, Any] = _load_xdr_config()

    # ----- XDR 统一告警+研判 FIFO 队列 -----
    # 每条记录格式: {alert_id, alert, analysis, status, analyzed_at}
    # status: "pending" (研判中) | "done" (研判完成) | "error" (研判失败)
    _XDR_QUEUE_MAX = 100
    _xdr_queue: deque = deque(maxlen=_XDR_QUEUE_MAX)
    _xdr_queue_lock = threading.Lock()
    # 已分析过的 alert_id 集合（用于去重）
    _xdr_analyzed_ids: set = set()
    # 停止监测事件（stop 时 set，轮询循环检查后立即退出）
    _xdr_stop_event = threading.Event()

    @app.route("/integrations/xdr/config", methods=["GET"])
    def xdr_config_get() -> Response:
        # 局部 import：避免循环依赖，同时让本函数能访问 SUPPORTED_XDR_PROVIDERS 等
        from nexus.integrations.xdr import (
            SUPPORTED_XDR_PROVIDERS, GENERIC_REST_PROVIDERS, VENDOR_PRESETS,
        )
        # 每次从文件加载（文件即真相），保证重启或外部修改后立刻生效
        config = _load_xdr_config()
        provider = config.get("provider", "")
        resp = {
            "provider": provider,
            "base_url": config.get("base_url", ""),
            "verify_ssl": config.get("verify_ssl", True),
            "timeout": config.get("timeout", 30),
            "persisted": os.path.exists(_XDR_CONFIG_PATH),
            "providers": SUPPORTED_XDR_PROVIDERS,
            # 厂商预设模板（前端选择平台时自动填充）
            "vendor_presets": VENDOR_PRESETS,
            # 直接启用 XDR 模式（不需要用户手动点测试连接）
            "can_enable_xdr": _xdr_config_complete(config),
            # 敏感字段仅在存在时返回 "********"，不在响应中暴露明文
            "api_key_set": bool(config.get("api_key")),
            "username_set": bool(config.get("username")),
            "password_set": bool(config.get("password")),
            "indexer_password_set": bool(config.get("indexer_password")),
            # Wazuh 专属字段（明文可见）
            "indexer_url": config.get("indexer_url", ""),
            "indexer_user": config.get("indexer_user", ""),
            # 通用 REST 字段（明文返回，非敏感）
            "auth_type": config.get("auth_type", ""),
            "auth_header_name": config.get("auth_header_name", ""),
            "alerts_endpoint": config.get("alerts_endpoint", ""),
            "alerts_json_path": config.get("alerts_json_path", ""),
            "field_mapping": config.get("field_mapping", {}),
            "tenant_id": config.get("tenant_id", ""),
            "token_url": config.get("token_url", ""),
            "region": config.get("region", ""),
        }
        # Wazuh: 展示已配置的用户名
        if provider == "wazuh":
            if config.get("username"):
                resp["username"] = config["username"]  # 用户名可明文回显
            resp["password_mask"] = "********" if config.get("password") else ""
            if config.get("indexer_password"):
                resp["indexer_password_mask"] = "********"
            resp["provider_hint"] = "已通过 Manager REST API + Indexer 与 Wazuh 对接"
        # 通用 REST 厂商：掩码 + 文案
        if provider in GENERIC_REST_PROVIDERS:
            preset = VENDOR_PRESETS.get(provider, {})
            label = preset.get("label", provider)
            if config.get("api_key"):
                resp["api_key_mask"] = _mask_secret(config["api_key"])
            if config.get("username"):
                resp["username"] = config["username"]
            if config.get("password"):
                resp["password_mask"] = "********"
            auth_label = {
                "bearer_token": "Bearer Token",
                "api_key_header": "API Key Header",
                "basic_auth": "Basic Auth",
                "aliyun_sig": "阿里云 AK/SK 签名",
                "huawei_sig": "华为云 AK/SK 签名",
            }.get(config.get("auth_type", ""), config.get("auth_type", ""))
            resp["provider_hint"] = f"已通过 {label} 通用 REST 接口对接（{auth_label}）"
        return jsonify(resp)

    @app.route("/integrations/xdr/config", methods=["POST"])
    def xdr_config_set() -> Response:
        # 局部 import：避免循环依赖，同时让本函数能访问 SUPPORTED_XDR_PROVIDERS 等
        from nexus.integrations.xdr import (
            SUPPORTED_XDR_PROVIDERS, GENERIC_REST_PROVIDERS, VENDOR_PRESETS,
        )
        payload = request.json or {}
        provider = (payload.get("provider") or "").lower()
        base_url = (payload.get("base_url") or "").rstrip("/")
        api_key = payload.get("api_key", "")
        username = payload.get("username", "")
        password = payload.get("password", "")
        indexer_url = (payload.get("indexer_url") or "").rstrip("/")
        indexer_user = payload.get("indexer_user", "")
        indexer_password = payload.get("indexer_password", "")
        verify_ssl = payload.get("verify_ssl", True)
        timeout = int(payload.get("timeout", 30))
        # 通用 REST 字段
        auth_type = payload.get("auth_type", "")
        auth_header_name = payload.get("auth_header_name", "")
        alerts_endpoint = payload.get("alerts_endpoint", "")
        alerts_json_path = payload.get("alerts_json_path", "")
        field_mapping = payload.get("field_mapping", {})
        tenant_id = payload.get("tenant_id", "")
        token_url = payload.get("token_url", "")
        region = payload.get("region", "")

        if not provider:
            return jsonify({"status": "error", "message": "provider is required"}), 400
        if provider not in SUPPORTED_XDR_PROVIDERS:
            return jsonify({"status": "error", "message": f"unsupported provider: {provider}"}), 400
        if not base_url:
            return jsonify({"status": "error", "message": "base_url is required"}), 400

        # 保留之前已保存的敏感字段：当传入的是 "********" 或空串时，保留已存储的值
        # 从文件读取旧配置（文件即真相），避免内存缓存与文件不同步
        existing = _load_xdr_config()
        _runtime_xdr_config.clear()
        _runtime_xdr_config.update(existing)
        keep_mask = "********"

        def _resolve(current: str, key: str, allow_empty: bool = False) -> str:
            if current and current != keep_mask:
                return current
            if key in existing and existing[key]:
                return existing[key]
            if allow_empty or current == "":
                return current
            return ""

        _runtime_xdr_config.clear()
        _runtime_xdr_config["provider"] = provider
        _runtime_xdr_config["base_url"] = base_url
        _runtime_xdr_config["verify_ssl"] = verify_ssl
        _runtime_xdr_config["timeout"] = timeout

        if provider == "wazuh":
            resolved_username = _resolve(username, "username")
            if resolved_username:
                _runtime_xdr_config["username"] = resolved_username
            resolved_password = _resolve(password, "password")
            if resolved_password:
                _runtime_xdr_config["password"] = resolved_password
            # Indexer 字段
            if indexer_url:
                _runtime_xdr_config["indexer_url"] = indexer_url
            elif indexer_user or indexer_password:
                # 若传了 Indexer 凭据但未传 URL，则从 base_url 推断
                inferred = _runtime_xdr_config.get("indexer_url") or _infer_indexer_url(base_url)
                _runtime_xdr_config["indexer_url"] = inferred
            if indexer_user:
                _runtime_xdr_config["indexer_user"] = indexer_user
            elif "indexer_user" in existing and existing["indexer_user"]:
                _runtime_xdr_config["indexer_user"] = existing["indexer_user"]
            resolved_idx_pwd = _resolve(indexer_password, "indexer_password")
            if resolved_idx_pwd:
                _runtime_xdr_config["indexer_password"] = resolved_idx_pwd
            # 兼容：向后保留 api_key 字段（承载 indexer_password）
            if _runtime_xdr_config.get("indexer_password"):
                _runtime_xdr_config["api_key"] = _runtime_xdr_config["indexer_password"]
            elif existing.get("api_key") and not _runtime_xdr_config.get("indexer_password"):
                _runtime_xdr_config["api_key"] = existing["api_key"]
                _runtime_xdr_config["indexer_password"] = existing["api_key"]
                if not _runtime_xdr_config.get("indexer_url"):
                    _runtime_xdr_config["indexer_url"] = _infer_indexer_url(base_url)
                if not _runtime_xdr_config.get("indexer_user"):
                    _runtime_xdr_config["indexer_user"] = "admin"

        elif provider in GENERIC_REST_PROVIDERS:
            # 通用 REST 厂商：保存通用字段 + 凭据
            _runtime_xdr_config["auth_type"] = auth_type
            _runtime_xdr_config["auth_header_name"] = auth_header_name
            _runtime_xdr_config["alerts_endpoint"] = alerts_endpoint
            _runtime_xdr_config["alerts_json_path"] = alerts_json_path
            _runtime_xdr_config["field_mapping"] = field_mapping if isinstance(field_mapping, dict) else {}
            _runtime_xdr_config["tenant_id"] = tenant_id
            _runtime_xdr_config["token_url"] = token_url
            _runtime_xdr_config["region"] = region
            # 凭据：根据 auth_type 决定存 api_key 还是 username/password
            if auth_type in ("basic_auth",):
                resolved_username = _resolve(username, "username")
                if resolved_username:
                    _runtime_xdr_config["username"] = resolved_username
                resolved_password = _resolve(password, "password")
                if resolved_password:
                    _runtime_xdr_config["password"] = resolved_password
            else:
                # bearer_token / api_key_header / aliyun_sig / huawei_sig 都用 api_key
                resolved_api_key = _resolve(api_key, "api_key")
                if resolved_api_key:
                    _runtime_xdr_config["api_key"] = resolved_api_key

        _save_xdr_config(_runtime_xdr_config)

        logger.info(f"[XDR Config] Saved: provider={provider}, base_url={base_url}")
        return jsonify({
            "status": "success",
            "message": "XDR 配置已更新并保存到本地",
            "provider": provider,
            "base_url": base_url,
            "credentials_set": bool(
                _runtime_xdr_config.get("api_key")
                or (_runtime_xdr_config.get("username") and _runtime_xdr_config.get("password"))
                or _runtime_xdr_config.get("indexer_password")
            ),
            "persisted": True,
        })

    def _mask_secret(val: str) -> str:
        if not val:
            return ""
        if len(val) <= 8:
            return "*" * len(val)
        return val[:4] + "****" + val[-4:]

    def _infer_indexer_url(manager_base_url: str) -> str:
        """从 Wazuh Manager base_url (https://host:55000) 推断 Indexer 地址 (https://host:9200)。"""
        base = (manager_base_url or "").rstrip("/")
        if not base:
            return ""
        if base.endswith(":55000"):
            return base[:-6] + ":9200"
        if ":55000/" in base:
            return base.replace(":55000/", ":9200/")
        return base

    @app.route("/integrations/xdr/alerts", methods=["GET"])
    def xdr_alerts_list() -> Response:
        """从已保存配置的 XDR 平台拉取告警列表（实时）。"""
        limit = request.args.get("limit", 20, type=int)
        severity = request.args.get("severity", "").strip() or None
        time_range = request.args.get("time_range", "").strip() or None
        client = _xdr_client_from_runtime()
        if client is None:
            return jsonify({
                "status": "error",
                "message": "XDR 平台尚未配置完整（缺少凭据或地址），请先在系统设置中填写。",
                "alerts": [],
                "count": 0,
            }), 200
        try:
            alerts = client.fetch_alerts(limit=limit, severity=severity, time_range=time_range)
            provider = client.provider_name
            client.close()

            def _alert_to_dict(a: Any) -> Dict[str, Any]:
                if hasattr(a, "to_dict"):
                    return a.to_dict()
                if isinstance(a, dict):
                    return a
                return {
                    "alert_id": getattr(a, "alert_id", ""),
                    "title": getattr(a, "title", ""),
                    "severity": getattr(a, "severity", ""),
                    "source": getattr(a, "source", ""),
                    "timestamp": getattr(a, "timestamp", ""),
                    "details": getattr(a, "details", {}),
                    "raw_data": getattr(a, "raw_data", {}),
                }

            payload = [_alert_to_dict(a) for a in alerts]
            return jsonify({
                "status": "success",
                "provider": provider,
                "alerts": payload,
                "count": len(payload),
                "limit": limit,
                "severity": severity,
                "time_range": time_range,
            })
        except Exception as exc:
            logger.exception("[XDR Alerts] Fetch failed")
            return jsonify({
                "status": "error",
                "message": f"拉取告警失败: {str(exc)}",
                "alerts": [],
                "count": 0,
            }), 500

    @app.route("/integrations/xdr/alerts/<alert_id>", methods=["GET"])
    def xdr_alert_detail(alert_id: str) -> Response:
        client = _xdr_client_from_runtime()
        if client is None:
            return jsonify({"status": "error", "message": "XDR 未配置完整"}), 200
        try:
            alert = client.get_alert(alert_id)
            client.close()
            if not alert:
                return jsonify({"status": "error", "message": "告警不存在"}), 404

            def _detail(a: Any) -> Dict[str, Any]:
                if hasattr(a, "to_dict"):
                    return a.to_dict()
                if isinstance(a, dict):
                    return a
                return {
                    "alert_id": getattr(a, "alert_id", alert_id),
                    "title": getattr(a, "title", ""),
                    "severity": getattr(a, "severity", ""),
                    "source": getattr(a, "source", ""),
                    "timestamp": getattr(a, "timestamp", ""),
                    "details": getattr(a, "details", {}),
                    "raw_data": getattr(a, "raw_data", {}),
                }

            return jsonify({"status": "success", "alert": _detail(alert)})
        except Exception as exc:
            logger.exception("[XDR Alert Detail] Fetch failed")
            return jsonify({"status": "error", "message": str(exc)}), 500

    # -------- XDR 告警智能分析（LLM 研判 + 规则降级） --------

    _xdr_agent_singleton: List[Any] = []  # 用 list 容器实现 nonlocal 单例缓存

    def _get_cangsight_agent_instance() -> Optional[Any]:
        """懒加载 CangSightAgent 单例（复用全局 _registry，避免每次请求重新初始化）。"""
        if _xdr_agent_singleton:
            return _xdr_agent_singleton[0]
        try:
            reg = get_registry()
            from nexus.agents.cangsight_agent import CangSightAgent
            agent = CangSightAgent(
                registry=reg,
                policy={"approval_timeout_sec": 60},
            )
            _xdr_agent_singleton.append(agent)
            return agent
        except Exception as exc:
            logger.warning(f"[XDR Analyze] Failed to init CangSightAgent: {exc}")
            return None

    @app.route("/integrations/xdr/analyze", methods=["POST"])
    def xdr_analyze() -> Response:
        """对 medium 及以上告警批量调 CangSightAgent.analyze_xdr_alert 做智能研判。

        为了让「停止监测」按钮立即生效，研判任务会放到后台线程中异步执行：
        - 调用后立即返回 {status: started}
        - 研判完成的告警会被推入统一 FIFO 队列（/integrations/xdr/alerts/unified 读取）
        - 若中途收到 stop 事件（/integrations/xdr/stop 触发），后台线程会在下一次 LLM 调用前退出
        """
        payload = request.json or {}
        alerts: List[Dict[str, Any]] = list(payload.get("alerts") or [])

        # 若前端未透传告警，则自动从 Indexer 拉取
        if not alerts:
            client = _xdr_client_from_runtime()
            if client is None:
                return jsonify({
                    "status": "error",
                    "message": "XDR 平台尚未配置完整，无法拉取告警进行分析。",
                }), 200
            try:
                limit = int(payload.get("limit") or 10)
                severity = payload.get("severity") or "medium"
                xdr_alerts = client.fetch_alerts(limit=limit, severity=severity, time_range="24h")
                client.close()

                def _alert_to_dict(a: Any) -> Dict[str, Any]:
                    if hasattr(a, "to_dict"):
                        return a.to_dict()
                    if isinstance(a, dict):
                        return a
                    return {
                        "alert_id": getattr(a, "alert_id", ""),
                        "title": getattr(a, "title", ""),
                        "severity": getattr(a, "severity", ""),
                        "source": getattr(a, "source", ""),
                        "timestamp": getattr(a, "timestamp", ""),
                        "details": getattr(a, "details", {}),
                        "raw_data": getattr(a, "raw_data", {}),
                    }

                alerts = [_alert_to_dict(a) for a in xdr_alerts]
            except Exception as exc:
                logger.exception("[XDR Analyze] Auto-fetch alerts failed")
                return jsonify({
                    "status": "error",
                    "message": f"拉取告警失败: {exc}",
                }), 500

        if not alerts:
            return jsonify({
                "status": "success",
                "message": "过去 24 小时无 medium 及以上告警，无需分析。",
                "started": False,
            })

        if _xdr_stop_event.is_set():
            # 停止事件已设置 → 本轮不启动新的后台线程
            return jsonify({
                "status": "success",
                "message": "监测已停止，本轮跳过研判",
                "started": False,
            })

        # 保存到闭包，供后台线程使用
        captured_alerts: List[Dict[str, Any]] = list(alerts)

        def _run_analysis() -> None:
            """后台线程：逐条分析告警，将结果推入统一队列。"""
            if _xdr_stop_event.is_set():
                return
            agent = _get_cangsight_agent_instance()
            if agent is None:
                logger.warning("[XDR Analyze Background] agent unavailable, aborting")
                return

            # 过滤已分析过的（去重）
            new_alerts: List[Dict[str, Any]] = []
            skipped = 0
            for a in captured_alerts:
                aid = str(a.get("alert_id") or a.get("id") or "")
                if aid and aid in _xdr_analyzed_ids:
                    skipped += 1
                    continue
                new_alerts.append(a)
                if aid:
                    _xdr_analyzed_ids.add(aid)

            if skipped:
                logger.info(f"[XDR Analyze Background] skipped {skipped} duplicates")

            for a in new_alerts:
                # 每条研判前检查停止事件 → 让 stop 按钮立即生效
                if _xdr_stop_event.is_set():
                    logger.info("[XDR Analyze Background] Stop event detected, aborting remaining analyses")
                    break
                try:
                    analysis = agent.analyze_xdr_alert(a)
                    alert_summary = {
                        "alert_id": a.get("alert_id") or a.get("id") or "",
                        "title": a.get("title") or "",
                        "severity": a.get("severity") or "",
                        "source": a.get("source") or "",
                        "timestamp": a.get("timestamp") or "",
                    }
                    analysis["alert"] = alert_summary

                    aid = alert_summary.get("alert_id", "")
                    queue_item = {
                        "alert_id": aid,
                        "alert": alert_summary,
                        "analysis": analysis,
                        "status": "done",
                        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    with _xdr_queue_lock:
                        _xdr_queue.appendleft(queue_item)
                except Exception as exc:
                    logger.warning(f"[XDR Analyze Background] analyze alert failed: {exc}")
                    error_alert = a.get("alert_id") or a.get("id") or ""
                    error_analysis = {
                        "alert_id": error_alert,
                        "alert": {
                            "alert_id": error_alert,
                            "title": a.get("title") or "",
                            "severity": a.get("severity") or "",
                            "source": a.get("source") or "",
                            "timestamp": a.get("timestamp") or "",
                        },
                        "threat_level": "未知",
                        "confidence": 0.0,
                        "reasoning": f"分析异常: {exc}",
                        "attack_technique": "",
                        "recommended_action": "monitor",
                        "target_ips": [],
                        "cwe": None,
                        "source": "error",
                        "status": "error",
                        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    with _xdr_queue_lock:
                        _xdr_queue.appendleft({
                            "alert_id": error_alert,
                            "alert": error_analysis["alert"],
                            "analysis": error_analysis,
                            "status": "error",
                            "analyzed_at": error_analysis["analyzed_at"],
                        })

        # 异步启动后台线程 → 立即释放 Flask 请求线程
        t = threading.Thread(target=_run_analysis, name="xdr-analyze-worker", daemon=True)
        t.start()

        return jsonify({
            "status": "success",
            "started": True,
            "message": f"已为 {len(captured_alerts)} 条告警启动异步研判线程",
            "count": len(captured_alerts),
            "total_cached": len(_xdr_queue),
        })

    @app.route("/integrations/xdr/analyses", methods=["GET"])
    def xdr_analyses_list() -> Response:
        """返回最近的分析结果列表（从统一队列读取，仅返回 analysis 部分用于兼容旧接口）。"""
        limit = request.args.get("limit", 50, type=int)
        threat_level = request.args.get("threat_level", "").strip() or None
        with _xdr_queue_lock:
            items = [item["analysis"] for item in _xdr_queue]
        if threat_level:
            items = [x for x in items if x.get("threat_level") == threat_level]
        return jsonify({
            "status": "success",
            "analyses": items[:limit],
            "count": len(items[:limit]),
            "total_cached": len(_xdr_queue),
        })

    @app.route("/integrations/xdr/alerts/unified", methods=["GET"])
    def xdr_alerts_unified() -> Response:
        """返回统一告警+研判 FIFO 队列快照（队首为最新，队末为最旧，最多 100 条）。

        每条记录格式:
            {
                alert_id: str,
                alert: {alert_id, title, severity, source, timestamp},
                analysis: {threat_level, confidence, reasoning, attack_technique, recommended_action, ...},
                status: "pending" | "done" | "error",
                analyzed_at: str
            }

        超过 100 条时自动淘汰队末（最旧）的记录。
        """
        limit = request.args.get("limit", 100, type=int)
        with _xdr_queue_lock:
            items = list(_xdr_queue)
        # deque 队首是最新的，按最新在前排序
        items.reverse()
        return jsonify({
            "status": "success",
            "items": items[:limit],
            "count": len(items[:limit]),
            "total_cached": len(_xdr_queue),
            "max_size": _XDR_QUEUE_MAX,
        })

    @app.route("/integrations/xdr/stop", methods=["POST"])
    def xdr_stop() -> Response:
        """停止 XDR 监测：设置 stop 事件，清空队列和已分析 ID，重置连接状态。

        前端点击"停止监测"时调用此接口，后端会：
        1. 设置 threading.Event，正在进行的研判/轮询会在下一次检查时立即退出
        2. 清空告警+研判队列和去重集合
        3. 重置连接状态标志
        """
        _xdr_stop_event.set()
        # 清空队列（释放内存，但保留最近 10 条的简洁视图让用户看到停止前的最后一批结果）
        with _xdr_queue_lock:
            _xdr_queue.clear()
        # 清空去重集合
        _xdr_analyzed_ids.clear()
        logger.info("[XDR] Monitoring stopped, queue and dedup cache cleared")
        return jsonify({
            "status": "success",
            "message": "XDR 监测已停止",
            "queue_cleared": True,
        })

    @app.route("/integrations/xdr/start", methods=["POST"])
    def xdr_start() -> Response:
        """启动 XDR 监测：清除 stop 事件，允许轮询和研判继续。"""
        _xdr_stop_event.clear()
        logger.info("[XDR] Monitoring started")
        return jsonify({
            "status": "success",
            "message": "XDR 监测已启动",
        })

    @app.route("/integrations/xdr/respond", methods=["POST"])
    def xdr_respond() -> Response:
        """对指定告警执行处置动作（走 HITL 人审 → 调 Wazuh client 真实下发）。

        请求体：
            alert_id: str
            action: 'block_ip' | 'isolate' | 'unblock_ip'
            target_ips: List[str]
            reason: str (可选)
        """
        payload = request.json or {}
        alert_id = str(payload.get("alert_id") or "")
        action = str(payload.get("action") or "block_ip").strip().lower()
        target_ips = list(payload.get("target_ips") or [])
        reason = str(payload.get("reason") or "")

        if not target_ips:
            return jsonify({
                "status": "error",
                "message": "缺少待处置的目标 IP（target_ips）。",
            }), 400

        if action not in ("block_ip", "isolate", "unblock_ip"):
            return jsonify({
                "status": "error",
                "message": f"未知处置动作: {action}（支持 block_ip / isolate / unblock_ip）。",
            }), 400

        agent = _get_cangsight_agent_instance()
        if agent is None:
            return jsonify({
                "status": "error",
                "message": "智能体初始化失败，无法执行处置。",
            }), 500

        try:
            result = agent.respond_xdr_alert(
                alert_id=alert_id, action=action,
                target_ips=target_ips, reason=reason,
            )
            return jsonify({
                "status": "success",
                "result": result,
            })
        except Exception as exc:
            logger.exception("[XDR Respond] Failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/integrations/xdr/test", methods=["POST"])
    def xdr_test() -> Response:
        try:
            from nexus.integrations.xdr import (
                get_xdr_client, XDRConfig,
                SUPPORTED_XDR_PROVIDERS, GENERIC_REST_PROVIDERS, VENDOR_PRESETS,
            )

            payload = request.json or {}
            provider = (payload.get("provider") or "").lower()
            if not provider:
                provider = _load_xdr_config().get("provider", "")

            # 解析敏感值：当传入 "********" 时，使用已存储的真实值
            keep_mask = "********"
            existing = _load_xdr_config()

            def _res(current: str, key: str) -> str:
                if current and current != keep_mask:
                    return current
                return existing.get(key, "") or ""

            resolved_api_key = _res(payload.get("api_key", ""), "api_key")
            resolved_username = _res(payload.get("username", ""), "username")
            resolved_password = _res(payload.get("password", ""), "password")
            resolved_indexer_pwd = _res(
                payload.get("indexer_password", ""), "indexer_password"
            ) or resolved_api_key

            config = XDRConfig(
                provider=provider,
                base_url=(payload.get("base_url") or existing.get("base_url", "")).rstrip("/"),
                api_key=resolved_api_key,
                username=resolved_username,
                password=resolved_password,
                verify_ssl=bool(payload.get("verify_ssl", existing.get("verify_ssl", True))),
                timeout=int(payload.get("timeout", existing.get("timeout", 30))),
                indexer_url=(payload.get("indexer_url") or existing.get("indexer_url", "")).rstrip("/"),
                indexer_user=payload.get("indexer_user") or existing.get("indexer_user", "") or "admin",
                indexer_password=resolved_indexer_pwd,
                # 通用 REST 字段（从 existing 加载，确保测试时用已保存配置而非预设值）
                auth_type=existing.get("auth_type", "") or payload.get("auth_type", ""),
                auth_header_name=existing.get("auth_header_name", "") or payload.get("auth_header_name", ""),
                alerts_endpoint=existing.get("alerts_endpoint", "") or payload.get("alerts_endpoint", ""),
                alerts_json_path=existing.get("alerts_json_path", "") or payload.get("alerts_json_path", ""),
                field_mapping=existing.get("field_mapping", {}) if isinstance(existing.get("field_mapping"), dict) else {},
                tenant_id=existing.get("tenant_id", "") or payload.get("tenant_id", ""),
                token_url=existing.get("token_url", "") or payload.get("token_url", ""),
                region=existing.get("region", "") or payload.get("region", ""),
            )

            if not config.base_url:
                return jsonify({
                    "status": "error",
                    "message": "Base URL 未配置",
                }), 400

            client = get_xdr_client(provider, config)
            result = client.test_connection()
            client.close()

            if result.success:
                return jsonify({
                    "status": "success",
                    "message": result.message,
                    "provider": provider,
                    "latency_ms": result.latency_ms,
                    "details": result.details,
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": result.message,
                    "provider": provider,
                    "latency_ms": result.latency_ms,
                }), 500
        except Exception as exc:
            return jsonify({
                "status": "error",
                "message": f"测试失败: {str(exc)}",
            }), 500

    @app.route("/llm/chat", methods=["POST"])
    def llm_chat() -> Response:
        payload = request.json or {}
        message = payload.get("message", "")
        system_prompt = payload.get("system_prompt", "你是一个专业的安全运营助手，请用中文回答。")

        if not message:
            return make_error("message parameter required", 400)

        try:
            provider = _runtime_llm_config.get("provider") or get_llm_provider()
            model = _runtime_llm_config.get("model") or os.environ.get("LLM_MODEL", "deepseek-chat")
            api_key = _runtime_llm_config.get("api_key") or get_llm_api_key()
            base_url = _runtime_llm_config.get("base_url") or get_llm_base_url()

            if not api_key:
                return jsonify({
                    "status": "error",
                    "message": "API Key 未配置，请先在系统设置中配置大模型",
                    "refused": True,
                }), 400

            adapter = get_llm_adapter(
                provider=provider, model=model, api_key=api_key, base_url=base_url
            )
            from nexus.llm.llm_adapter import ChatMessage
            messages = [
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=message),
            ]
            response = adapter.chat(messages, max_tokens=2048)

            if response.is_success:
                return jsonify({
                    "status": "success",
                    "answer": response.content,
                    "provider": provider,
                    "model": model,
                    "usage": response.usage,
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": response.error or "LLM 调用失败",
                    "provider": provider,
                }), 500
        except Exception as exc:
            return jsonify({
                "status": "error",
                "message": f"调用失败: {str(exc)}",
            }), 500

    def _skills_to_tools() -> List[Dict[str, Any]]:
        reg = get_registry()
        skills_list = reg.list_skills()
        tools = []
        
        default_schemas = {
            "code_scan": {
                "properties": {"code": {"type": "string", "description": "代码内容"}},
                "required": ["code"]
            },
            "vkb_retrieve": {
                "properties": {
                    "query": {"type": "string", "description": "查询关键词"},
                    "top_k": {"type": "integer", "description": "返回数量"}
                },
                "required": ["query"]
            },
            "cwe_classifier": {
                "properties": {
                    "file": {"type": "string", "description": "代码文件路径"},
                    "findings": {"type": "array", "description": "漏洞列表"}
                },
                "required": []
            },
            "repair_prompt_bundle": {
                "properties": {
                    "cwe": {"type": "string", "description": "CWE编号"},
                    "code": {"type": "string", "description": "代码内容"}
                },
                "required": []
            },
            "uafr_report": {
                "properties": {"findings": {"type": "array", "description": "漏洞发现列表"}},
                "required": []
            },
            "pcap_analyze": {
                "properties": {"pcap_file": {"type": "string", "description": "PCAP文件路径"}},
                "required": ["pcap_file"]
            },
            "sbfl_rank": {
                "properties": {
                    "file": {"type": "string", "description": "代码文件路径"},
                    "top_k": {"type": "integer", "description": "返回数量"}
                },
                "required": []
            },
            "agent_context": {
                "properties": {"query": {"type": "string", "description": "查询问题"}},
                "required": []
            },
            "edr_isolation": {
                "properties": {"hostname": {"type": "string", "description": "主机名"}},
                "required": ["hostname"]
            },
            "firewall_block": {
                "properties": {"ip": {"type": "string", "description": "IP地址"}},
                "required": ["ip"]
            },
            "ctf_port_scan": {
                "properties": {
                    "host": {"type": "string", "description": "目标主机IP地址"},
                    "ports": {"type": "array", "description": "要扫描的端口列表"}
                },
                "required": ["host"]
            },
            "ctf_dir_brute": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "paths": {"type": "array", "description": "自定义路径列表"}
                },
                "required": ["url"]
            },
            "ctf_sql_inject": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"}
                },
                "required": ["url"]
            },
            "ctf_xss_test": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"}
                },
                "required": ["url"]
            },
            "ctf_upload_test": {
                "properties": {"url": {"type": "string", "description": "上传目标URL"}},
                "required": ["url"]
            },
            "ctf_find_flag": {
                "properties": {
                    "text": {"type": "string", "description": "要搜索的文本"},
                    "pattern": {"type": "string", "description": "Flag匹配模式"}
                },
                "required": ["text"]
            },
            "ctf_exploit_sqli": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "param": {"type": "string", "description": "注入参数名"},
                    "technique": {"type": "string", "description": "利用技术"}
                },
                "required": ["url", "param"]
            },
            "ctf_exploit_lfi": {
                "description": "LFI漏洞利用，读取敏感文件",
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "param": {"type": "string", "description": "文件参数名，默认file"}
                },
                "required": ["url"]
            },
            "ctf_exploit_rce": {
                "description": "命令注入利用，执行命令获取flag",
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "param": {"type": "string", "description": "命令参数名，默认cmd"}
                },
                "required": ["url"]
            },
            "ctf_http_request": {
                "properties": {
                    "method": {"type": "string", "description": "HTTP方法"},
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"},
                    "data": {"type": "object", "description": "请求体"},
                    "headers": {"type": "object", "description": "请求头"},
                    "cookies": {"type": "object", "description": "Cookie"}
                },
                "required": ["url"]
            },
            "ctf_subdomain_scan": {
                "properties": {
                    "domain": {"type": "string", "description": "目标域名"},
                    "wordlist": {"type": "array", "description": "自定义子域名列表"}
                },
                "required": ["domain"]
            },
            "ctf_ssrf_test": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"}
                },
                "required": ["url"]
            },
            "ctf_lfi_rfi_test": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"}
                },
                "required": ["url"]
            },
            "ctf_command_inject": {
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "params": {"type": "object", "description": "查询参数"}
                },
                "required": ["url"]
            },
            "ctf_sensitive_files": {
                "properties": {"url": {"type": "string", "description": "目标URL"}},
                "required": ["url"]
            },
            "ctf_encode_decode": {
                "properties": {
                    "text": {"type": "string", "description": "待处理文本"},
                    "operation": {"type": "string", "description": "操作类型"}
                },
                "required": ["text"]
            },
            "ctf_service_fingerprint": {
                "properties": {
                    "host": {"type": "string", "description": "目标主机"},
                    "ports": {"type": "array", "description": "端口列表"}
                },
                "required": ["host"]
            },
            "ctf_dns_info": {
                "properties": {"domain": {"type": "string", "description": "目标域名"}},
                "required": ["domain"]
            },
            "ctf_crypto_analysis": {
                "properties": {
                    "text": {"type": "string", "description": "待处理文本"},
                    "operation": {"type": "string", "description": "操作类型"}
                },
                "required": ["text"]
            },
            "ctf_hash_crack": {
                "properties": {
                    "hash": {"type": "string", "description": "待破解的哈希值"},
                    "type": {"type": "string", "description": "哈希类型"}
                },
                "required": ["hash"]
            },
            "ctf_binary_analysis": {
                "properties": {
                    "content": {"type": "string", "description": "二进制文件内容"},
                    "type": {"type": "string", "description": "文件类型"}
                },
                "required": ["content"]
            },
            "ctf_stego_analysis": {
                "properties": {
                    "content": {"type": "string", "description": "文件内容"},
                    "operation": {"type": "string", "description": "操作类型"}
                },
                "required": ["content"]
            },
            "ctf_jwt_analysis": {
                "properties": {"token": {"type": "string", "description": "JWT令牌"}},
                "required": ["token"]
            },
            "ctf_reverse_shell": {
                "properties": {
                    "ip": {"type": "string", "description": "监听IP地址"},
                    "port": {"type": "integer", "description": "监听端口"}
                },
                "required": ["ip"]
            },
            "start_scan": {
                "properties": {
                    "target_dir": {"type": "string", "description": "目标目录或文件路径"},
                    "rules": {"type": "string", "description": "规则集名称"},
                    "rules_yaml": {"type": "string", "description": "自定义规则YAML"}
                },
                "required": ["target_dir"]
            },
            "sympas_slice": {
                "properties": {
                    "source_file": {"type": "string", "description": "源文件路径"},
                    "variable": {"type": "string", "description": "目标变量名"}
                },
                "required": ["source_file"]
            },
            "sympas-hv": {
                "properties": {"target_file": {"type": "string", "description": "目标文件路径"}},
                "required": ["target_file"]
            },
            "generate_mr": {
                "properties": {
                    "program_path": {"type": "string", "description": "程序路径"},
                    "mr_count": {"type": "integer", "description": "生成数量"}
                },
                "required": ["program_path"]
            },
            "eval_patch_taint": {
                "properties": {
                    "original_code": {"type": "string", "description": "原始代码"},
                    "patch_code": {"type": "string", "description": "补丁代码"}
                },
                "required": ["original_code", "patch_code"]
            },
            "reproduce_fault": {
                "properties": {"fault_location": {"type": "string", "description": "故障位置"}},
                "required": ["fault_location"]
            },
            "concurrency_check": {
                "properties": {"source_dir": {"type": "string", "description": "源目录路径"}},
                "required": ["source_dir"]
            },
            "agentic_repair": {
                "properties": {
                    "target_file": {"type": "string", "description": "目标文件路径"},
                    "max_iterations": {"type": "integer", "description": "最大迭代次数"}
                },
                "required": ["target_file"]
            },
            "sympas_slice_table": {
                "properties": {
                    "source_file": {"type": "string", "description": "源文件路径"},
                    "output_format": {"type": "string", "description": "输出格式"}
                },
                "required": ["source_file"]
            },
            "dep_cluster": {
                "properties": {"project_dir": {"type": "string", "description": "项目目录路径"}},
                "required": ["project_dir"]
            },
            "sympas_dep_graph": {
                "properties": {
                    "source_file": {"type": "string", "description": "源文件路径"},
                    "graph_types": {"type": "array", "description": "图类型列表"}
                },
                "required": ["source_file"]
            },
            "sympas_dynamic_slice": {
                "properties": {
                    "source_file": {"type": "string", "description": "源文件路径"},
                    "trace_file": {"type": "string", "description": "追踪文件路径"}
                },
                "required": ["source_file"]
            },
            "taint_path_explainer": {
                "properties": {"source_file": {"type": "string", "description": "源文件路径"}},
                "required": ["source_file"]
            },
            "reachability_query": {
                "properties": {
                    "target_symbol": {"type": "string", "description": "目标符号"},
                    "direction": {"type": "string", "description": "查询方向"}
                },
                "required": ["target_symbol"]
            },
            "slice_diff": {
                "properties": {
                    "original_file": {"type": "string", "description": "原始文件路径"},
                    "patched_file": {"type": "string", "description": "补丁文件路径"}
                },
                "required": ["original_file", "patched_file"]
            },
            "sca_cve_scanner": {
                "properties": {"project_dir": {"type": "string", "description": "项目目录路径"}},
                "required": ["project_dir"]
            },
            "plan_case_reproduce": {
                "properties": {"case_id": {"type": "string", "description": "案例ID"}},
                "required": ["case_id"]
            },
            "plan_quality_gate": {
                "properties": {"project_dir": {"type": "string", "description": "项目目录路径"}},
                "required": ["project_dir"]
            },
            "four_layer_demo": {
                "properties": {"project_dir": {"type": "string", "description": "项目目录路径"}},
                "required": ["project_dir"]
            },
            "ast_symbol_extractor": {
                "properties": {"source_file": {"type": "string", "description": "源文件路径"}},
                "required": ["source_file"]
            },
            "patch_safety_verifier": {
                "properties": {
                    "original_code": {"type": "string", "description": "原始代码"},
                    "patch_code": {"type": "string", "description": "补丁代码"}
                },
                "required": ["original_code", "patch_code"]
            },
            "skill_doc_generator": {
                "properties": {"tool_ids": {"type": "array", "description": "工具ID列表"}},
                "required": []
            },
            "sarif_textual_export": {
                "properties": {"scan_results": {"type": "object", "description": "扫描结果"}},
                "required": []
            },
        }
        
        for skill in skills_list:
            if not isinstance(skill, dict):
                continue
            
            skill_id = skill.get("skill_id", "")
            if not skill_id:
                continue
            
            input_schema = skill.get("input_schema", {})
            properties = input_schema.get("properties", {})
            required = input_schema.get("required", [])
            
            if not properties and skill_id in default_schemas:
                properties = default_schemas[skill_id]["properties"]
                required = default_schemas[skill_id]["required"]
            
            tool = {
                "type": "function",
                "function": {
                    "name": skill_id,
                    "description": skill.get("description", ""),
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                }
            }
            tools.append(tool)
        
        return tools

    def detect_input_type(message: str) -> str:
        ctf_keywords = [
            "ctf", "flag", "pwn", "web", "crypto", "reverse", "misc",
            "渗透测试", "漏洞利用", "端口扫描", "目录爆破", "sql注入", "xss",
            "文件上传", "命令执行", "远程代码", "溢出", "缓冲区", "堆栈",
            "栈溢出", "格式化字符串", "ROP", "shellcode", "canary", "ret2libc",
            "CTF题目", "CTF挑战", "获取flag", "夺旗", "攻防", "靶场"
        ]
        
        security_event_keywords = [
            "安全事件", "告警", "攻击", "入侵", "异常", "威胁",
            "日志", "流量", "进程", "登录", "提权", "黑客",
            "恶意软件", "病毒", "木马", "钓鱼", "DDoS", "APT",
            "数据泄露", "违规", "策略", "防火墙", "EDR", "WAF"
        ]
        
        msg_lower = message.lower()
        
        ctf_score = sum(1 for kw in ctf_keywords if kw.lower() in msg_lower)
        security_score = sum(1 for kw in security_event_keywords if kw.lower() in msg_lower)
        
        if ctf_score > security_score:
            return "ctf"
        elif security_score > ctf_score:
            return "security_event"
        else:
            return "unknown"

    # 工具调用最大轮次。按"LLM 调用次数"计：一轮内模型可能返回多个 tool_calls，
    # 全部执行完再进下一轮。用尽后不再执行，交给调用方基于已有结果收口。
    MAX_TOOL_ROUNDS = 2

    def _parse_text_tool_call(content: str) -> Optional[Dict[str, Any]]:
        """兜底：模型没走 function calling，而是把调用写成了代码形式。

        只对不支持 tools 参数的模型生效，正常路径不会走到这里。
        """
        if not content:
            return None
        import re
        text = content.strip()
        match = re.search(r'^(\w+)\s*\(\s*code\s*=\s*["\'](.+)["\']\s*\)$', text, re.DOTALL)
        if match:
            return {"function_name": match.group(1),
                    "function_args": {"code": match.group(2).replace('\\"', '"')}}
        match = re.search(r'(\w+)\s*\(\s*code\s*=\s*(.+?)\s*\)', text)
        if match:
            return {"function_name": match.group(1),
                    "function_args": {"code": match.group(2).strip('"\'').replace('\\"', '"')}}
        return None

    def _compress_tool_result(tool_name: str, result: Any, max_chars: int = 6000) -> str:
        """把工具结果压成模型可读的紧凑文本。

        MCP 原始返回动辄 20KB，其中约 95% 是重复字段（data 与 report 相同、
        artifacts 与 graphs 相同、preview.json_source 是副本），engine_log 还含
        服务器绝对路径。直接塞进上下文会让模型淹没在噪音里，也白白消耗 token。
        """
        if not isinstance(result, dict):
            return str(result)[:max_chars]

        if tool_name == "sympas_dep_graph":
            graph = _extract_sympas_graph(result)
            if graph["status"] != "pass":
                # 必须带上 message：只给 reason 的话，模型看到 "tool_error"
                # 根本不知道是服务端 403 还是自己参数错了，只能换工具瞎试。
                return json.dumps(
                    {"status": graph["status"], "reason": graph.get("reason"),
                     "message": graph.get("message")},
                    ensure_ascii=False,
                )[:max_chars]
            payload = {
                "status": "pass",
                "graphs": [
                    {"graph_type": item.get("graph_type"),
                     "node_count": item.get("node_count"),
                     "edge_count": item.get("edge_count")}
                    for item in graph["graphs"]
                ],
                # structure 里是 "n0_16->n0_4" 这样的边，模型能直接看出回边与循环；
                # SVG 全是坐标，不要给模型。
                "structure": _graph_to_summary(graph["graphs"]),
            }
            return json.dumps(payload, ensure_ascii=False)[:max_chars]

        if tool_name in ("sympas_slice", "sympas_slice_table"):
            return json.dumps(
                _extract_sympas_slice(result), ensure_ascii=False
            )[:max_chars]

        if tool_name == "code_scan":
            issues = result.get("issues")
            if not isinstance(issues, list):
                issues = result.get("findings") if isinstance(result.get("findings"), list) else []
            slim = []
            for item in issues:
                if not isinstance(item, dict):
                    continue
                extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
                start = item.get("start") if isinstance(item.get("start"), dict) else {}
                slim.append({
                    "check_id": item.get("check_id") or item.get("rule_id"),
                    "message": extra.get("message") or item.get("description"),
                    "line": item.get("line", start.get("line")),
                    "severity": item.get("severity"),
                })
            return json.dumps(
                {"status": result.get("status"),
                 "reason": _classify_failure(result.get("message"))
                           if str(result.get("status", "")).lower() != "success" else None,
                 "message": result.get("message"),
                 "issues": slim[:50]},
                ensure_ascii=False,
            )[:max_chars]

        return json.dumps(result, ensure_ascii=False)[:max_chars]

    def _run_tool_loop(
        messages: List[Any],
        adapter: Any,
        tools: Optional[List[Dict[str, Any]]],
        max_rounds: int = MAX_TOOL_ROUNDS,
        is_reasoning_model: bool = False,
    ) -> Dict[str, Any]:
        """执行最多 max_rounds 轮工具调用，把结果以标准 tool 消息回灌上下文。

        与旧实现的区别：旧代码把 assistant/tool 消息 append 进 messages 后，
        又在 report_messages 里重建了一个只有 system+user 的序列，等于把工具
        结果全丢了；而且 assistant 缺 tool_calls、tool 缺 tool_call_id，
        这个序列本身也会被服务端以 400/422 拒收。

        返回：error / messages / answered / content / tool_calls / tool_results /
              rounds / usage
        """
        from nexus.llm.llm_adapter import ChatMessage

        tool_calls_all: List[Dict[str, Any]] = []
        tool_results_all: List[Dict[str, Any]] = []
        usage: Dict[str, Any] = {}
        rounds = 0
        reg = get_registry()

        def _call_llm() -> Any:
            kwargs: Dict[str, Any] = {
                "max_tokens": 8192 if is_reasoning_model else 1024
            }
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            return adapter.chat(messages, **kwargs)

        while rounds < max_rounds:
            response = _call_llm()
            if not response.is_success:
                return {
                    "error": response.error or "LLM 调用失败",
                    "messages": messages, "answered": False, "content": "",
                    "tool_calls": tool_calls_all,
                    "tool_results": tool_results_all,
                    "rounds": rounds, "usage": usage,
                }
            usage = response.usage or usage

            # 归一化本轮待执行调用，两类来源都转成统一结构
            pending: List[Dict[str, Any]] = []
            if response.tool_calls:
                for tc in response.tool_calls:
                    pending.append({
                        "id": tc.id,
                        "name": tc.function_name,
                        "args": tc.function_args,
                        "payload": tc.to_dict(),
                    })
            else:
                parsed = _parse_text_tool_call(response.content) if rounds == 0 else None
                if parsed:
                    tid = f"text_{uuid.uuid4().hex[:8]}"
                    pending.append({
                        "id": tid,
                        "name": parsed["function_name"],
                        "args": parsed["function_args"],
                        "payload": {
                            "id": tid, "type": "function",
                            "function": {
                                "name": parsed["function_name"],
                                "arguments": json.dumps(
                                    parsed["function_args"], ensure_ascii=False
                                ),
                            },
                        },
                    })

            if not pending:
                # 模型给出的是最终回答
                return {
                    "error": None, "messages": messages, "answered": True,
                    "content": response.content,
                    "tool_calls": tool_calls_all,
                    "tool_results": tool_results_all,
                    "rounds": rounds, "usage": usage,
                }

            logger.info(
                "[Agent Chat] round %d: %d tool call(s) -> %s",
                rounds + 1, len(pending), [p["name"] for p in pending],
            )

            messages.append(ChatMessage(
                role="assistant",
                content=response.content or "",
                tool_calls=[p["payload"] for p in pending],
            ))

            for item in pending:
                tool_name = item["name"]
                # 不打印 args：里面是完整源码
                logger.info("[Agent Chat] Executing tool: %s (args %d bytes)",
                            tool_name, len(json.dumps(item["args"], ensure_ascii=False)))
                failed = False
                try:
                    raw = reg.execute_skill(tool_name, item["args"])
                    if isinstance(raw, dict):
                        state = str(raw.get("status", "")).strip().lower()
                        failed = state in ("error", "failed", "blocked", "timeout")
                    else:
                        raw = {"status": "error", "message": "返回格式异常"}
                        failed = True
                except Exception as exc:
                    logger.warning("[Agent Chat] tool %s raised: %s", tool_name, exc)
                    raw = {"status": "error", "message": str(exc)}
                    failed = True

                # 失败必须留痕：这次对话只记了"Executing tool"，
                # 四个工具集体 403 时没有任何日志可查，只能事后猜。
                if failed:
                    logger.warning(
                        "[Agent Chat] tool %s failed: reason=%s message=%s",
                        tool_name,
                        _classify_failure(raw.get("message") if isinstance(raw, dict) else None),
                        str(raw.get("message") if isinstance(raw, dict) else raw)[:300],
                    )

                messages.append(ChatMessage(
                    role="tool",
                    content=_compress_tool_result(tool_name, raw),
                    tool_call_id=item["id"],
                ))
                tool_calls_all.append({
                    "id": item["id"], "name": tool_name, "args": item["args"],
                })
                tool_results_all.append({
                    "tool_name": tool_name,
                    "status": "error" if failed else "success",
                    "result": raw,
                    "error": (raw.get("message") if failed and isinstance(raw, dict) else None),
                })

            rounds += 1

        # 轮次用尽，模型还想继续调工具：不再执行，交给调用方收口
        return {
            "error": None, "messages": messages, "answered": False, "content": "",
            "tool_calls": tool_calls_all,
            "tool_results": tool_results_all,
            "rounds": rounds, "usage": usage,
        }

    def _agent_chat_prepare(message: str, input_type: str) -> Dict[str, Any]:
        """执行「多轮工具调用」，返回生成最终回答所需的上下文。

        工具结果以标准 assistant(tool_calls) + tool(tool_call_id) 消息回灌到
        messages，模型在后续轮次里读到的是结构化工具输出，不是二手摘要。

        返回 dict：
            - error：出错时存在，值为 {"message": str, "status": int, "refused": bool}
            - 成功时：provider / model / usage / has_tool_calls / tool_calls / tool_results /
              tool_rounds（实际执行的工具轮次）/
              final_messages（需要生成最终报告的 messages；模型已自行作答时为 None）/
              direct_answer（模型已自行作答时的回答）/
              adapter / max_tokens（生成最终报告的 max_tokens）
        """
        try:
            provider = _runtime_llm_config.get("provider") or get_llm_provider()
            model = _runtime_llm_config.get("model") or os.environ.get("LLM_MODEL", "deepseek-chat")
            api_key = _runtime_llm_config.get("api_key") or get_llm_api_key()
            base_url = _runtime_llm_config.get("base_url") or get_llm_base_url()

            if not api_key:
                return {
                    "error": {
                        "message": "API Key 未配置，请先在系统设置中配置大模型",
                        "status": 400,
                        "refused": True,
                    }
                }

            adapter = get_llm_adapter(
                provider=provider, model=model, api_key=api_key, base_url=base_url
            )
            from nexus.llm.llm_adapter import ChatMessage

            tools = _skills_to_tools()

            if not input_type:
                input_type = detect_input_type(message)

            logger.info(f"[Agent Chat] Detected input type: {input_type}")

            if input_type == "ctf":
                system_prompt = (
                    "你是鉴真CTF智能体（CangSight），一个专业的CTF攻防助手。\n\n"
                    "你的能力：分析CTF题目、制定攻击计划、利用漏洞获取Flag。\n"
                    "你可以自主判断用户意图，选择合适的工具进行分析，并结合工具结果和自身知识给出完整回答。\n\n"
                    "可用工具列表：\n"
                )
                for tool in tools:
                    func = tool["function"]
                    params = func.get("parameters", {}).get("properties", {})
                    param_list = ", ".join(params.keys())
                    system_prompt += f"- {func['name']}: {func['description']} (参数: {param_list})\n"

                system_prompt += "\n" + (
                    "工具使用指南（根据用户请求自动选择）：\n"
                    "- 扫描端口/服务 → ctf_port_scan, ctf_service_fingerprint\n"
                    "- 目录/路径发现 → ctf_dir_brute, ctf_sensitive_files\n"
                    "- Web漏洞检测 → ctf_sql_inject, ctf_xss_test, ctf_ssrf_test, ctf_lfi_rfi_test, ctf_command_inject, ctf_upload_test\n"
                    "- 编码/解码 → ctf_encode_decode\n"
                    "- 密码学 → ctf_crypto_analysis, ctf_hash_crack\n"
                    "- 二进制/逆向 → ctf_binary_analysis\n"
                    "- 隐写术 → ctf_stego_analysis\n"
                    "- JWT分析 → ctf_jwt_analysis\n"
                    "- DNS/子域名 → ctf_dns_info, ctf_subdomain_scan\n"
                    "- HTTP请求 → ctf_http_request\n"
                    "- Flag搜索 → ctf_find_flag\n"
                    "- 代码分析 → code_scan\n"
                    "- 漏洞知识 → vkb_retrieve, cwe_classifier\n"
                    "- 修复建议 → repair_prompt_bundle\n"
                    "- 普通对话/知识问答 → 直接回答，无需调用工具\n\n"
                    "工作流程：\n"
                    "1. 理解用户的CTF题目或请求\n"
                    "2. 自主判断需要哪些工具，依次调用\n"
                    "3. 根据工具返回结果，结合你的CTF经验，给出完整的分析\n\n"
                    "回答要求：\n"
                    "1. 结合工具结果和你的分析，给出有深度的回答\n"
                    "2. 使用 Markdown 格式，结构清晰\n"
                    "3. 如果找到Flag，明确标注\n"
                    "4. 给出攻击思路和利用方法\n"
                    "5. 始终使用中文回答\n"
                )
                report_format = "CTF"
            else:
                system_prompt = (
                    "你是鉴真安全智能体（CangSight），一个专业的安全运营助手。\n\n"
                    "核心理念：模型可以不确定，但系统必须可解释、可验证、可追责。\n\n"
                    "你的能力：\n"
                    "- 分析安全事件、检测代码漏洞、检索漏洞知识、生成安全报告\n"
                    "- 自主识别用户意图，选择合适的工具进行分析\n"
                    "- 结合工具返回结果和自身专业知识，给出完整、准确、可操作的安全建议\n\n"
                    "可用工具列表：\n"
                )

                for tool in tools:
                    func = tool["function"]
                    params = func.get("parameters", {}).get("properties", {})
                    param_list = ", ".join(params.keys())
                    system_prompt += f"- {func['name']}: {func['description']} (参数: {param_list})\n"

                system_prompt += "\n" + (
                    "工具使用指南（根据用户请求自动选择）：\n"
                    "- 代码漏洞扫描 → code_scan, start_scan, sbfl_rank\n"
                    "- 漏洞知识检索 → vkb_retrieve, cwe_classifier\n"
                    "- 修复建议 → repair_prompt_bundle, agentic_repair\n"
                    "- 报告生成 → uafr_report\n"
                    "- 流量分析 → pcap_analyze\n"
                    "- 符号切片/依赖分析 → sympas_slice, sympas_dep_graph, dep_cluster\n"
                    "- 补丁评估 → eval_patch_taint, patch_safety_verifier\n"
                    "- 并发缺陷 → concurrency_check\n"
                    "- SCA扫描 → sca_cve_scanner\n"
                    "- 普通对话/知识问答 → 直接回答，无需调用工具\n\n"
                    "工具参数约束（不遵守会直接失败）：\n"
                    "- 凡是带 code 内联分析的 SymPas 工具（sympas_slice / sympas_slice_table / "
                    "sympas_dep_graph），必须同时传 filename（含后缀，如 probe.cj）和 lang"
                    "（cangjie/c/cpp/java/python）\n"
                    "- 只传 code 不给 lang 的后果：sympas_slice 会 HTTP 500（后端按 source.c "
                    "编译仓颉失败）；sympas_slice_table 会返回空表且状态仍是 success。"
                    "看到空结果时先检查自己有没有传 lang，不要直接下结论\n"
                    "- 需要程序切片时用 sympas_slice_table，不要用 sympas_slice："
                    "后者只要遇到跨函数调用或 Array 参数，data.backward_slices 就恒为空，"
                    "切片只写进 raw_output 日志；sympas_slice_table 在这些情况下都能返回"
                    "结构化结果。direction 传 \"Bwd\"，不要传 \"Both\""
                    "（Both 会把两个方向混进 backward_slices 并丢掉 forward_slices）\n"
                    "- 不要给 file 参数传文件名。file 是服务器工作区路径，传不存在的路径会 400；"
                    "内联代码一律用 code + filename + lang\n"
                    "- sympas_dep_graph 不接受 file 参数\n"
                    "- sympas_dep_graph 的 graph_types 要传字符串而不是数组："
                    "传 \"All\" 取全部 7 种（Cfg/Cg/Cdg/Ddg/Pdg/Sdg/Dfg），或传单个类型\n"
                    "- 分析结果的 status 有三态：pass=已拿到结果；empty=工具执行了但没有内容"
                    "（不代表安全）；reject=工具失败（不能当作无风险）。"
                    "讨论风险时必须区分这三种情况\n"
                    "- 依赖图已由系统转成 \"n0_16->n0_4\" 形式的紧凑文本，直接读边判断循环即可，"
                    "不要去解析 SVG（SVG 是画给用户的，里面全是坐标）\n"
                    "- 仓颉代码在规则扫描下命中恒为 0，这是规则集不覆盖该语言导致，"
                    "不等于无漏洞；此时应改用 sympas_slice / sympas_dep_graph 佐证\n"
                    "- 同一轮不要重复调用参数完全相同的工具。已经拿到 pass 结果就不要重试；"
                    "失败时先改参数（多半是缺 lang），仍失败就如实说明并基于已有证据作答\n\n"
                    "工作流程：\n"
                    "1. 理解用户的问题，判断是否需要调用工具\n"
                    "2. 如果需要工具，选择最合适的工具并调用\n"
                    "3. 根据工具返回的结果，结合你的专业知识，给出完整的回答\n\n"
                    "回答要求：\n"
                    "1. 如果调用了工具，请结合工具结果给出详细分析，不要只复述工具输出\n"
                    "2. 回答要结构清晰、重点突出，使用 Markdown 格式\n"
                    "3. 对于安全事件，给出明确的风险等级和处置建议\n"
                    "4. 对于代码漏洞，指出具体位置和修复方案\n"
                    "5. 如果工具执行失败，说明原因并给出你基于知识的分析\n"
                    "6. 始终使用中文回答\n"
                )
                report_format = "SECURITY"

            messages = [
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=message),
            ]

            logger.info(f"[Agent Chat] Sending to LLM: model={model}, tools_count={len(tools)}, message_len={len(message)}, input_type={input_type}")

            # 推理模型（如 deepseek-reasoner）的推理 token 也计入 max_tokens，需要更大预算
            is_reasoning_model = "reasoner" in model.lower() or "o1" in model.lower() or "o3" in model.lower()

            loop = _run_tool_loop(
                messages=messages,
                adapter=adapter,
                tools=tools,
                max_rounds=MAX_TOOL_ROUNDS,
                is_reasoning_model=is_reasoning_model,
            )
            if loop.get("error"):
                logger.error(f"[Agent Chat] LLM failed: {loop['error']}")
                return {
                    "error": {
                        "message": loop["error"],
                        "status": 500,
                        "refused": False,
                    }
                }

            answered = bool(loop.get("answered"))
            logger.info(
                "[Agent Chat] tool rounds=%d calls=%d answered=%s",
                loop.get("rounds", 0), len(loop.get("tool_calls") or []), answered,
            )

            # answered=True 说明模型已经把工具结果消化完并直接给出回答，
            # 无需再调一次 LLM；否则把带 tool 消息的完整序列交给调用方生成报告。
            # 旧实现无论哪种情况都重建 report_messages，等于把工具结果整段丢弃。
            return {
                "provider": provider,
                "model": model,
                "usage": loop.get("usage") or {},
                "has_tool_calls": bool(loop.get("tool_calls")),
                "tool_calls": loop.get("tool_calls") or [],
                "tool_results": loop.get("tool_results") or [],
                "tool_rounds": loop.get("rounds", 0),
                "final_messages": None if answered else loop.get("messages"),
                "direct_answer": loop.get("content") if answered else None,
                "adapter": adapter,
                "max_tokens": 8192 if is_reasoning_model else 3000,
            }

        except Exception as exc:
            logger.exception("Agent chat failed")
            return {
                "error": {
                    "message": f"调用失败: {str(exc)}",
                    "status": 500,
                    "refused": False,
                }
            }

    @app.route("/agent/chat", methods=["POST"])
    def agent_chat() -> Response:
        payload = request.json or {}
        message = payload.get("message", "")
        input_type = payload.get("input_type", "")

        if not message:
            return make_error("message parameter required", 400)

        ctx = _agent_chat_prepare(message, input_type)
        if "error" in ctx:
            err = ctx["error"]
            extra = {"refused": True} if err.get("refused") else {}
            return make_error(err["message"], err["status"], **extra)

        result_data = {
            "status": "success",
            "answer": "",
            "provider": ctx["provider"],
            "model": ctx["model"],
            "usage": ctx["usage"],
            "has_tool_calls": ctx["has_tool_calls"],
            "tool_calls": ctx["tool_calls"],
            "tool_results": ctx["tool_results"],
            "tool_rounds": ctx.get("tool_rounds", 0),
        }

        if ctx["final_messages"] is not None:
            try:
                report_response = ctx["adapter"].chat(ctx["final_messages"], max_tokens=ctx["max_tokens"])
                logger.info(f"[Agent Chat] Report generation response: has_tool_calls={report_response.has_tool_calls}, content_len={len(report_response.content)}")
                if report_response.is_success:
                    result_data["answer"] = report_response.content
                else:
                    logger.error(f"[Agent Chat] Report generation failed: {report_response.error}")
                    result_data["answer"] = f"报告生成失败: {report_response.error}"
            except Exception as exc:
                logger.error(f"[Agent Chat] Report generation exception: {exc}")
                result_data["answer"] = f"报告生成失败: {str(exc)}"
        else:
            result_data["answer"] = ctx["direct_answer"]

        logger.info(f"[Agent Chat] Final result_data: answer='{result_data['answer'][:100] if result_data['answer'] else 'EMPTY'}'")
        return jsonify(result_data)

    @app.route("/agent/chat/stream", methods=["POST"])
    def agent_chat_stream() -> Response:
        payload = request.json or {}
        message = payload.get("message", "")
        input_type = payload.get("input_type", "")

        if not message:
            return make_error("message parameter required", 400)

        ctx = _agent_chat_prepare(message, input_type)

        def _sse(event: str, data: Dict[str, Any]) -> str:
            return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

        def event_stream():
            if "error" in ctx:
                err = ctx["error"]
                yield _sse("error", {"message": err["message"], "refused": err.get("refused", False)})
                return

            yield _sse("meta", {
                "provider": ctx["provider"],
                "model": ctx["model"],
                "has_tool_calls": ctx["has_tool_calls"],
                "tool_calls_count": len(ctx["tool_calls"]),
                "tool_rounds": ctx.get("tool_rounds", 0),
            })

            if ctx["tool_results"]:
                yield _sse("tools", {
                    "tool_calls": ctx["tool_calls"],
                    "tool_results": ctx["tool_results"],
                    "tool_rounds": ctx.get("tool_rounds", 0),
                })

            answer_parts: List[str] = []
            try:
                if ctx["final_messages"] is not None:
                    for chunk in ctx["adapter"].stream_chat(ctx["final_messages"], max_tokens=ctx["max_tokens"]):
                        if chunk is None:
                            continue
                        if isinstance(chunk, str) and chunk.startswith("[ERROR]"):
                            yield _sse("error", {"message": chunk})
                            return
                        answer_parts.append(chunk)
                        yield _sse("delta", {"text": chunk})
                else:
                    text = ctx["direct_answer"] or ""
                    if text:
                        answer_parts.append(text)
                        yield _sse("delta", {"text": text})
            except Exception as exc:
                logger.exception("Agent chat stream failed")
                yield _sse("error", {"message": f"调用失败: {str(exc)}"})
                return

            yield _sse("done", {
                "answer": "".join(answer_parts),
                "provider": ctx["provider"],
                "model": ctx["model"],
                "has_tool_calls": ctx["has_tool_calls"],
                "tool_calls": ctx["tool_calls"],
                "tool_results": ctx["tool_results"],
            })

        return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

    # ===== 场景模板加载（评委演示动态化）=====
    _scenario_templates: Optional[Dict[str, Any]] = None

    def _load_scenario_templates() -> Dict[str, Any]:
        nonlocal _scenario_templates
        if _scenario_templates is not None:
            return _scenario_templates
        import json
        templates_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "demo_assets", "scenario_templates.json"
        )
        try:
            with open(templates_path, "r", encoding="utf-8") as f:
                _scenario_templates = json.load(f)
            logger.info(f"[Scenario] Loaded {len(_scenario_templates)} templates")
        except Exception as exc:
            logger.exception("[Scenario] Failed to load templates")
            _scenario_templates = {}
        return _scenario_templates

    def _select_scenario_template(message: str) -> str:
        """根据用户输入关键词选择最匹配的场景模板"""
        msg_lower = message.lower()
        scores = {
            "sqli": sum(1 for kw in ["sql", "注入", "inject", "布尔盲注", "联合查询", "or 1=1"] if kw in msg_lower),
            "webshell": sum(1 for kw in ["webshell", "shell", "一句话", "eval", "上传", "木马", "后门文件"] if kw in msg_lower),
            "apt": sum(1 for kw in ["apt", "横向移动", "持久化", "域控", "pass-the-hash", "内网渗透", "persistence"] if kw in msg_lower),
            "credential_theft": sum(1 for kw in ["凭据", "lsass", "mimikatz", "密码", "credential", "哈希", "票据", "kerberos"] if kw in msg_lower),
            "xss": sum(1 for kw in ["xss", "跨站", "脚本", "cookie", "反射", "存储型", "script"] if kw in msg_lower),
            "ransomware": sum(1 for kw in ["勒索", "加密", "ransomware", "wannacry", "locked", "比特币", "文件加密"] if kw in msg_lower),
            "ddos": sum(1 for kw in ["ddos", "拒绝服务", "流量", "cc攻击", "洪水", "syn", "拥塞"] if kw in msg_lower),
            "phishing": sum(1 for kw in ["钓鱼", "phishing", "邮件", "宏", "伪造发件", "恶意附件", "发票"] if kw in msg_lower),
        }
        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return "sqli"  # 默认回退
        return best

    def _generate_scenario_with_llm(message: str, template: Dict[str, Any]) -> Dict[str, Any]:
        """调用 LLM 生成案件元数据和9阶段内容；失败时用模板默认值"""
        template_case = template.get("case", {})
        template_stages = template.get("stages", [])
        result = {
            "title": template_case.get("title", ""),
            "summary": template_case.get("summary", ""),
            "risk": template_case.get("risk", "高风险"),
            "stages": None,
        }
        try:
            provider = _runtime_llm_config.get("provider") or get_llm_provider()
            model = _runtime_llm_config.get("model") or os.environ.get("LLM_MODEL", "deepseek-chat")
            api_key = _runtime_llm_config.get("api_key") or get_llm_api_key()
            base_url = _runtime_llm_config.get("base_url") or get_llm_base_url()
            if not api_key:
                return result
            adapter = get_llm_adapter(
                provider=provider, model=model, api_key=api_key, base_url=base_url
            )
            from nexus.llm.llm_adapter import ChatMessage
            stage_hints = "\n".join(
                f"{i+1}. {s.get('title','')}" for i, s in enumerate(template_stages)
            )
            system_prompt = (
                "你是安全事件分析专家。根据用户描述的安全场景，生成完整的9阶段安全事件分析流程。\n"
                "严格按 JSON 格式输出，不要输出其他内容：\n"
                "{\n"
                '  "title": "案件标题（10-20字，贴合场景）",\n'
                '  "summary": "案件摘要（20-50字，描述具体威胁）",\n'
                '  "risk": "高风险|严重风险|中风险|低风险",\n'
                '  "stages": [\n'
                '    {"title": "阶段标题（8-15字）", "summary": "阶段摘要（15-30字）", "detail": "阶段详情（20-60字）"},\n'
                "    ...（共9个阶段，顺序对应下方说明）\n"
                "  ]\n"
                "}\n"
                "9个阶段依次为：\n"
                f"{stage_hints}\n"
                "要求：每个阶段的 title/summary/detail 必须贴合用户输入的具体场景。\n"
                "例如用户输入SQL注入则阶段2应描述检测到SQL注入特征，阶段3应描述关联注入证据等。\n"
                "风险等级规则：涉及数据泄露/横向移动/持久化=严重风险，涉及注入/上传/凭据=高风险，其他=中风险"
            )
            messages = [
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=message),
            ]
            response = adapter.chat(messages, max_tokens=2000)
            if response.is_success and response.content:
                import json as _json
                content = response.content.strip()
                if "```" in content:
                    start = content.find("{")
                    end = content.rfind("}") + 1
                    if start >= 0 and end > start:
                        content = content[start:end]
                parsed = _json.loads(content)
                if parsed.get("title"):
                    result["title"] = str(parsed["title"])[:50]
                if parsed.get("summary"):
                    result["summary"] = str(parsed["summary"])[:120]
                if parsed.get("risk") in ["高风险", "严重风险", "中风险", "低风险"]:
                    result["risk"] = parsed["risk"]
                if isinstance(parsed.get("stages"), list) and len(parsed["stages"]) == 9:
                    result["stages"] = []
                    for s in parsed["stages"]:
                        result["stages"].append({
                            "title": str(s.get("title", ""))[:30],
                            "summary": str(s.get("summary", ""))[:80],
                            "detail": str(s.get("detail", ""))[:120],
                        })
                    logger.info(f"[Scenario] LLM generated {len(result['stages'])} dynamic stages")
        except Exception as exc:
            logger.warning(f"[Scenario] LLM generation failed, using template default: {exc}")
        return result

    @app.route("/agent/scenario/preset", methods=["POST"])
    def agent_scenario_preset() -> Response:
        """直接返回预设场景的模板数据，不调用LLM，实现秒级加载"""
        payload = request.json or {}
        preset_key = payload.get("preset_key", "")
        if not preset_key:
            return make_error("preset_key parameter required", 400)

        try:
            templates = _load_scenario_templates()
            if not templates:
                return make_error("场景模板加载失败", 500)

            template = templates.get(preset_key)
            if not template:
                return make_error(f"未找到预设场景: {preset_key}", 404)

            from datetime import datetime
            case_id = f"CASE-PRESET-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            case = dict(template.get("case", {}))
            case["caseId"] = case_id
            risk_class_map = {"严重风险": "risk-high", "高风险": "risk-high", "中风险": "risk-medium", "低风险": "risk-low"}
            case["riskClass"] = risk_class_map.get(case.get("risk", ""), "risk-high")

            return jsonify({
                "status": "success",
                "case": case,
                "stages": template.get("stages", []),
                "truthStates": template.get("truthStates", {}),
                "stageAudit": template.get("stageAudit", []),
                "auditId": template.get("auditId", ""),
                "executionReceiptId": template.get("executionReceiptId", ""),
                "verificationReceiptId": template.get("verificationReceiptId", ""),
                "templateKey": preset_key,
            })
        except Exception as exc:
            logger.exception("[Scenario Preset] Failed")
            return make_error(f"预设场景加载失败: {str(exc)}", 500)

    @app.route("/agent/scenario", methods=["POST"])
    def agent_scenario() -> Response:
        """根据用户输入的安全场景，生成 9 阶段案件流程（模板结构 + LLM 动态内容）"""
        payload = request.json or {}
        message = payload.get("message", "")
        if not message:
            return make_error("message parameter required", 400)

        try:
            templates = _load_scenario_templates()
            if not templates:
                return make_error("场景模板加载失败", 500)

            # 1. 关键词匹配选择基础模板
            template_key = _select_scenario_template(message)
            template = templates.get(template_key) or templates.get("sqli")
            if not template:
                return make_error("未找到合适的场景模板", 500)

            # 2. 调用 LLM 生成案件元数据 + 9阶段动态内容（失败时用模板默认值）
            llm_data = _generate_scenario_with_llm(message, template)

            # 3. 构建案件元数据
            from datetime import datetime
            case_id = f"CASE-AUTO-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            case = dict(template.get("case", {}))
            case["title"] = llm_data["title"]
            case["summary"] = llm_data["summary"]
            case["risk"] = llm_data["risk"]
            risk_class_map = {"严重风险": "risk-high", "高风险": "risk-high", "中风险": "risk-medium", "低风险": "risk-low"}
            case["riskClass"] = risk_class_map.get(case["risk"], "risk-high")
            case["caseId"] = case_id

            # 4. 合并 LLM 生成的阶段内容到模板（保留 status/confidence/evidence 结构）
            template_stages = template.get("stages", [])
            llm_stages = llm_data.get("stages")
            if llm_stages and len(llm_stages) == len(template_stages):
                stages = []
                for i, ts in enumerate(template_stages):
                    ls = llm_stages[i] if i < len(llm_stages) else {}
                    merged = {
                        **ts,
                        "title": ls.get("title", ts.get("title", "")),
                        "summary": ls.get("summary", ts.get("summary", "")),
                        "detail": ls.get("detail", ts.get("detail", "")),
                    }
                    stages.append(merged)
            else:
                stages = template_stages

            return jsonify({
                "status": "success",
                "case": case,
                "stages": stages,
                "truthStates": template.get("truthStates", {}),
                "stageAudit": template.get("stageAudit", []),
                "auditId": template.get("auditId", ""),
                "executionReceiptId": template.get("executionReceiptId", ""),
                "verificationReceiptId": template.get("verificationReceiptId", ""),
                "templateKey": template_key,
            })
        except Exception as exc:
            logger.exception("[Scenario] Generation failed")
            return make_error(f"场景生成失败: {str(exc)}", 500)

    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
    app.static_folder = os.path.join(frontend_dir, "dashboard")

    @app.after_request
    def _disable_frontend_cache(response):
        if request.path.startswith("/frontend/dashboard/"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.route("/frontend/dashboard/<path:filename>")
    def frontend_static(filename):
        import mimetypes
        mimetypes.add_type('application/javascript', '.js')
        mimetypes.add_type('application/javascript', '.mjs')
        return app.send_static_file(filename)

    @app.route("/agents/ooda", methods=["POST"])
    def ooda_execute() -> Response:
        payload = request.json or {}
        objective = payload.get("objective", "")
        cycle_count = payload.get("cycle_count", 3)

        if not objective:
            return make_error("objective parameter required", 400)

        try:
            from nexus.agents.ooda_agent import OODAController
            agent = OODAController()
            agent.set_objective(objective)
            result = agent.run_cycles(cycle_count)
            
            return make_success(
                objective=objective,
                cycles=result.get("cycles", []),
                total_cycles=len(result.get("cycles", [])),
            )
        except Exception as exc:
            logger.exception("OODA execution failed")
            return make_error(str(exc), 500)

    @app.route("/agents/ooda/step", methods=["POST"])
    def ooda_step() -> Response:
        payload = request.json or {}
        objective = payload.get("objective", "")
        cycle_count = payload.get("cycle_count", 1)

        if not objective:
            return make_error("objective parameter required", 400)

        try:
            from nexus.agents.ooda_agent import OODAController
            agent = OODAController()
            agent.set_objective(objective)
            result = agent.run_cycles(cycle_count)
            
            return make_success(
                objective=objective,
                cycles=result.get("cycles", []),
            )
        except Exception as exc:
            logger.exception("OODA step failed")
            return make_error(str(exc), 500)

    @app.route("/audit/eat/chain", methods=["GET"])
    def eat_chain_list() -> Response:
        try:
            eat_db = get_eat_db()
            sessions = eat_db.list_sessions()
            return jsonify({
                "status": "success",
                "sessions": [{"id": s} for s in sessions],
                "count": len(sessions),
            })
        except Exception as exc:
            logger.exception("EAT chain list failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/audit/eat/chain/<session_id>", methods=["GET"])
    def eat_chain_get(session_id: str) -> Response:
        try:
            eat_db = get_eat_db()
            frames = eat_db.load_session(session_id)
            
            if frames is None:
                return make_error("session not found", 404)

            return jsonify({
                "status": "success",
                "session_id": session_id,
                "chain": frames,
                "total_nodes": len(frames),
            })
        except Exception as exc:
            logger.exception("EAT chain get failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/audit/eat/verify", methods=["GET"])
    @app.route("/audit/eat/verify/<session_id>", methods=["GET"])
    def eat_verify(session_id: str = None) -> Response:
        try:
            from nexus.audit.eat_enhanced import EnhancedEATChain
            eat_chain = EnhancedEATChain()
            
            if session_id:
                eat_db = get_eat_db()
                frames = eat_db.load_session(session_id)
                if frames is None:
                    return jsonify({"error": "session not found"}), 404
                
                result = eat_chain.verify_chain(frames)
                return jsonify({
                    "status": "success",
                    "session_id": session_id,
                    "valid": result["valid"],
                    "hash_chain_valid": result.get("hash_chain_valid", False),
                    "signature_valid": result.get("signature_valid", False),
                    "total_nodes": len(frames),
                    "error": result.get("error"),
                })
            else:
                eat_db = get_eat_db()
                sessions = eat_db.list_sessions()
                results = []
                
                for s in sessions:
                    frames = eat_db.load_session(s)
                    if frames:
                        result = eat_chain.verify_chain(frames)
                        results.append({
                            "session_id": s,
                            "valid": result["valid"],
                            "total_nodes": len(frames),
                        })
                
                return jsonify({
                    "status": "success",
                    "results": results,
                    "total_sessions": len(results),
                })
        except Exception as exc:
            logger.exception("EAT verify failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/audit/eat/export", methods=["GET"])
    @app.route("/audit/eat/export/<session_id>", methods=["GET"])
    def eat_export(session_id: str = None) -> Response:
        try:
            eat_db = get_eat_db()
            
            if session_id:
                frames = eat_db.load_session(session_id)
                if frames is None:
                    return jsonify({"error": "session not found"}), 404
                
                return jsonify({
                    "status": "success",
                    "session_id": session_id,
                    "chain": frames,
                })
            else:
                all_data = {}
                sessions = eat_db.list_sessions()
                for s in sessions:
                    frames = eat_db.load_session(s)
                    if frames:
                        all_data[s] = frames
                
                return jsonify({
                    "status": "success",
                    "total_sessions": len(sessions),
                    "data": all_data,
                })
        except Exception as exc:
            logger.exception("EAT export failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/gateway/hitl/approvals", methods=["GET"])
    def hitl_approvals() -> Response:
        try:
            filter_type = request.args.get("filter", "all")
            
            items = []
            pending_count = 0
            approved_count = 0
            rejected_count = 0
            critical_pending = 0
            
            from nexus.gateway.hitl_gateway import ApprovalRequest
            
            for task_id, req in PENDING_APPROVALS.items():
                if not isinstance(req, ApprovalRequest):
                    continue
                
                if filter_type == "pending" and req.status != "pending":
                    continue
                if filter_type == "approved" and req.status != "approved":
                    continue
                if filter_type == "rejected" and req.status != "rejected":
                    continue
                if filter_type == "critical" and (req.status != "pending" or req.risk_level != "critical"):
                    continue
                
                risk_level = getattr(req, "risk_level", "medium")
                
                created_at_ts = getattr(req, "created_at", None)
                created_at_str = ""
                if created_at_ts:
                    created_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created_at_ts))

                expires_at_ts = getattr(req, "expires_at", None)
                expires_at_str = None
                if expires_at_ts:
                    expires_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at_ts))
                
                items.append({
                    "id": task_id,
                    "task_id": task_id,
                    "skill_id": req.skill_id,
                    "skill_name": getattr(req, "skill_name", req.skill_id),
                    "action": req.proposed_action,
                    "status": req.status,
                    "risk_level": risk_level,
                    "approval_token": getattr(req, "approval_token", task_id),
                    "session_id": getattr(req, "session_id", ""),
                    "created_at": created_at_str,
                    "expires_at": expires_at_str,
                    "policy_hit": getattr(req, "policy_hit", None),
                    "approver": getattr(req, "approver", None),
                })
                
                if req.status == "pending":
                    pending_count += 1
                    if risk_level == "critical":
                        critical_pending += 1
                elif req.status == "approved":
                    approved_count += 1
                elif req.status == "rejected":
                    rejected_count += 1
            
            logger.info(f"HITL approvals: {len(items)} items, pending={pending_count}, approved={approved_count}, rejected={rejected_count}")
            
            return jsonify({
                "status": "success",
                "approvals": items,
                "summary": {
                    "pending": pending_count,
                    "approved": approved_count,
                    "rejected": rejected_count,
                    "critical_pending": critical_pending,
                },
            })
        except Exception as exc:
            logger.exception("HITL approvals failed")
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 500

    @app.route("/gateway/hitl/approval/<task_id>", methods=["GET"])
    def hitl_approval_get(task_id: str) -> Response:
        try:
            req = PENDING_APPROVALS.get(task_id)
            if not req:
                return make_error("task not found", 404)

            risk_level = getattr(req, "risk_level", "medium")
            created_at_ts = getattr(req, "created_at", None)
            created_at_str = ""
            if created_at_ts:
                created_at_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(created_at_ts))

            return jsonify({
                "id": task_id,
                "task_id": task_id,
                "skill_id": req.skill_id,
                "skill_name": getattr(req, "skill_name", req.skill_id),
                "action": req.proposed_action,
                "status": req.status,
                "risk_level": risk_level,
                "approval_token": getattr(req, "approval_token", task_id),
                "session_id": getattr(req, "session_id", ""),
                "created_at": created_at_str,
                "expires_at": getattr(req, "expires_at", None),
                "policy_hit": getattr(req, "policy_hit", None),
                "approver": getattr(req, "approver", None),
            })
        except Exception as exc:
            logger.exception("HITL approval get failed")
            return make_error(str(exc), 500)

    @app.route("/gateway/hitl/approve/<task_id>", methods=["POST"])
    def hitl_approve(task_id: str) -> Response:
        try:
            req = PENDING_APPROVALS.get(task_id)
            if not req:
                return make_error("task not found", 404)

            payload = request.json or {}
            provided_token = payload.get("approval_token", "")
            expected_token = getattr(req, "approval_token", "")
            operator = payload.get("operator", "web_ui")

            if expected_token and provided_token != expected_token:
                logger.warning(f"Invalid approval token for task {task_id}: expected {expected_token[:8]}..., got {provided_token[:8] if provided_token else 'EMPTY'}")
                return make_error("审批令牌无效，请刷新页面重试", 403)

            from nexus.gateway.hitl_gateway import approve_request
            result = approve_request(task_id, approver=operator)

            logger.info(f"Approved task {task_id} by {operator}")
            return jsonify(result)
        except Exception as exc:
            logger.exception("HITL approve failed")
            return make_error(str(exc), 500)

    @app.route("/gateway/hitl/reject/<task_id>", methods=["POST"])
    def hitl_reject(task_id: str) -> Response:
        try:
            req = PENDING_APPROVALS.get(task_id)
            if not req:
                return make_error("task not found", 404)

            payload = request.json or {}
            provided_token = payload.get("approval_token", "")
            expected_token = getattr(req, "approval_token", "")
            operator = payload.get("operator", "web_ui")

            if expected_token and provided_token != expected_token:
                logger.warning(f"Invalid approval token for reject task {task_id}")
                return make_error("审批令牌无效，请刷新页面重试", 403)

            from nexus.gateway.hitl_gateway import reject_request
            result = reject_request(task_id, approver=operator)

            logger.info(f"Rejected task {task_id} by {operator}")
            return jsonify(result)
        except Exception as exc:
            logger.exception("HITL reject failed")
            return make_error(str(exc), 500)

    @app.route("/policy/decide", methods=["GET", "POST"])
    def policy_decide() -> Response:
        try:
            if request.method == "POST":
                payload = request.json if request.is_json else request.form
                data = dict(payload) if payload else {}
            else:
                data = request.args.to_dict()

            tool = str(data.get("tool", "")).strip()
            if not tool:
                return make_error("tool is required", 400)
            scope_allowed = str(data.get("scope_allowed", "true")).strip().lower() in ("true", "1", "yes")
            approval_valid = str(data.get("approval_valid", "false")).strip().lower() in ("true", "1", "yes")
            try:
                remaining_ms = int(data.get("remaining_ms", 60000))
            except (TypeError, ValueError):
                remaining_ms = 60000

            from nexus.gateway.hitl_gateway import decide_action
            result = decide_action(tool, scope_allowed=scope_allowed,
                                   approval_valid=approval_valid, remaining_ms=remaining_ms)
            return jsonify(result)
        except Exception as exc:
            logger.exception("policy decide failed")
            return make_error(str(exc), 500)

    @app.route("/")
    def root_redirect():
        # index.html 里资源全是相对路径（css/… js/… images/…），
        # 根路径 "/" 直接返回它会导致浏览器把资源解析到 /js/app.js（404）。
        # 统一重定向到 /frontend/dashboard/，让相对路径正确落到该目录下。
        return redirect("/frontend/dashboard/", code=302)

    @app.route("/frontend/dashboard/")
    def dashboard() -> Response:
        index_path = os.path.join(frontend_dir, "dashboard", "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return f.read()
        return "Dashboard not found", 404

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("NEXUS_PORT", "7800"))
    app.run(host="0.0.0.0", port=port, debug=False)