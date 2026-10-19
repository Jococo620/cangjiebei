import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from queue import Queue

logger = logging.getLogger("nexus.gateway.hitl")

PENDING_APPROVALS: Dict[str, "ApprovalRequest"] = {}
_APPROVAL_LOCK = threading.Lock()
APPROVAL_HISTORY: List[Dict[str, Any]] = []

SAFETY_POLICIES = {
    "high_risk": {
        "skills": ["agentic_repair", "edr_isolation", "firewall_block"],
        "required_approval": "manual",
        "description": "高危操作需人工审批",
    },
    "medium_risk": {
        "skills": ["sympas-hv", "generate_mr", "eval_patch_taint"],
        "required_approval": "auto",
        "description": "中危操作可自动审批",
    },
    "low_risk": {
        "skills": ["code_scan", "vkb_retrieve", "sympas_slice"],
        "required_approval": "skip",
        "description": "低危操作无需审批",
    },
}


@dataclass
class ApprovalRequest:
    task_id: str
    skill_id: str
    proposed_action: Dict[str, Any]
    approval_token: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    status: str = "pending"
    approved: bool = False
    channel: Queue = field(default_factory=Queue)
    expires_at: Optional[float] = None
    policy_hit: Optional[str] = None
    risk_level: str = "medium"
    approver: Optional[str] = None
    approved_at: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    skill_name: Optional[str] = None
    session_id: Optional[str] = None

    def wait(self, timeout_sec: float) -> bool:
        try:
            result = self.channel.get(timeout=timeout_sec)
            return bool(result)
        except Exception:
            return False


def get_risk_level(skill_id: str) -> str:
    for level, policy in SAFETY_POLICIES.items():
        if skill_id in policy["skills"]:
            return level
    return "medium"


def check_policy(skill_id: str) -> Dict[str, Any]:
    for level, policy in SAFETY_POLICIES.items():
        if skill_id in policy["skills"]:
            return {"risk_level": level, "policy": policy}
    return {"risk_level": "medium", "policy": SAFETY_POLICIES["medium_risk"]}


# —— 策略决策核 ——
# 由仓颉引擎（cangjie_engine/src/main.cj 的 decide）承担处置放行/风险分级裁决，
# 本文件内的 _python_decide 为等价镜像，供仓颉引擎不可用时回退。
# 三态 Verdict：
#   ALLOW                   放行（低危/中危，或已审批的高危）
#   DENY|<reason>           拒绝（预算耗尽 / 越界 / 未知工具）
#   NEED_APPROVAL|<reason>  需要人工审批（致命动作 / 未审批的高危）

_CRITICAL_TOOLS = {"safe_firewall_ban", "edr_client.micro_isolate"}
_HIGH_RISK_TOOLS = {"agentic_repair", "plan_case_reproduce", "edr_isolation", "firewall_block"}
_MEDIUM_RISK_TOOLS = {
    "sympas_dynamic_slice", "generate_mr", "eval_patch_taint", "reproduce_fault",
    "plan_quality_gate", "patch_safety_verifier", "skill_doc_generator", "four_layer_demo",
}
_LOW_RISK_TOOLS = {
    "code_scan", "sympas_slice", "sympas_slice_table", "cwe_classifier", "taint_path_explainer",
    "sbfl_rank", "reachability_query", "vkb_retrieve", "ast_symbol_extractor", "sympas-hv",
    "sca_cve_scanner", "dep_cluster", "sympas_dep_graph", "uafr_report", "start_scan",
    "sarif_textual_export", "slice_diff", "repair_prompt_bundle", "agent_context",
    "traffic_hunt.pcap_analyze", "ticket_im.notify_dispatch",
}


def _python_decide(tool: str, scope_allowed: bool, approval_valid: bool, remaining_ms: int) -> str:
    if remaining_ms <= 0:
        return "DENY|BUDGET_EXHAUSTED"
    if not scope_allowed:
        return "DENY|OUT_OF_SCOPE"
    if tool in _CRITICAL_TOOLS:
        return "NEED_APPROVAL|CRITICAL_ACTION"
    if tool in _HIGH_RISK_TOOLS:
        return "ALLOW" if approval_valid else "NEED_APPROVAL|HIGH_RISK_REVIEW"
    if tool in _MEDIUM_RISK_TOOLS or tool in _LOW_RISK_TOOLS:
        return "ALLOW"
    return "DENY|UNKNOWN_TOOL"


def decide_action(tool: str, scope_allowed: bool = True, approval_valid: bool = False,
                  remaining_ms: int = 60_000) -> Dict[str, Any]:
    """三态裁决，优先仓颉引擎，回退 Python 镜像。"""
    verdict_text = None
    source = "python_fallback"
    try:
        from nexus.adapters.cangjie_engine_client import get_cangjie_engine
        res = get_cangjie_engine().decide(tool, scope_allowed, approval_valid, remaining_ms)
        if res.get("available") and res.get("verdict"):
            verdict_text = res.get("raw") or res["verdict"]
            source = "cangjie"
    except Exception as exc:  # noqa: BLE001 - 引擎异常不阻断决策
        logger.warning("cangjie decide unavailable, fallback to python: %s", exc)

    if verdict_text is None:
        verdict_text = _python_decide(tool, scope_allowed, approval_valid, remaining_ms)

    verdict, sep, reason = verdict_text.partition("|")
    return {
        "tool": tool,
        "verdict": verdict,
        "reason": reason if sep else None,
        "source": source,
        "scope_allowed": scope_allowed,
        "approval_valid": approval_valid,
        "remaining_ms": remaining_ms,
        "raw": verdict_text,
    }


def create_approval_request(task_id: str, skill_id: str, action_details: Dict[str, Any]) -> ApprovalRequest:
    policy_result = check_policy(skill_id)
    risk_level = policy_result["risk_level"]

    with _APPROVAL_LOCK:
        req = ApprovalRequest(
            task_id=task_id,
            skill_id=skill_id,
            proposed_action=action_details,
            expires_at=time.time() + action_details.get("timeout_sec", 120),
            policy_hit=policy_result["policy"].get("description"),
            risk_level=risk_level,
        )
        PENDING_APPROVALS[task_id] = req
        logger.info(f"Created approval request: {task_id}, risk_level: {risk_level}")
        return req


def resolve_approval(task_id: str, approved: bool, approver: str = "system") -> bool:
    with _APPROVAL_LOCK:
        req = PENDING_APPROVALS.get(task_id)
        if not req:
            return False
        req.approved = approved
        req.status = "approved" if approved else "rejected"
        req.approver = approver
        req.approved_at = time.time()
        req.channel.put(approved)

        APPROVAL_HISTORY.append({
            "task_id": task_id,
            "skill_id": req.skill_id,
            "approved": approved,
            "status": req.status,
            "risk_level": req.risk_level,
            "approver": approver,
            "created_at": req.created_at,
            "approved_at": req.approved_at,
        })

        logger.info(f"Approval resolved: {task_id}, approved: {approved}, approver: {approver}")
        return True


def wait_for_human_approval(task_id: str, skill_id: str, action_details: Dict[str, Any], timeout_sec: int = 120) -> bool:
    policy_result = check_policy(skill_id)
    required_approval = policy_result["policy"]["required_approval"]

    if required_approval == "skip":
        logger.info(f"Skill {skill_id} is low risk, skipping approval")
        return True

    if required_approval == "auto":
        logger.info(f"Skill {skill_id} is medium risk, auto-approving")
        return True

    with _APPROVAL_LOCK:
        existing = PENDING_APPROVALS.get(task_id)
        if not existing:
            create_approval_request(task_id, skill_id, action_details)

    req = PENDING_APPROVALS.get(task_id)
    if not req:
        logger.warning(f"Approval request {task_id} not found, auto-approving")
        return True

    result = req.wait(timeout_sec)

    if not result:
        with _APPROVAL_LOCK:
            if task_id in PENDING_APPROVALS:
                PENDING_APPROVALS[task_id].status = "timeout"
                APPROVAL_HISTORY.append({
                    "task_id": task_id,
                    "skill_id": skill_id,
                    "approved": False,
                    "status": "timeout",
                    "risk_level": req.risk_level,
                    "approver": "timeout",
                    "created_at": req.created_at,
                    "approved_at": None,
                })

    return result


def get_pending_approvals() -> List[Dict[str, Any]]:
    with _APPROVAL_LOCK:
        return [
            {
                "task_id": req.task_id,
                "skill_id": req.skill_id,
                "status": req.status,
                "risk_level": req.risk_level,
                "approval_token": req.approval_token,
                "created_at": req.created_at,
                "expires_at": req.expires_at,
                "proposed_action": req.proposed_action,
            }
            for req in PENDING_APPROVALS.values()
            if req.status == "pending"
        ]


def get_approval_history() -> List[Dict[str, Any]]:
    return APPROVAL_HISTORY.copy()


def get_approval_summary() -> Dict[str, Any]:
    pending = len([r for r in PENDING_APPROVALS.values() if r.status == "pending"])
    approved = sum(1 for h in APPROVAL_HISTORY if h["approved"])
    rejected = sum(1 for h in APPROVAL_HISTORY if not h["approved"] and h["status"] != "timeout")
    timeout = sum(1 for h in APPROVAL_HISTORY if h["status"] == "timeout")

    return {
        "pending": pending,
        "approved": approved,
        "rejected": rejected,
        "timeout": timeout,
        "total": len(APPROVAL_HISTORY),
    }


def approve_request(task_id: str, approver: str = "web_ui") -> Dict[str, Any]:
    result = resolve_approval(task_id, approved=True, approver=approver)
    if result:
        req = PENDING_APPROVALS.get(task_id)
        return {
            "success": True,
            "task_id": task_id,
            "status": req.status if req else "approved",
            "message": "审批已通过",
        }
    return {
        "success": False,
        "task_id": task_id,
        "message": "审批请求不存在或已处理",
    }


def reject_request(task_id: str, approver: str = "web_ui") -> Dict[str, Any]:
    result = resolve_approval(task_id, approved=False, approver=approver)
    if result:
        req = PENDING_APPROVALS.get(task_id)
        return {
            "success": True,
            "task_id": task_id,
            "status": req.status if req else "rejected",
            "message": "审批已拒绝",
        }
    return {
        "success": False,
        "task_id": task_id,
        "message": "审批请求不存在或已处理",
    }


__all__ = [
    "PENDING_APPROVALS", "ApprovalRequest",
    "create_approval_request", "resolve_approval", "wait_for_human_approval",
    "get_pending_approvals", "get_approval_history", "get_approval_summary",
    "check_policy", "get_risk_level",
    "approve_request", "reject_request",
    "decide_action",
]
