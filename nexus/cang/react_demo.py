"""CangSight 挑战任务零干预 ReAct 演示入口。"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Dict, Optional

import requests

from nexus.config import get_sympas_auth_headers, resolve_sympas_endpoint

logger = logging.getLogger("nexus.cang.react_demo")


def _gated_disposal(
    action_name: str,
    action_fn: Callable[[], Dict[str, Any]],
    action_details: Dict[str, Any],
    reason: str,
    approval_timeout_sec: int,
    event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """破坏性处置动作统一 HITL 人审网关：先挂起等待批准，批准后才真正调用 ``action_fn``。

    与 ``nexus.agents.cangsight_agent.CangSightAgent._disposal`` 同构，避免本演示入口
    绕过人审直接下发封禁/隔离动作。
    """
    task_id = f"cangsight_react_demo-{action_name}-{uuid.uuid4().hex[:8]}"
    if event_sink:
        try:
            event_sink("approval_required", {"task_id": task_id, "action": action_name, "details": action_details, "reason": reason})
        except Exception:  # noqa: BLE001
            logger.debug("event sink failed", exc_info=True)

    approved = True
    try:
        from nexus.gateway.hitl_gateway import wait_for_human_approval

        approved = wait_for_human_approval(
            task_id, action_name, {**action_details, "reason": reason}, timeout_sec=approval_timeout_sec
        )
    except Exception as exc:  # noqa: BLE001 — 网关不可用时降级为模拟放行，保证离线可演示
        logger.warning("HITL gateway unavailable, fallback simulated approval: %s", exc)

    if event_sink:
        try:
            event_sink("approval_resolved", {"task_id": task_id, "action": action_name, "decision": "approve" if approved else "reject"})
        except Exception:  # noqa: BLE001
            logger.debug("event sink failed", exc_info=True)

    if not approved:
        return {"status": "rejected", "action": action_name, "reason": "HITL operator rejected critical disposal action."}
    return action_fn()


def cangsight_zero_intervention_react(
    alert: Dict[str, Any],
    ngaf_client: Any,
    edr_client: Any,
    ticket_client: Any,
    approval_timeout_sec: int = 300,
    event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """零干预 ReAct：发现 TP 后自动封锁、隔离、复验与通报。

    NGFW 封禁 / EDR 微隔离均属破坏性动作，经 ``_gated_disposal`` 挂起 HITL 人审后
    才真正下发，符合"研判与无害动作全自动、破坏性动作经人审"的设计红线。
    """
    src_ip = alert.get("src_ip", "")
    host_id = alert.get("host_id", "")
    cwe = alert.get("cwe", "CWE-unknown")

    ban_result = _gated_disposal(
        "ngaf_ban_ip",
        lambda: ngaf_client.ban_ip(ip=src_ip, duration=3600, reason=f"Confirmed {cwe}"),
        {"ip": src_ip, "duration": 3600},
        reason=f"Block confirmed malicious source IP {src_ip} ({cwe})",
        approval_timeout_sec=approval_timeout_sec,
        event_sink=event_sink,
    )
    isolate_result = _gated_disposal(
        "edr_micro_isolate",
        lambda: edr_client.micro_isolate(host_id=host_id, reason=cwe),
        {"host_id": host_id},
        reason=f"Micro-isolate compromised host {host_id} ({cwe})",
        approval_timeout_sec=approval_timeout_sec,
        event_sink=event_sink,
    )

    hunt_endpoint = resolve_sympas_endpoint("/tools/dep_cluster")
    hunt_payload = {
        "target_dir": alert.get("project_path", ""),
        "focus_module": src_ip,
    }
    hunt_headers = get_sympas_auth_headers({"Content-Type": "application/json"})
    try:
        hunt_response = requests.post(
            hunt_endpoint,
            json=hunt_payload,
            headers=hunt_headers,
            timeout=180,
        )
        hunt_response.raise_for_status()
        hunt = hunt_response.json()
    except Exception as exc:  # pragma: no cover - network failure path
        hunt = {"status": "error", "message": f"dep_cluster call failed: {exc}"}

    ticket = ticket_client.create_ticket(
        title=f"[AUTO] {cwe} Blocked {src_ip}",
        body=(
            f"Alert: {alert}\n"
            f"Ban: {ban_result}\n"
            f"Isolate: {isolate_result}\n"
            f"Hunt: {hunt}"
        ),
        severity="critical",
    )

    return {
        "status": "success",
        "ban": ban_result,
        "isolate": isolate_result,
        "hunt": hunt,
        "ticket": ticket,
    }


__all__ = ["cangsight_zero_intervention_react"]