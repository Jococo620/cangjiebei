"""CangSight 超级智能体补充模块。"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
from typing import Any, Dict, List, Optional


class DigestChainSigner:
    """轻量级哈希链签名器，作为 EAT 缺省降级实现。"""

    def __init__(self, agent_id: str = "cangsight_agent") -> None:
        self.agent_id = agent_id
        self.prev_hash = "0" * 64

    def sign_frame(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(frame)
        payload.setdefault("agent_id", self.agent_id)
        payload.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        payload["prev_frame_hash"] = self.prev_hash
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        payload["frame_hash"] = digest
        self.prev_hash = digest
        return payload


class CoTTracer:
    """将思维链按假设、证据、研判结论组织并纳入签名链。"""

    def __init__(self, eat_signer: Optional[Any] = None) -> None:
        self.signer = eat_signer or DigestChainSigner()
        self.steps: List[Dict[str, Any]] = []

    def think(self, hypothesis: str, evidence: Dict[str, Any], conclusion: str) -> Dict[str, Any]:
        frame = {
            "type": "cot_step",
            "hypothesis": hypothesis,
            "evidence": evidence,
            "conclusion": conclusion,
        }
        if hasattr(self.signer, "sign_frame"):
            frame = self.signer.sign_frame(frame)
        self.steps.append(frame)
        return frame


async def _maybe_call(func: Any, *args: Any, **kwargs: Any) -> Any:
    result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


async def insider_threat_loop(agent: Any, alert: Dict[str, Any]) -> Dict[str, Any]:
    """挑战任务范例：多源观测、跨域研判、自动处置。"""
    if not callable(getattr(agent, "platform", None)):
        raise AttributeError("agent must provide platform(skill_id, payload)")
    if not callable(getattr(agent, "act_with_policy", None)):
        raise AttributeError("agent must provide act_with_policy(skill_id, payload)")

    cot = CoTTracer(getattr(agent, "eat", None))

    traffic = await _maybe_call(agent.platform, "traffic_anomaly", dict(alert))
    cot.think("流量异常疑似数据外泄", {"alert": alert, "traffic": traffic}, "需关联终端进程")

    proc = await _maybe_call(
        agent.platform,
        "endpoint_correlate",
        {"flow": alert, "traffic": traffic},
    )
    host = proc.get("host") or alert.get("host") or alert.get("host_id") or "unknown-host"
    cot.think("定位到可疑外联进程", proc, "回溯发起账号身份")

    ident = await _maybe_call(
        agent.platform,
        "identity_trace",
        {"pid": proc.get("pid") or proc.get("process_id"), "host": host},
    )
    cot.think("账号于非常规时段批量访问敏感库", ident, "判定内鬼行为，触发处置")

    edr_result = await _maybe_call(agent.act_with_policy, "edr_isolation", {"host": host})
    firewall_result = await _maybe_call(
        agent.act_with_policy,
        "firewall_block",
        {"ip": alert.get("dst_ip") or alert.get("dest_ip") or alert.get("src_ip") or ""},
    )

    return {
        "verdict": "insider_exfiltration",
        "cot_chain": cot.steps,
        "telemetry": {
            "traffic": traffic,
            "process": proc,
            "identity": ident,
        },
        "actions": {
            "edr_isolation": edr_result,
            "firewall_block": firewall_result,
        },
    }


def run_insider_threat_loop_sync(agent: Any, alert: Dict[str, Any]) -> Dict[str, Any]:
    """同步包装器，便于现有同步入口复用。"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(insider_threat_loop(agent, alert))
    raise RuntimeError("run_insider_threat_loop_sync must be called outside an active event loop")


__all__ = ["CoTTracer", "DigestChainSigner", "insider_threat_loop", "run_insider_threat_loop_sync"]