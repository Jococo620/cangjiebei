from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any, Dict

logger = logging.getLogger("nexus.hooks")


class PreToolUseGuard:
    def __init__(self) -> None:
        self._blocked_skills = {"delete_all", "shutdown_system", "format_disk"}

    def validate(self, skill_id: str, params: Dict[str, Any], context: Dict[str, Any]) -> tuple:
        if skill_id in self._blocked_skills:
            return False, f"Skill {skill_id!r} is permanently blocked by safety policy"

        if "danger_level" in params:
            danger = params["danger_level"]
            if danger in {"critical", "high"}:
                if not context.get("hitl_approved"):
                    return False, f"High-risk skill {skill_id!r} requires HITL approval"

        return True, ""


class PostToolUseObserver:
    def __init__(self, project_hash: str = "default") -> None:
        self._project_hash = project_hash
        self._recorded_events: Dict[str, Dict[str, Any]] = {}

    def record(
        self,
        skill_id: str,
        params: Dict[str, Any],
        result: Dict[str, Any],
        agent_id: str = "",
        duration_ms: int = 0,
        session_id: str = "",
        event_id: str = "",
        params_hash: str = "",
        eat_frame_id: Any = None,
    ) -> None:
        event = {
            "event_id": event_id or uuid.uuid4().hex,
            "event_type": "PostToolUse",
            "skill_id": skill_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "duration_ms": duration_ms,
            "params_hash": params_hash,
            "eat_frame_id": eat_frame_id,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "result_summary": {
                "status": result.get("status"),
                "has_findings": bool(result.get("findings") or result.get("data")),
                "error_hint": result.get("message") if result.get("status") != "success" else None,
            },
        }
        self._recorded_events[event["event_id"]] = event
        logger.debug("PostToolUse recorded: %s", event["event_id"])

    def get_events(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._recorded_events)


__all__ = ["PreToolUseGuard", "PostToolUseObserver"]