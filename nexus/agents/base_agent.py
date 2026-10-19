from __future__ import annotations

import abc
import logging
import time
import uuid
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

from nexus.runtime.checkpointing import CheckpointManager

if TYPE_CHECKING:
    from nexus.core.plugin_registry import NexusPluginRegistry

logger = logging.getLogger("nexus.agents.base")


class BaseAgent(abc.ABC):
    def __init__(
        self,
        agent_id: str,
        role: str,
        system_prompt: str,
        registry: "NexusPluginRegistry",
        policy: Optional[Dict[str, Any]] = None,
        event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.system_prompt = system_prompt
        self.registry = registry
        self.policy = policy or {}
        self.session_id = self.policy.get("session_id", uuid.uuid4().hex[:12])
        self.max_cycles = int(self.policy.get("max_cycles", 10))
        self.event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = (
            event_sink if callable(event_sink) else None
        )
        self.checkpoints = CheckpointManager(
            self.session_id,
            self.policy.get("checkpoint_dir", ".nexus/checkpoints"),
        )
        self.recorder = self._init_recorder()
        self.context: Dict[str, Any] = {}

    def _init_recorder(self) -> Any:
        try:
            from nexus.integrations.ecc.eat_recorder import EATRecorder

            return EATRecorder(
                session_id=self.session_id,
                agent_id=self.agent_id,
                project_hash=self.policy.get("project_hash", "default"),
            )
        except Exception as exc:
            logger.warning("EATRecorder unavailable, audit chain disabled: %s", exc)
            return None

    @abc.abstractmethod
    def run_mission(self, objective: str, target: str) -> Dict[str, Any]:
        raise NotImplementedError

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self.event_sink:
            return
        try:
            self.event_sink(event_type, payload)
        except Exception:
            logger.debug("event sink unavailable", exc_info=True)

    def _skill_context(self, eat_frame_id: str = "") -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "event_sink": self.event_sink,
            "eat_frame_id": eat_frame_id,
        }

    def call_skill(self, skill_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.time()
        result = self.registry.execute_skill(skill_id, params, context=self._skill_context())
        duration_ms = int((time.time() - t0) * 1000)
        if self.recorder is not None:
            try:
                self.recorder.record(
                    skill_id=skill_id,
                    status=str(result.get("status", "error")),
                    result=result,
                    duration_ms=duration_ms,
                )
            except Exception:
                logger.debug("EAT record failed", exc_info=True)
        return result

    def export_audit_manifest(self) -> Dict[str, Any]:
        if self.recorder is None:
            return {"frames": 0, "merkle_root": "0" * 64, "sig_alg": "none"}
        return self.recorder.export_manifest()


__all__ = ["BaseAgent"]