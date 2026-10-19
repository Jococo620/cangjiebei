import json
import os
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("nexus.runtime.checkpointing")


class CheckpointManager:
    def __init__(self, session_id: str, checkpoint_dir: str = ".nexus/checkpoints"):
        self.session_id = session_id
        self.checkpoint_dir = os.path.abspath(checkpoint_dir)
        os.makedirs(self.checkpoint_dir, exist_ok=True)

    def _checkpoint_path(self, cycle: int) -> str:
        return os.path.join(self.checkpoint_dir, f"{self.session_id}_cycle_{cycle}.json")

    def save(self, cycle: int, state: Dict[str, Any], eat_chain: list = None) -> str:
        checkpoint = {
            "session_id": self.session_id,
            "cycle": cycle,
            "state": state,
            "eat_chain": eat_chain or [],
        }
        path = self._checkpoint_path(cycle)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, ensure_ascii=False, indent=2)
        return path

    def load(self, cycle: int) -> Optional[Dict[str, Any]]:
        path = self._checkpoint_path(cycle)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to load checkpoint {cycle}: {exc}")
            return None

    def load_latest(self) -> Optional[Dict[str, Any]]:
        latest_cycle = -1
        latest_path = None

        for fname in os.listdir(self.checkpoint_dir):
            if fname.startswith(f"{self.session_id}_cycle_") and fname.endswith(".json"):
                try:
                    cycle = int(fname.replace(f"{self.session_id}_cycle_", "").replace(".json", ""))
                    if cycle > latest_cycle:
                        latest_cycle = cycle
                        latest_path = os.path.join(self.checkpoint_dir, fname)
                except ValueError:
                    continue

        if latest_path and os.path.exists(latest_path):
            try:
                with open(latest_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logger.warning(f"Failed to load latest checkpoint: {exc}")

        return None


__all__ = ["CheckpointManager"]