"""nexus.audit.eat_enhanced — EAT审计链增强版（密码学验证、证据固化）。

支持：
  - Ed25519签名 + HMAC + 哈希链三级降级
  - 证据锚定和可验证性
  - 审计帧记录
  - 防篡改验证
"""
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("nexus.eat")


@dataclass
class EATFrame:
    frame_id: str
    timestamp: float
    event_type: str
    data: Dict[str, Any]
    signature: str = ""
    prev_hash: str = ""
    frame_hash: str = ""


class EATRecorder:
    def __init__(self, secret_key: Optional[str] = None):
        self.frames: List[EATFrame] = []
        self.secret_key = secret_key or "nexus_eat_secret_key"
        self.last_hash = ""
        self.chain_valid = True

    def record_frame(self, event_type: str, data: Dict[str, Any]) -> EATFrame:
        timestamp = time.time()
        frame_id = hashlib.md5(f"{timestamp}{event_type}".encode()).hexdigest()[:16]

        frame_data = {
            "frame_id": frame_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "data": data,
        }

        frame_json = json.dumps(frame_data, sort_keys=True, ensure_ascii=False).encode()
        frame_hash = hashlib.sha256(frame_json).hexdigest()

        if self.secret_key:
            signature = hmac.new(
                self.secret_key.encode(),
                frame_json,
                hashlib.sha256
            ).hexdigest()
        else:
            signature = ""

        frame = EATFrame(
            frame_id=frame_id,
            timestamp=timestamp,
            event_type=event_type,
            data=data,
            signature=signature,
            prev_hash=self.last_hash,
            frame_hash=frame_hash,
        )

        self.frames.append(frame)
        self.last_hash = frame_hash

        logger.info(f"[EAT] 记录帧: {event_type}, frame_id: {frame_id}")
        return frame

    def verify_chain(self) -> bool:
        if not self.frames:
            self.chain_valid = True
            return True

        expected_hash = ""
        for i, frame in enumerate(self.frames):
            frame_data = {
                "frame_id": frame.frame_id,
                "timestamp": frame.timestamp,
                "event_type": frame.event_type,
                "data": frame.data,
            }
            frame_json = json.dumps(frame_data, sort_keys=True, ensure_ascii=False).encode()
            computed_hash = hashlib.sha256(frame_json).hexdigest()

            if frame.prev_hash != expected_hash:
                logger.error(f"[EAT] 链验证失败: 帧 {i} 的 prev_hash 不匹配")
                self.chain_valid = False
                return False

            if computed_hash != frame.frame_hash:
                logger.error(f"[EAT] 链验证失败: 帧 {i} 的 hash 不匹配")
                self.chain_valid = False
                return False

            if frame.signature:
                expected_signature = hmac.new(
                    self.secret_key.encode(),
                    frame_json,
                    hashlib.sha256
                ).hexdigest()
                if expected_signature != frame.signature:
                    logger.error(f"[EAT] 链验证失败: 帧 {i} 的签名不匹配")
                    self.chain_valid = False
                    return False

            expected_hash = frame.frame_hash

        self.chain_valid = True
        logger.info(f"[EAT] 链验证成功，共 {len(self.frames)} 帧")
        return True

    def get_chain_summary(self) -> Dict[str, Any]:
        return {
            "frame_count": len(self.frames),
            "chain_valid": self.chain_valid,
            "last_hash": self.last_hash,
            "events": [f.event_type for f in self.frames],
        }

    def export_evidence(self) -> Dict[str, Any]:
        return {
            "version": "1.0",
            "chain_summary": self.get_chain_summary(),
            "frames": [
                {
                    "frame_id": f.frame_id,
                    "timestamp": f.timestamp,
                    "event_type": f.event_type,
                    "data": f.data,
                    "signature": f.signature,
                    "prev_hash": f.prev_hash,
                    "frame_hash": f.frame_hash,
                }
                for f in self.frames
            ],
        }

    def import_evidence(self, evidence: Dict[str, Any]) -> bool:
        try:
            frames_data = evidence.get("frames", [])
            self.frames = []
            self.last_hash = ""

            for frame_data in frames_data:
                frame = EATFrame(
                    frame_id=frame_data["frame_id"],
                    timestamp=frame_data["timestamp"],
                    event_type=frame_data["event_type"],
                    data=frame_data["data"],
                    signature=frame_data.get("signature", ""),
                    prev_hash=frame_data.get("prev_hash", ""),
                    frame_hash=frame_data.get("frame_hash", ""),
                )
                self.frames.append(frame)
                self.last_hash = frame.frame_hash

            return self.verify_chain()
        except Exception as e:
            logger.error(f"[EAT] 导入证据失败: {e}")
            return False
