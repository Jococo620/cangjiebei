from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import pathlib
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nexus.ecc.eat")

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_GENESIS = "0" * 64


@dataclass
class EATFrame:
    seq: int
    timestamp: str
    phase: str
    action: str
    result: Dict[str, Any]
    danger_level: str
    signature_level: str
    prev_hash: str
    this_hash: str = ""
    signature: str = ""

    def content(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("this_hash", None)
        data.pop("signature", None)
        return data

    def compute_hash(self) -> str:
        return compute_frame_hash(self.prev_hash, self.content())


def _now_ts() -> str:
    return time.strftime(_TS_FMT, time.gmtime())


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def select_signature_level(
    danger_level: str,
    hsm_available: bool = False,
    ed25519_available: bool = True,
    hmac_available: bool = True,
) -> str:
    level = str(danger_level or "").strip().lower()
    if level == "critical" and hsm_available:
        return "L1"
    if level in {"critical", "high"} and ed25519_available:
        return "L2"
    if hmac_available or level in {"low", "medium"}:
        return "L3"
    return "L3"


def compute_frame_hash(prev_hash: str, frame_content: Dict[str, Any]) -> str:
    prev = str(prev_hash or _GENESIS)
    combined = prev.encode("utf-8") + b":" + _canonical(dict(frame_content or {}))
    return hashlib.sha256(combined).hexdigest()


def _default_eat_dir(project_hash: str) -> pathlib.Path:
    env_dir = os.environ.get("NEXUS_EAT_DIR", "").strip()
    if env_dir:
        base = pathlib.Path(env_dir).expanduser()
    else:
        xdg = os.environ.get("XDG_DATA_HOME", "").strip()
        root = pathlib.Path(xdg) if xdg else pathlib.Path.home() / ".local" / "share"
        base = root / "nexus-homunculus" / "projects" / project_hash
    base.mkdir(parents=True, exist_ok=True)
    return base


def _load_ed25519_signer() -> Optional[Tuple[Any, str]]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except Exception:
        return None

    pem = os.environ.get("NEXUS_EAT_PRIVATE_KEY", "").strip()
    try:
        if pem:
            key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        else:
            key = Ed25519PrivateKey.generate()
        pub_hex = (
            key.public_key()
            .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            .hex()
        )
        return key, pub_hex
    except Exception as exc:
        logger.warning("[EAT] ed25519 signer init failed: %s", exc)
        return None


class EATRecorder:
    def __init__(
        self,
        session_id: str = "",
        agent_id: str = "nexus_agent",
        project_hash: str = "default",
        path: Optional[str] = None,
    ) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        if path:
            self.chain_path = pathlib.Path(path).expanduser()
            self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.chain_path = _default_eat_dir(project_hash) / "eat_chain.jsonl"
        self._seq, self._last_hash = self._load_tail()

        self._ed = _load_ed25519_signer()
        self._hmac_key = os.environ.get("NEXUS_EAT_HMAC_KEY", "").strip().encode("utf-8") or None
        if self._ed is not None:
            self._sig_alg = "ed25519"
        elif self._hmac_key:
            self._sig_alg = "hmac-sha256"
        else:
            self._sig_alg = "none"

    def _load_tail(self) -> Tuple[int, str]:
        try:
            lines = [l for l in self.chain_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return 0, _GENESIS
        if not lines:
            return 0, _GENESIS
        try:
            last = json.loads(lines[-1])
            return int(last.get("seq", len(lines) - 1)) + 1, str(last.get("this_hash", _GENESIS))
        except Exception:
            return len(lines), _GENESIS

    def _sign(self, digest_hex: str) -> str:
        if self._sig_alg == "ed25519" and self._ed is not None:
            key = self._ed[0]
            return key.sign(bytes.fromhex(digest_hex)).hex()
        if self._sig_alg == "hmac-sha256" and self._hmac_key:
            return hmac.new(self._hmac_key, bytes.fromhex(digest_hex), hashlib.sha256).hexdigest()
        return ""

    def record(
        self,
        skill_id: str,
        status: str = "ok",
        params_hash: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        duration_ms: int = 0,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result_digest = ""
        if result is not None:
            summary = {
                "status": result.get("status"),
                "has_findings": bool(result.get("findings") or result.get("data")),
                "message": result.get("message"),
            }
            result_digest = _sha256_hex(_canonical(summary))

        body = {
            "frame_id": uuid.uuid4().hex,
            "seq": self._seq,
            "prev_hash": self._last_hash,
            "ts": _now_ts(),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "skill_id": skill_id,
            "status": status,
            "duration_ms": int(duration_ms),
            "params_hash": params_hash or "",
            "result_digest": result_digest,
            "extra": extra or {},
        }
        this_hash = _sha256_hex(_canonical(body))
        frame = dict(body)
        frame["this_hash"] = this_hash
        frame["sig_alg"] = self._sig_alg
        frame["signature"] = self._sign(this_hash)
        if self._sig_alg == "ed25519" and self._ed is not None:
            frame["pubkey"] = self._ed[1]

        try:
            with open(self.chain_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(frame, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("[EAT] failed to append frame: %s", exc)

        self._seq += 1
        self._last_hash = this_hash
        return frame

    def merkle_root(self) -> str:
        return compute_merkle_root(self._read_leaves())

    def _read_leaves(self) -> List[str]:
        try:
            lines = [l for l in self.chain_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return []
        leaves: List[str] = []
        for line in lines:
            try:
                leaves.append(str(json.loads(line)["this_hash"]))
            except Exception:
                continue
        return leaves

    def export_manifest(self) -> Dict[str, Any]:
        leaves = self._read_leaves()
        manifest = {
            "chain_path": str(self.chain_path),
            "frames": len(leaves),
            "merkle_root": compute_merkle_root(leaves),
            "sig_alg": self._sig_alg,
            "ts": _now_ts(),
        }
        if self._sig_alg == "ed25519" and self._ed is not None:
            manifest["pubkey"] = self._ed[1]
        return manifest

    def prove_inclusion(self, index: int) -> Dict[str, Any]:
        leaves = self._read_leaves()
        if not leaves or index < 0 or index >= len(leaves):
            return {"ok": False, "reason": "index out of range", "frames": len(leaves)}
        proof = inclusion_proof(leaves, index)
        root = compute_merkle_root(leaves)
        return {
            "ok": verify_inclusion(leaves[index], proof, root),
            "index": index,
            "leaf": leaves[index],
            "proof": proof,
            "merkle_root": root,
            "frames": len(leaves),
        }

    def frame_at(self, index: int) -> Optional[Dict[str, Any]]:
        try:
            lines = [l for l in self.chain_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return None
        if index < 0 or index >= len(lines):
            return None
        try:
            return json.loads(lines[index])
        except Exception:
            return None


def compute_merkle_root(leaves: List[str]) -> str:
    if not leaves:
        return _GENESIS
    level = [bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest() for h in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def _leaf_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest()


def inclusion_proof(leaves: List[str], index: int) -> List[Tuple[str, str]]:
    if not leaves or index < 0 or index >= len(leaves):
        return []
    level = [_leaf_to_bytes(h) for h in leaves]
    idx = index
    path: List[Tuple[str, str]] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:
            sibling, side = level[idx + 1], "R"
        else:
            sibling, side = level[idx - 1], "L"
        path.append((sibling.hex(), side))
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
        idx //= 2
    return path


def verify_inclusion(leaf_hex: str, proof: List[Tuple[str, str]], root_hex: str) -> bool:
    node = _leaf_to_bytes(leaf_hex)
    for sibling_hex, side in proof:
        sibling = bytes.fromhex(sibling_hex)
        if side == "L":
            node = hashlib.sha256(sibling + node).digest()
        else:
            node = hashlib.sha256(node + sibling).digest()
    return node.hex() == root_hex


def verify_chain(path: str, pubkey_hex: Optional[str] = None) -> Dict[str, Any]:
    p = pathlib.Path(path).expanduser()
    errors: List[str] = []
    try:
        lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError as exc:
        return {"ok": False, "frames": 0, "errors": [f"cannot read: {exc}"], "merkle_root": _GENESIS}

    prev = _GENESIS
    leaves: List[str] = []
    for idx, line in enumerate(lines):
        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"frame {idx}: invalid JSON")
            continue

        sig = frame.pop("signature", "")
        sig_alg = frame.pop("sig_alg", "none")
        stored_hash = frame.pop("this_hash", "")
        recomputed = _sha256_hex(_canonical(frame))
        if recomputed != stored_hash:
            errors.append(f"frame {idx}: hash mismatch (tampered)")
        if frame.get("prev_hash") != prev:
            errors.append(f"frame {idx}: broken prev_hash linkage")

        if sig_alg == "ed25519" and (pubkey_hex or frame.get("pubkey")):
            if not _verify_ed25519(pubkey_hex or frame.get("pubkey"), stored_hash, sig):
                errors.append(f"frame {idx}: ed25519 signature invalid")
        elif sig_alg == "hmac-sha256":
            key = os.environ.get("NEXUS_EAT_HMAC_KEY", "").strip().encode("utf-8")
            if key:
                expect = hmac.new(key, bytes.fromhex(stored_hash), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expect, sig):
                    errors.append(f"frame {idx}: hmac signature invalid")

        prev = stored_hash
        leaves.append(stored_hash)

    return {"ok": not errors, "frames": len(leaves), "errors": errors, "merkle_root": compute_merkle_root(leaves)}


def _verify_ed25519(pubkey_hex: Optional[str], digest_hex: str, sig_hex: str) -> bool:
    if not pubkey_hex or not sig_hex:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(digest_hex))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def record_eat_frame(event: Dict[str, Any]) -> Dict[str, Any]:
    session_id = str(event.get("session_id", ""))
    agent_id = str(event.get("agent_id", "nexus_agent"))
    project_hash = str(event.get("project_hash", "default"))

    try:
        recorder = EATRecorder(session_id=session_id, agent_id=agent_id, project_hash=project_hash)
    except Exception as exc:
        logger.warning("Failed to create EATRecorder: %s", exc)
        return {}

    return recorder.record(
        skill_id=str(event.get("skill_id", "")),
        status=str(event.get("status", "ok")),
        params_hash=event.get("params_hash"),
        result=event.get("result"),
        duration_ms=int(event.get("duration_ms", 0) or 0),
        extra=event.get("extra"),
    )


def main(argv: Optional[list] = None) -> int:
    try:
        raw = sys.stdin.read()
    except Exception:
        return 0
    if not raw or not raw.strip():
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        return 0

    if "skill_id" not in event:
        event["skill_id"] = event.get("tool_name") or ""
        resp = event.get("tool_response")
        if isinstance(resp, dict):
            event["result"] = resp

    frame = record_eat_frame(event)
    print(json.dumps({
        "eat_frame_id": frame.get("frame_id"),
        "this_hash": frame.get("this_hash"),
        "seq": frame.get("seq"),
        "sig_alg": frame.get("sig_alg"),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["EATRecorder", "EATFrame", "record_eat_frame", "verify_chain", "compute_merkle_root"]