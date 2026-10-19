# nexus/audit/eat_db.py — 可信审计链 SQLite 持久化/可查询索引层
# 与 nexus/integrations/ecc/eat_recorder.py 的 JSONL append-only 主链互补：
#   JSONL 负责"只追加 + 续链"，本 SQLite 层负责"按 session 快速检索 + 崩溃后复原视图"。
# 同时兼容两种帧 schema：eat_recorder 帧(this_hash/prev_hash/seq) 与
# OODA 内联帧(cryptographic_signature/prev_frame_hash/cycle_index)。
from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional


def _frame_hash(frame: Dict[str, Any]) -> str:
    return str(
        frame.get("this_hash")
        or frame.get("frame_hash")
        or frame.get("cryptographic_signature")
        or ""
    )


def _prev_hash(frame: Dict[str, Any]) -> str:
    return str(frame.get("prev_hash") or frame.get("prev_frame_hash") or "0" * 64)


def _seq(frame: Dict[str, Any]) -> int:
    val = frame.get("seq", frame.get("cycle_index", 0))
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


class EATDatabase:

    def __init__(self, db_path: str = ".nexus/eat_audit_trail.db"):
        self.db_path = db_path
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS eat_frames (
                    this_hash   TEXT PRIMARY KEY,
                    session_id  TEXT,
                    seq         INTEGER,
                    frame_id    TEXT,
                    prev_hash   TEXT,
                    sig_alg     TEXT,
                    signature   TEXT,
                    pubkey      TEXT,
                    agent_id    TEXT,
                    skill_id    TEXT,
                    status      TEXT,
                    payload     TEXT,
                    ts          TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_eat_session_seq ON eat_frames(session_id, seq)"
            )
            conn.commit()

    def persist_frame(self, session_id: str, frame: Dict[str, Any]) -> None:
        this_hash = _frame_hash(frame)
        if not this_hash:
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO eat_frames "
                "(this_hash, session_id, seq, frame_id, prev_hash, sig_alg, signature, "
                " pubkey, agent_id, skill_id, status, payload, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    this_hash,
                    session_id,
                    _seq(frame),
                    str(frame.get("frame_id", "")),
                    _prev_hash(frame),
                    str(frame.get("sig_alg", "")),
                    str(frame.get("signature", "")),
                    str(frame.get("pubkey", "")),
                    str(frame.get("agent_id", "")),
                    str(frame.get("skill_id", "")),
                    str(frame.get("status", "")),
                    json.dumps(frame, ensure_ascii=False),
                    str(frame.get("ts", frame.get("timestamp", ""))),
                ),
            )
            conn.commit()

    def persist_chain(self, session_id: str, frames: List[Dict[str, Any]]) -> int:
        count = 0
        for frame in frames:
            if _frame_hash(frame):
                self.persist_frame(session_id, frame)
                count += 1
        return count

    def load_session_frames(self, session_id: str) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT payload FROM eat_frames WHERE session_id = ? ORDER BY seq ASC, rowid ASC",
                (session_id,),
            )
            rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for (payload,) in rows:
            try:
                out.append(json.loads(payload))
            except (TypeError, json.JSONDecodeError):
                continue
        return out

    def load_leaves(self, session_id: str) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT this_hash FROM eat_frames WHERE session_id = ? ORDER BY seq ASC, rowid ASC",
                (session_id,),
            )
            return [str(h) for (h,) in cur.fetchall() if h]

    def list_sessions(self) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT session_id FROM eat_frames ORDER BY session_id")
            return [str(s) for (s,) in cur.fetchall()]


__all__ = ["EATDatabase"]