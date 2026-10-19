"""superagent 哈希链签名与思维链追踪单元测试。"""

import time

import pytest

from nexus.cang.superagent import DigestChainSigner, CoTTracer


def test_signer_chain_linking():
    signer = DigestChainSigner("agent-1")
    f1 = signer.sign_frame({"type": "x", "data": 1})
    f2 = signer.sign_frame({"type": "y", "data": 2})
    assert f1["prev_frame_hash"] == "0" * 64
    assert f1["frame_hash"] == f2["prev_frame_hash"]
    assert len(f1["frame_hash"]) == 64
    assert f1["agent_id"] == "agent-1"


def test_signer_deterministic_per_chain_state(monkeypatch):
    fixed = time.struct_time((2026, 1, 1, 0, 0, 0, 0, 1, -1))
    monkeypatch.setattr("nexus.cang.superagent.time.gmtime", lambda: fixed)
    s1 = DigestChainSigner("a")
    s2 = DigestChainSigner("a")
    a = s1.sign_frame({"x": 1})
    b = s2.sign_frame({"x": 1})
    assert a["frame_hash"] == b["frame_hash"]


def test_cot_tracer_records_steps():
    tracer = CoTTracer()
    frame = tracer.think("假设", {"k": "v"}, "结论")
    assert frame["type"] == "cot_step"
    assert frame["hypothesis"] == "假设"
    assert "frame_hash" in frame
    assert len(tracer.steps) == 1
