"""security_rag 低置信拒答与引用闭环单元测试。"""

import pytest

from nexus.cang.security_rag import SecurityRAG


def make_rag(min_citations=1, min_score=0.62):
    return SecurityRAG(
        embedder=None,
        vector_store=None,
        min_citations=min_citations,
        min_score=min_score,
    )


def test_refuses_when_no_evidence(monkeypatch):
    rag = make_rag(min_citations=1)
    monkeypatch.setattr(rag, "retrieve", lambda query, top_k=6: [])
    out = rag.grounded_answer(llm=None, query="任意问题")
    assert out["refused"] is True
    assert out["citations"] == []
    assert "低于要求 1 条" in out["refusal_reason"]


def test_refuses_when_insufficient_citations(monkeypatch):
    rag = make_rag(min_citations=2)
    hits = [{"source": "s1", "text": "内容", "score": 0.9}]
    monkeypatch.setattr(rag, "retrieve", lambda query, top_k=6: hits)
    out = rag.grounded_answer(llm=None, query="x")
    assert out["refused"] is True
    assert "低于要求 2 条" in out["refusal_reason"]


def test_refuses_when_low_score(monkeypatch):
    rag = make_rag(min_citations=1, min_score=0.8)
    hits = [{"source": "s1", "text": "内容", "score": 0.5}]
    monkeypatch.setattr(rag, "retrieve", lambda query, top_k=6: hits)
    out = rag.grounded_answer(llm=None, query="x")
    assert out["refused"] is True
    assert "低于阈值 0.80" in out["refusal_reason"]


def test_answers_when_evidence_sufficient(monkeypatch):
    rag = make_rag(min_citations=1, min_score=0.6)
    hits = [{"source": "s1", "text": "可靠证据", "score": 0.9}]
    monkeypatch.setattr(rag, "retrieve", lambda query, top_k=6: hits)
    monkeypatch.setattr(rag, "_ask_llm", lambda llm, prompt: "结论[1]")
    monkeypatch.setattr(rag, "_extract_content", lambda response: response)
    out = rag.grounded_answer(llm=None, query="x")
    assert out["refused"] is False
    assert out["citations"] == ["s1"]
    assert out["answer"] == "结论[1]"


def test_chunk_overlap_guard():
    with pytest.raises(ValueError):
        SecurityRAG(embedder=None, vector_store=None, chunk_size=512, chunk_overlap=512)
