"""citation_processor 引用闭环校验单元测试。"""

import pytest

from nexus.cang.citation_processor import CitationProcessor


def test_extract_citations_plain():
    cp = CitationProcessor(["doc-a", "doc-b"])
    assert cp.extract_citations("根据[1]和[2]可知") == [1, 2]


def test_extract_citations_chinese_and_evidence():
    cp = CitationProcessor(["a", "b"])
    assert cp.extract_citations("参见[证据1]与[Evidence 2]") == [1, 2]


def test_extract_citations_dedup_keeps_order():
    cp = CitationProcessor(["a", "b"])
    assert cp.extract_citations("[2]... [1]... [2]") == [2, 1]


def test_extract_claims_splits_on_punctuation():
    cp = CitationProcessor([])
    assert cp.extract_claims("第一句。第二句！第三句？") == ["第一句", "第二句", "第三句"]


def test_index_only_pass():
    cp = CitationProcessor(["d1", "d2", "d3"])
    verdict = cp.post_verify_answer("结论[1][2]")
    assert verdict["status"] == "passed"
    assert verdict["ok"] is True
    assert verdict["faithfulness"] == 1.0


def test_index_only_fabricated_citation():
    cp = CitationProcessor(["d1", "d2"])
    verdict = cp.post_verify_answer("结论[3]")
    assert verdict["status"] == "failed"
    assert 3 in verdict["invalid_citations"]


def test_index_only_no_citation_fails_by_default():
    cp = CitationProcessor(["d1", "d2"])
    verdict = cp.post_verify_answer("没有引用的回答")
    assert verdict["status"] == "failed"
    assert "未包含任何引用" in verdict["reason"]


def test_allow_no_citation():
    cp = CitationProcessor(["d1"], allow_no_citation=True)
    verdict = cp.post_verify_answer("没有引用的回答")
    assert verdict["status"] == "passed"


def test_claim_level_entailment_pass():
    docs = [{"text": "SQL注入可通过参数化查询防御"}]
    cp = CitationProcessor(docs, faithfulness_threshold=0.7)
    verdict = cp.post_verify_answer("SQL注入可通过参数化查询防御[1]", cited_docs=docs)
    assert verdict["status"] == "passed"
    assert verdict["supported_claims"] == 1


def test_claim_level_fabricated_citation():
    docs = [{"text": "某内容"}]
    cp = CitationProcessor(docs)
    verdict = cp.post_verify_answer("结论[5]", cited_docs=docs)
    assert verdict["status"] == "failed"
    assert 5 in verdict["invalid_citations"]


def test_enforce_refuses_on_failure():
    cp = CitationProcessor(["d1"])
    out = cp.enforce("没有引用")
    assert out["refused"] is True
    assert "防幻觉" in out["answer"]


def test_enforce_passes_on_success():
    cp = CitationProcessor(["d1"])
    out = cp.enforce("结论[1]")
    assert out["refused"] is False
    assert out["answer"] == "结论[1]"


def test_build_citation_cards_marks_invalid():
    cp = CitationProcessor(["d1"])
    cards = cp.build_citation_cards("见[1][2]")
    by_idx = {c["citation_index"]: c for c in cards}
    assert by_idx[1]["valid"] is True
    assert by_idx[2]["valid"] is False
