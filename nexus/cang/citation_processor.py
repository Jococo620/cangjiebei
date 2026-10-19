# nexus/cang/citation_processor.py — 强制引用闭环校验处理器
# 鉴真"防幻觉三件套"之一：扫描 LLM 研判报告中的每一个引用角标 [i]，
# 若编造了不存在的证据索引、或全文无任何引用，则触发"降级保护拒答"，
# 从根本上扼杀超出上下文的臆测（对标 Self-RAG 的引用纪律 / RAGAS Faithfulness）。
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# 同时兼容 [1] / [证据 1] / [证据1] / [Evidence 2] 等角标写法
_CITATION_RE = re.compile(r"\[(?:证据\s*|evidence\s*)?(\d+)\]", re.IGNORECASE)


class CitationProcessor:
    """强制引用闭环校验处理器。

    Args:
        allowed_sources: RAG 检索出的可信数据源列表（顺序与 prompt 中 [1..N] 对应）。
    """

    def __init__(
        self,
        allowed_sources: Optional[List[Any]] = None,
        faithfulness_threshold: float = 0.95,
        allow_no_citation: bool = False,
    ):
        self.allowed_sources = list(allowed_sources or [])
        self.faithfulness_threshold = float(faithfulness_threshold)
        self.allow_no_citation = bool(allow_no_citation)

    @staticmethod
    def extract_citations(text: str) -> List[int]:
        """提取文本中出现的全部引用角标编号（1-based，保序去重）。"""
        seen: Dict[int, None] = {}
        for m in _CITATION_RE.finditer(text or ""):
            seen.setdefault(int(m.group(1)), None)
        return list(seen.keys())

    @staticmethod
    def extract_claims(answer: str) -> List[str]:
        """把答案切分为可独立校验的事实陈述。"""
        parts = re.split(r"[。！？!?；;\n]+", answer or "")
        claims = []
        for part in parts:
            claim = part.strip()
            if claim:
                claims.append(claim)
        return claims

    @staticmethod
    def _doc_text(doc: Any) -> str:
        if isinstance(doc, dict):
            for key in ("text", "content", "document", "desc", "description"):
                if doc.get(key):
                    return str(doc[key])
            return str(doc.get("source") or doc.get("id") or "")
        return str(doc or "")

    @staticmethod
    def _strip_citations(text: str) -> str:
        return _CITATION_RE.sub("", text or "")

    @staticmethod
    def _units(text: str) -> List[str]:
        clean = CitationProcessor._strip_citations(text).lower()
        return re.findall(r"[a-z0-9_]+|[\u4e00-\u9fff]", clean)

    def check_entailment(self, claim: str, doc: Any) -> bool:
        """轻量确定性蕴含代理：子串命中或高覆盖字符/词重合即视为支持。"""
        claim_text = self._strip_citations(claim).strip()
        doc_text = self._doc_text(doc)
        if not claim_text:
            return True
        if claim_text in doc_text:
            return True

        claim_units = set(self._units(claim_text))
        if not claim_units:
            return False
        doc_units = set(self._units(doc_text))
        coverage = len(claim_units & doc_units) / len(claim_units)
        return coverage >= 0.5

    def _index_only_verdict(self, llm_answer: str) -> Dict[str, Any]:
        """对生成的研判报告做引用闭环校验。

        Returns dict:
          - status: "passed" | "failed"
          - reason: 失败原因（status==failed 时）
          - used_citations: 报告中实际引用的编号
          - invalid_citations: 超出可信上下文范围的虚构编号
          - faithfulness: 合规引用占比（0~1），可作为 RAGAS Faithfulness 的轻量代理指标
          - verified_content: 通过时回显原文
        """
        citations = self.extract_citations(llm_answer)
        if not citations:
            if self.allow_no_citation:
                return {
                    "status": "passed",
                    "ok": True,
                    "used_citations": [],
                    "invalid_citations": [],
                    "fabricated_citations": [],
                    "faithfulness": 1.0,
                    "supported_claims": 0,
                    "total_claims": 0,
                    "verified_content": llm_answer,
                }
            return {
                "status": "failed",
                "ok": False,
                "reason": "回答未包含任何引用标签，属于不合规幻觉报告（降级拒答）。",
                "used_citations": [],
                "invalid_citations": [],
                "fabricated_citations": [{"claim": llm_answer, "reason": "无引用"}],
                "faithfulness": 0.0,
                "supported_claims": 0,
                "total_claims": len(self.extract_claims(llm_answer)),
            }

        n = len(self.allowed_sources)
        invalid = [c for c in citations if c < 1 or c > n]
        if invalid:
            faithfulness = round(1.0 - len(invalid) / len(citations), 4)
            return {
                "status": "failed",
                "ok": False,
                "reason": (
                    f"回答中包含超出置信上下文的虚构引用角标 {invalid}；"
                    f"可信证据仅 {n} 条，触发降级保护拒答。"
                ),
                "used_citations": citations,
                "invalid_citations": invalid,
                "fabricated_citations": [
                    {"citation": c, "reason": f"虚构引用 [{c}]"} for c in invalid
                ],
                "faithfulness": faithfulness,
                "supported_claims": len(citations) - len(invalid),
                "total_claims": len(citations),
            }

        return {
            "status": "passed",
            "ok": True,
            "used_citations": citations,
            "invalid_citations": [],
            "fabricated_citations": [],
            "faithfulness": 1.0,
            "supported_claims": len(citations),
            "total_claims": len(citations),
            "verified_content": llm_answer,
        }

    def post_verify_answer(
        self,
        llm_answer: str,
        cited_docs: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """对生成答案做引用闭环校验。

        未显式传入 ``cited_docs`` 时保持旧行为：仅校验引用角标是否落在
        ``allowed_sources`` 范围内。显式传入文档时按文档方案执行 claim-level
        支持度校验，并返回 ``ok/faithfulness/supported_claims`` 等规范字段。
        """
        if cited_docs is None:
            return self._index_only_verdict(llm_answer)

        docs = list(cited_docs or [])
        claims = self.extract_claims(llm_answer)
        all_citations = self.extract_citations(llm_answer)
        fabricated: List[Dict[str, Any]] = []
        invalid_citations: List[int] = []

        if not claims:
            ok = self.allow_no_citation
            return {
                "status": "passed" if ok else "failed",
                "ok": ok,
                "used_citations": all_citations,
                "invalid_citations": [],
                "fabricated_citations": [],
                "faithfulness": 1.0 if ok else 0.0,
                "supported_claims": 0,
                "total_claims": 0,
                "verified_content": llm_answer if ok else None,
                "reason": "" if ok else "回答未包含可校验陈述。",
            }

        supported = 0
        for claim in claims:
            claim_citations = self.extract_citations(claim)
            if not claim_citations:
                if self.allow_no_citation:
                    supported += 1
                    continue
                claim_supported = False
                for doc in docs:
                    if self.check_entailment(claim, doc):
                        claim_supported = True
                        break
                if claim_supported:
                    supported += 1
                else:
                    fabricated.append({"claim": claim, "reason": "无引用且证据不支持该陈述"})
                continue

            claim_supported = False
            for citation_id in claim_citations:
                if citation_id < 1 or citation_id > len(docs):
                    invalid_citations.append(citation_id)
                    fabricated.append(
                        {"claim": claim, "citation": citation_id, "reason": f"虚构引用 [{citation_id}]"}
                    )
                    continue
                if self.check_entailment(claim, docs[citation_id - 1]):
                    claim_supported = True
                    break
            if claim_supported:
                supported += 1
            elif not any(item.get("claim") == claim for item in fabricated):
                fabricated.append({"claim": claim, "reason": "引用文档不支持该陈述"})

        total = len(claims)
        faithfulness = round(supported / total, 4) if total else 0.0
        invalid_unique = list(dict.fromkeys(invalid_citations))
        ok = faithfulness >= self.faithfulness_threshold and not fabricated
        reason = ""
        if not ok:
            if invalid_unique:
                reason = f"回答中包含虚构引用角标 {invalid_unique}。"
            elif faithfulness < self.faithfulness_threshold:
                reason = (
                    f"引用忠实度 {faithfulness:.2f} 低于阈值 "
                    f"{self.faithfulness_threshold:.2f}。"
                )
            else:
                reason = "回答未通过引用闭环校验。"

        return {
            "status": "passed" if ok else "failed",
            "ok": ok,
            "reason": reason,
            "used_citations": all_citations,
            "invalid_citations": invalid_unique,
            "fabricated_citations": fabricated,
            "faithfulness": faithfulness,
            "supported_claims": supported,
            "total_claims": total,
            "verified_content": llm_answer if ok else None,
        }

    def enforce(self, llm_answer: str, refusal_template: str = "") -> Dict[str, Any]:
        """便捷封装：校验通过则返回原文；否则返回标准拒答文本与失败详情。"""
        verdict = self.post_verify_answer(llm_answer)
        if verdict["status"] == "passed":
            return {"answer": llm_answer, "refused": False, "verdict": verdict}
        refusal = refusal_template or (
            "【鉴真防幻觉安全守卫】生成内容未能通过引用闭环校验"
            f"（{verdict['reason']}）。为防止臆测，已执行降级拒答，请补充垂域证据后重试。"
        )
        return {"answer": refusal, "refused": True, "verdict": verdict}

    def enforce_or_refuse(self, answer: str, verdict: Dict[str, Any]) -> str:
        """文档接口：校验未通过时返回拒答回退消息。"""
        if verdict.get("ok") or verdict.get("status") == "passed":
            return answer
        reason = verdict.get("reason") or "回答未通过引用闭环校验。"
        return f"【鉴真防幻觉安全守卫】生成内容未通过引用闭环校验（{reason}），已降级拒答。"

    # ── RAGFlow 风格可点击引用卡片 ──
    def build_citation_cards(self, llm_answer: str, snippet_len: int = 160) -> List[Dict[str, Any]]:
        """把回答中的引用角标渲染为『可点击展开』引用卡片列表，供前端直接消费。

        对标 RAGFlow "Quick view of the key references and traceable citations" 的产品
        设计语言：默认只展示原文片段预览（``snippet``），前端点击展开后再渲染
        ``full_text``。虚构引用角标（超出 ``allowed_sources`` 范围）会被显式标记为
        ``valid=False`` 且不回填任何来源内容，供前端高亮成"不可信引用"而非静默隐藏，
        与既有 ``post_verify_answer`` 的防幻觉纪律保持一致。

        本函数只产出与具体前端框架无关的结构化数据（可直接 JSON 序列化），实际的
        "可点击展开"交互由消费方（如 nexus.gateway.rest_api 的响应）负责渲染。
        """
        cards: List[Dict[str, Any]] = []
        for idx in self.extract_citations(llm_answer):
            valid = 1 <= idx <= len(self.allowed_sources)
            full_text = ""
            source_id: Optional[str] = None
            source_title: Optional[str] = None
            if valid:
                doc = self.allowed_sources[idx - 1]
                full_text = self._doc_text(doc)
                if isinstance(doc, dict):
                    source_id = doc.get("id")
                    source_title = doc.get("title") or doc.get("source")
                else:
                    source_title = str(doc)
            snippet = full_text[:snippet_len]
            if len(full_text) > snippet_len:
                snippet += "…"
            cards.append(
                {
                    "citation_index": idx,
                    "valid": valid,
                    "source_id": source_id,
                    "source_title": source_title,
                    "snippet": snippet,
                    "full_text": full_text,
                    "expandable": True,
                }
            )
        return cards

    def render_answer_with_cards(self, llm_answer: str) -> Dict[str, Any]:
        """一站式渲染：引用闭环校验裁决 + 引用卡片列表，直接作为 REST 响应体返回。

        未通过校验时 ``answer`` 字段替换为标准拒答文本（复用 :meth:`enforce_or_refuse`），
        ``citation_cards`` 仍然基于原始回答生成，便于前端展示"哪些引用是虚构的"。
        """
        verdict = self.post_verify_answer(llm_answer)
        cards = self.build_citation_cards(llm_answer)
        answer = self.enforce_or_refuse(llm_answer, verdict)
        return {
            "answer": answer,
            "refused": answer != llm_answer,
            "verdict": verdict,
            "citation_cards": cards,
        }


__all__ = ["CitationProcessor"]