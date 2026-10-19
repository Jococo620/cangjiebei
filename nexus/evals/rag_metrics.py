"""RAG 分解式指标采集模块——不使用 LLM-as-judge 做主判，采用轻量确定性指标。

对齐  核心模块设计文档第十章 RAG 防幻觉三件套接口规范，提供：
  - faithfulness：引用忠实度（陈述与证据的蕴含关系）
  - context_precision：上下文精确率（检索证据的相关性）
  - context_recall：上下文召回率（证据覆盖程度）
  - answer_relevancy：答案相关性（答案与问题的匹配度）
  - retrieval_precision：检索精确率（top-k 结果中的有效比例）
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


class RAGMetrics:
    """RAG 分解式指标计算器。"""

    @staticmethod
    def _text_units(text: str) -> List[str]:
        """提取文本中的语义单元（词和汉字）。"""
        return re.findall(r"[a-z0-9_]+|[\u4e00-\u9fff]", str(text or "").lower())

    @staticmethod
    def _doc_text(doc: Any) -> str:
        """从文档对象中提取文本内容。"""
        if isinstance(doc, dict):
            for key in ("text", "content", "document", "desc", "description"):
                if doc.get(key):
                    return str(doc[key])
            return str(doc.get("source") or doc.get("id") or "")
        return str(doc or "")

    @staticmethod
    def _extract_claims(answer: str) -> List[str]:
        """把答案切分为可独立校验的事实陈述。"""
        parts = re.split(r"[。！？!?；;\n]+", answer or "")
        claims = []
        for part in parts:
            claim = part.strip()
            if claim:
                claims.append(claim)
        return claims

    @staticmethod
    def _check_entailment(claim: str, doc: Any, threshold: float = 0.5) -> bool:
        """轻量确定性蕴含代理：子串命中或高覆盖字符/词重合即视为支持。"""
        claim_text = str(claim or "").strip()
        doc_text = RAGMetrics._doc_text(doc)
        if not claim_text:
            return True
        if claim_text in doc_text:
            return True

        claim_units = set(RAGMetrics._text_units(claim_text))
        if not claim_units:
            return False
        doc_units = set(RAGMetrics._text_units(doc_text))
        coverage = len(claim_units & doc_units) / len(claim_units)
        return coverage >= threshold

    @staticmethod
    def faithfulness(answer: str, contexts: List[Any]) -> float:
        """引用忠实度：答案中的每一条陈述是否都被检索到的证据支持。

        返回值范围：0.0 ~ 1.0，越高表示答案越忠实于证据。
        """
        claims = RAGMetrics._extract_claims(answer)
        if not claims:
            return 0.0

        supported = 0
        for claim in claims:
            for ctx in contexts:
                if RAGMetrics._check_entailment(claim, ctx):
                    supported += 1
                    break

        return round(supported / len(claims), 4)

    @staticmethod
    def context_precision(answer: str, contexts: List[Any]) -> float:
        """上下文精确率：检索到的证据中有多少被答案实际引用。

        返回值范围：0.0 ~ 1.0，越高表示检索结果越精确。
        """
        if not contexts:
            return 0.0

        claims = RAGMetrics._extract_claims(answer)
        if not claims:
            return 0.0

        used_contexts = 0
        for ctx in contexts:
            for claim in claims:
                if RAGMetrics._check_entailment(claim, ctx):
                    used_contexts += 1
                    break

        return round(used_contexts / len(contexts), 4)

    @staticmethod
    def context_recall(question: str, contexts: List[Any]) -> float:
        """上下文召回率：检索到的证据覆盖问题关键信息的程度。

        返回值范围：0.0 ~ 1.0，越高表示证据覆盖越全面。
        """
        question_units = set(RAGMetrics._text_units(question))
        if not question_units:
            return 0.0

        covered_units = set()
        for ctx in contexts:
            ctx_units = set(RAGMetrics._text_units(RAGMetrics._doc_text(ctx)))
            covered_units |= ctx_units

        return round(len(question_units & covered_units) / len(question_units), 4)

    @staticmethod
    def answer_relevancy(question: str, answer: str) -> float:
        """答案相关性：答案与问题的语义匹配程度。

        返回值范围：0.0 ~ 1.0，越高表示答案越相关。
        """
        question_units = set(RAGMetrics._text_units(question))
        answer_units = set(RAGMetrics._text_units(answer))

        if not question_units or not answer_units:
            return 0.0

        return round(len(question_units & answer_units) / len(question_units), 4)

    @staticmethod
    def retrieval_precision(contexts: List[Any], min_score: float = 0.3) -> float:
        """检索精确率：top-k 结果中满足最小分数阈值的比例。

        返回值范围：0.0 ~ 1.0，越高表示检索结果质量越好。
        """
        if not contexts:
            return 0.0

        valid = 0
        for ctx in contexts:
            score = float(ctx.get("score", 0.0)) if isinstance(ctx, dict) else 0.0
            if score >= min_score:
                valid += 1

        return round(valid / len(contexts), 4)

    @staticmethod
    def evaluate_rag(
        question: str,
        answer: str,
        contexts: List[Any],
        min_score: float = 0.3,
    ) -> Dict[str, Any]:
        """一站式评估 RAG 质量，返回所有分解式指标。

        Args:
            question: 用户问题
            answer: RAG 生成的答案
            contexts: 检索到的证据列表
            min_score: 检索分数阈值

        Returns:
            包含所有指标的字典：
              - faithfulness: float (0~1)
              - context_precision: float (0~1)
              - context_recall: float (0~1)
              - answer_relevancy: float (0~1)
              - retrieval_precision: float (0~1)
              - overall_score: float (0~1) - 加权综合得分
              - breakdown: dict - 各指标的详细信息
        """
        metrics = {
            "faithfulness": RAGMetrics.faithfulness(answer, contexts),
            "context_precision": RAGMetrics.context_precision(answer, contexts),
            "context_recall": RAGMetrics.context_recall(question, contexts),
            "answer_relevancy": RAGMetrics.answer_relevancy(question, answer),
            "retrieval_precision": RAGMetrics.retrieval_precision(contexts, min_score),
        }

        weights = {
            "faithfulness": 0.35,
            "context_precision": 0.15,
            "context_recall": 0.20,
            "answer_relevancy": 0.20,
            "retrieval_precision": 0.10,
        }

        overall_score = sum(
            metrics[key] * weights[key] for key in weights if key in metrics
        )

        breakdown = {
            key: {
                "value": metrics[key],
                "weight": weights.get(key, 0.0),
                "contribution": round(metrics[key] * weights.get(key, 0.0), 4),
            }
            for key in metrics
        }

        return {
            "metrics": metrics,
            "overall_score": round(overall_score, 4),
            "breakdown": breakdown,
            "evidence_count": len(contexts),
            "answer_length": len(answer),
            "question_length": len(question),
        }


__all__ = ["RAGMetrics"]