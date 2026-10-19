"""安全垂域 RAG 组件。"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("nexus.cang.rag")


class SecurityRAG:
    """提供检索置信门控、强制引用和低置信拒答的安全 RAG。"""

    def __init__(
        self,
        embedder: Any,
        vector_store: Any,
        reranker: Optional[Any] = None,
        vkb_client: Optional[Any] = None,
        min_score: float = 0.62,
        min_citations: int = 1,
        faithfulness_threshold: float = 0.70,
        rerank_weights: tuple = (0.3, 0.3, 0.4),
        chunk_size: int = 512,
        chunk_overlap: int = 64,
    ) -> None:
        if chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be smaller than chunk_size")
        self.embed = embedder
        self.store = vector_store
        self._external_reranker = reranker
        self.vkb_client = vkb_client
        self.min_score = float(min_score)
        self.min_citations = int(min_citations)
        self.faithfulness_threshold = float(faithfulness_threshold)
        self.rerank_weights = tuple(float(x) for x in rerank_weights)
        self.chunk_size = int(chunk_size)
        self.chunk_overlap = int(chunk_overlap)

    def ingest(self, docs: List[Dict[str, Any]]) -> int:
        """文档切块后入向量库，保留 source/title 供引用。"""
        inserted = 0
        for index, doc in enumerate(docs):
            text = str(doc.get("text", "")).strip()
            if not text:
                continue
            chunks = self._chunk(text, size=self.chunk_size, overlap=self.chunk_overlap)
            embeddings = self._embed_many(chunks)
            doc_id = str(doc.get("id", f"doc-{index}"))
            ids = [f"{doc_id}-{chunk_index}" for chunk_index, _ in enumerate(chunks)]
            metadatas = [
                {
                    "source": doc.get("source", doc_id),
                    "title": doc.get("title", doc_id),
                    "chunk_index": chunk_index,
                }
                for chunk_index, _ in enumerate(chunks)
            ]
            self._store_add(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=chunks)
            inserted += len(chunks)
        return inserted

    def retrieve(self, query: str, top_k: int = 6) -> List[Dict[str, Any]]:
        raw_hits = self._store_query(query, top_k=max(top_k * 2, top_k))
        hits = self._normalize_hits(raw_hits)
        if self._external_reranker:
            hits = list(self._external_reranker(query, hits))
        filtered = [hit for hit in hits if float(hit.get("score", 0.0)) >= self.min_score]
        return filtered[:top_k]

    def retrieve_with_vkb(
        self,
        registry: Any = None,
        query: Optional[str] = None,
        top_k: int = 6,
    ) -> List[Dict[str, Any]]:
        """融合本地向量库与 Sympas ``vkb_retrieve`` 权威漏洞知识库的检索。

        权威源（VKB）默认高置信，参与统一排序；失败/未注册时静默退化为纯本地检索。
        """
        if query is None:
            query = str(registry or "")
            registry = self.vkb_client
        registry = registry or self.vkb_client
        local = self.retrieve(query, top_k=top_k)
        authoritative: List[Dict[str, Any]] = []
        if registry is not None and hasattr(registry, "execute_skill"):
            try:
                vkb = registry.execute_skill("vkb_retrieve", {"query": query, "top_k": 3})
                hits = (vkb.get("data") or {}).get("hits") or vkb.get("hits") or []
                for h in hits:
                    if not isinstance(h, dict):
                        continue
                    ident = h.get("id") or h.get("cve") or "entry"
                    authoritative.append(
                        {
                            "id": ident,
                            "text": h.get("text") or h.get("desc") or h.get("description") or "",
                            "source": f"VKB::{ident}",
                            "score": float(h.get("score", 0.9)),
                            "metadata": {"authoritative": True},
                        }
                    )
            except Exception:  # noqa: BLE001
                logger.debug("vkb_retrieve augment skipped", exc_info=True)
        elif registry is not None and hasattr(registry, "retrieve"):
            try:
                hits = registry.retrieve(query=query, top_k=3)
                for h in hits or []:
                    if not isinstance(h, dict):
                        continue
                    ident = h.get("id") or h.get("cve") or "entry"
                    authoritative.append(
                        {
                            "id": ident,
                            "text": h.get("text") or h.get("desc") or h.get("description") or "",
                            "source": h.get("source") or f"VKB::{ident}",
                            "score": float(h.get("score", 0.9)),
                            "metadata": {"authoritative": True},
                        }
                    )
            except Exception:  # noqa: BLE001
                logger.debug("vkb client augment skipped", exc_info=True)

        merged = sorted(
            authoritative + local, key=lambda x: float(x.get("score", 0.0)), reverse=True
        )
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for item in merged:
            key = (item.get("source", ""), (item.get("text", "") or "")[:64])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:top_k]

    def rerank_documents(
        self,
        query: str,
        documents: List[Dict[str, Any]],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """三路融合重排序：词面覆盖、原始相似度、短语交互。"""
        if not documents:
            return []
        alpha, beta, gamma = self._normalized_rerank_weights()
        scored: List[Dict[str, Any]] = []
        for raw_doc in documents:
            doc = self._normalize_hit(raw_doc)
            bm25_score = self._lexical_overlap(query, doc.get("text", ""))
            embed_score = max(0.0, min(1.0, float(doc.get("score", 0.0))))
            cross_score = self._phrase_interaction(query, doc.get("text", ""))
            final_score = alpha * bm25_score + beta * embed_score + gamma * cross_score
            enriched = dict(doc)
            enriched["base_score"] = doc.get("score", 0.0)
            enriched["score"] = round(final_score, 6)
            enriched["score_components"] = {
                "bm25": round(bm25_score, 6),
                "embedding": round(embed_score, 6),
                "cross_encoder": round(cross_score, 6),
            }
            scored.append(enriched)

        scored.sort(key=lambda item: item["score"], reverse=True)
        for rank, item in enumerate(scored, 1):
            item["rank"] = rank
            item["refusal"] = rank == 1 and item["score"] < self.min_score
        return scored[:top_k]

    def rerank(
        self,
        query: str,
        documents: List[Dict[str, Any]],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """文档接口别名，返回带 score/rank 的重排序文档。"""
        return self.rerank_documents(query, documents, top_k=top_k)

    def generate_with_citations(self, query: str, documents: List[Dict[str, Any]]) -> str:
        """生成一个确定性、带引用标记的证据摘要，供无 LLM 环境降级使用。"""
        ranked = self.rerank_documents(query, documents, top_k=max(1, len(documents)))
        snippets = []
        for index, doc in enumerate(ranked, 1):
            text = str(doc.get("text", "")).strip()
            if text:
                snippets.append(f"{text}[{index}]")
        return " ".join(snippets) if snippets else "知识库证据不足，无法生成有引用的答案。"

    def should_refuse(
        self,
        query: str,
        reranked_docs: List[Dict[str, Any]],
        answer: str,
        citation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """根据检索置信度与引用忠实度决定是否拒答。"""
        del query, answer
        top_score = max((float(doc.get("score", 0.0)) for doc in reranked_docs or []), default=0.0)
        if top_score < self.min_score:
            return {
                "refuse": True,
                "reason": "检索置信度过低，证据不足",
                "fallback_message": "抱歉，知识库中未找到足够证据回答此问题。",
            }

        faithfulness = float(citation_result.get("faithfulness", 0.0))
        if faithfulness < self.faithfulness_threshold or citation_result.get("ok") is False:
            return {
                "refuse": True,
                "reason": (
                    f"引用忠实度 {faithfulness:.2f} 低于阈值 "
                    f"{self.faithfulness_threshold:.2f}"
                ),
                "fallback_message": "抱歉，生成的答案未通过引用校验，可能存在幻觉。",
            }

        return {"refuse": False, "reason": "", "fallback_message": ""}

    def grounded_answer(
        self,
        llm: Any,
        query: str,
        registry: Any = None,
        enforce_citations: bool = False,
    ) -> Dict[str, Any]:
        # 提供 registry 时融合 vkb 权威源；否则保持纯本地检索（向后兼容既有调用）
        ctx = (
            self.retrieve_with_vkb(registry, query)
            if registry is not None
            else self.retrieve(query)
        )
        top_score = max((float(item.get("score", 0.0)) for item in ctx), default=0.0)
        if len(ctx) < self.min_citations or top_score < self.min_score:
            return {
                "answer": "知识库证据不足，拒绝臆测；建议补充垂域语料或转人工。",
                "citations": [],
                "refused": True,
                "refusal_reason": (
                    f"命中 {len(ctx)} 条证据，低于要求 {self.min_citations} 条"
                    if len(ctx) < self.min_citations
                    else f"最高置信度 {top_score:.2f} 低于阈值 {self.min_score:.2f}"
                ),
                "evidence": ctx,
            }

        prompt = self._build_grounded_prompt(query, ctx)
        try:
            response = self._ask_llm(llm, prompt)
            answer = self._extract_content(response)
            if "error" in answer.lower() or "invalid url" in answer.lower() or not answer.strip():
                answer = "\n\n".join(f"[{i+1}] {item.get('text', '')}" for i, item in enumerate(ctx))
        except Exception as e:
            answer = "\n\n".join(f"[{i+1}] {item.get('text', '')}" for i, item in enumerate(ctx))
        citations = list(dict.fromkeys(item["source"] for item in ctx if item.get("source")))
        result = {
            "answer": answer,
            "citations": citations,
            "refused": False,
            "refusal_reason": "",
            "faithfulness": 1.0,
            "evidence": ctx,
        }
        # 引用闭环后置校验（默认关闭以兼容既有行为；开启则强制 Self-RAG 式引用纪律）
        if enforce_citations:
            from nexus.cang.citation_processor import CitationProcessor

            verdict = CitationProcessor(
                citations,
                faithfulness_threshold=self.faithfulness_threshold,
                allow_no_citation=True,
            ).post_verify_answer(answer, ctx)
            result["citation_verdict"] = verdict
            result["faithfulness"] = float(verdict.get("faithfulness", 0.0))
            if verdict.get("status") == "failed":
                result["refused"] = True
                result["refusal_reason"] = verdict.get("reason", "")
                result["answer"] = (
                    "【鉴真防幻觉安全守卫】生成内容未通过引用闭环校验"
                    f"（{verdict.get('reason', '')}），已降级拒答以防臆测。"
                )
        return result

    def _embed_many(self, texts: Iterable[str]) -> List[Any]:
        payload = list(texts)
        if callable(self.embed):
            result = self.embed(payload)
            return list(result)
        if hasattr(self.embed, "embed_documents"):
            return list(self.embed.embed_documents(payload))
        if hasattr(self.embed, "encode"):
            return list(self.embed.encode(payload))
        raise TypeError("embedder must be callable or provide embed_documents/encode")

    def _store_add(
        self,
        ids: List[str],
        embeddings: List[Any],
        metadatas: List[Dict[str, Any]],
        documents: List[str],
    ) -> None:
        add = getattr(self.store, "add", None) or getattr(self.store, "upsert", None)
        if not callable(add):
            raise TypeError("vector_store must provide add or upsert")
        try:
            add(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)
        except TypeError:
            add(embeddings, metadatas, documents)

    def _store_query(self, query: str, top_k: int) -> Any:
        query_embedding = self._embed_many([query])[0]
        if hasattr(self.store, "query"):
            try:
                return self.store.query(query_embedding=query_embedding, top_k=top_k)
            except TypeError:
                try:
                    return self.store.query(query_embedding, top_k=top_k)
                except TypeError:
                    return self.store.query(query_embedding, n_results=top_k)
        raise TypeError("vector_store must provide query")

    def _normalize_hits(self, raw_hits: Any) -> List[Dict[str, Any]]:
        if isinstance(raw_hits, dict) and "documents" in raw_hits:
            documents = (raw_hits.get("documents") or [[]])[0]
            metadatas = (raw_hits.get("metadatas") or [[]])[0]
            distances = (raw_hits.get("distances") or [[]])[0]
            ids = (raw_hits.get("ids") or [[]])[0]
            items = []
            for index, text in enumerate(documents):
                metadata = metadatas[index] if index < len(metadatas) else {}
                distance = distances[index] if index < len(distances) else 1.0
                doc_id = ids[index] if index < len(ids) else f"hit-{index}"
                score = max(0.0, 1.0 - float(distance) / 2.0)
                items.append(
                    {
                        "id": doc_id,
                        "text": text,
                        "metadata": metadata,
                        "score": score,
                    }
                )
            return [self._normalize_hit(item) for item in items]

        if isinstance(raw_hits, dict) and "hits" in raw_hits:
            raw_hits = raw_hits["hits"]

        if not isinstance(raw_hits, list):
            return []
        return [self._normalize_hit(hit) for hit in raw_hits if isinstance(hit, dict)]

    def _normalize_hit(self, hit: Dict[str, Any]) -> Dict[str, Any]:
        metadata = dict(hit.get("metadata") or {})
        score = hit.get("score")
        if score is None and hit.get("similarity") is not None:
            score = hit.get("similarity")
        if score is None and hit.get("distance") is not None:
            score = max(0.0, 1.0 - float(hit.get("distance", 1.0)) / 2.0)
        if score is None:
            score = 0.0
        return {
            "id": hit.get("id") or metadata.get("id") or "unknown",
            "text": hit.get("text") or hit.get("document") or hit.get("content") or "",
            "title": hit.get("title") or metadata.get("title") or "",
            "source": hit.get("source") or metadata.get("source") or "",
            "metadata": metadata,
            "score": float(score),
        }

    def _normalized_rerank_weights(self) -> tuple:
        weights = self.rerank_weights or (0.3, 0.3, 0.4)
        if len(weights) != 3:
            weights = (0.3, 0.3, 0.4)
        total = sum(max(0.0, float(w)) for w in weights)
        if total <= 0:
            return (0.3, 0.3, 0.4)
        return tuple(max(0.0, float(w)) / total for w in weights)

    def _lexical_overlap(self, query: str, text: str) -> float:
        q_units = set(self._text_units(query))
        if not q_units:
            return 0.0
        t_units = set(self._text_units(text))
        return len(q_units & t_units) / len(q_units)

    def _phrase_interaction(self, query: str, text: str) -> float:
        q_terms = [term for term in str(query or "").lower().split() if term]
        if not q_terms:
            return self._lexical_overlap(query, text)
        text_lower = str(text or "").lower()
        return sum(1 for term in q_terms if term in text_lower) / len(q_terms)

    def _text_units(self, text: str) -> List[str]:
        import re

        return re.findall(r"[a-z0-9_]+|[\u4e00-\u9fff]", str(text or "").lower())

    def _chunk(self, text: str, size: int, overlap: int) -> List[str]:
        if len(text) <= size:
            return [text]
        step = max(1, size - overlap)
        chunks = []
        for start in range(0, len(text), step):
            chunk = text[start:start + size]
            if not chunk:
                continue
            chunks.append(chunk)
            if start + size >= len(text):
                break
        return chunks

    def _build_grounded_prompt(self, query: str, ctx: List[Dict[str, Any]]) -> str:
        lines = [
            "请仅依据下列证据回答问题，并在结尾保留引用来源列表。",
            f"问题: {query}",
            "",
            "证据:",
        ]
        for index, item in enumerate(ctx, 1):
            lines.append(
                f"[{index}] source={item.get('source') or 'unknown'} | score={item.get('score', 0.0):.3f}"
            )
            lines.append(item.get("text", ""))
            lines.append("")
        lines.append("回答要求: 仅基于证据作答；证据不足时明确指出不确定。")
        return "\n".join(lines)

    def _ask_llm(self, llm: Any, prompt: str) -> Any:
        messages = [{"role": "user", "content": prompt}]
        if hasattr(llm, "chat_with_tools"):
            return llm.chat_with_tools(messages, tools=[])
        if hasattr(llm, "chat"):
            try:
                return llm.chat(messages, tools=[], task="rag_retrieval")
            except TypeError:
                return llm.chat(messages)
        raise TypeError("llm must provide chat_with_tools or chat")

    def _extract_content(self, response: Any) -> str:
        if isinstance(response, dict):
            return str(response.get("content") or response.get("answer") or "")
        return str(response)


class AdvancedSecurityRAG:
    """三路融合重排序、VKB 权威源接入、引用闭环校验与主动拒答的高级防幻觉 RAG 引擎。

    相比基础 SecurityRAG，AdvancedSecurityRAG 额外提供：
      - ``retrieve_and_rerank``：BM25 词频 + 向量余弦 + 仿 CrossEncoder 三路加权重排序
      - ``grounded_answer_loop``：检索门控 → 主动拒答 → 引用忠实度后置拦截完整流水线
      - ``compute_bm25_similarity``：轻量词频匹配得分计算
      - ``import_vkb_corpus``：VKB权威知识库批量导入器（支持JSONL/Markdown/ATT&CK STIX 2.1）
      - ``adaptive_confidence_threshold``：检索置信度门控阈值动态调整
      - ``hybrid_retrieval``：多路召回融合策略（稠密+稀疏+RRF）

    与 SecurityRAG 设计兼容：可作为更严格防幻觉级别的替代引擎（或与之叠加使用）。
    """

    def __init__(
        self,
        vector_memory: Any,
        min_score: float = 0.62,
        faithfulness_threshold: float = 0.95,
        rerank_weights: tuple = (0.3, 0.3, 0.4),
        chunk_size: int = 512,
        chunk_overlap: int = 64,
    ) -> None:
        self.memory = vector_memory
        self.min_score = float(min_score)
        self.faithfulness_threshold = float(faithfulness_threshold)
        self.rerank_weights = tuple(float(w) for w in rerank_weights)
        self.chunk_size = int(chunk_size)
        self.chunk_overlap = int(chunk_overlap)
        self._ingested_hashes: set = set()

    def ingest(self, docs: List[Dict[str, Any]]) -> int:
        """文档切块后入向量库，兼容SecurityRAG接口。"""
        inserted = 0
        for index, doc in enumerate(docs):
            text = str(doc.get("text", "")).strip()
            if not text:
                continue
            chunks = self._chunk(text, size=self.chunk_size, overlap=self.chunk_overlap)
            doc_id = str(doc.get("id", f"doc-{index}"))
            for chunk_index, chunk in enumerate(chunks):
                if self.memory and hasattr(self.memory, "add"):
                    metadata = {
                        "source": doc.get("source", doc_id),
                        "title": doc.get("title", doc_id),
                        "chunk_index": chunk_index,
                    }
                    try:
                        self.memory.add(texts=[chunk], metadatas=[metadata])
                        inserted += 1
                    except Exception:
                        pass
        return inserted

    def compute_bm25_similarity(self, query: str, doc_text: str) -> float:
        """轻量词频匹配分度量（BM25 近似）：查询词命中占比。"""
        import re as _re
        q_words = set(_re.findall(r"\w+", (query or "").lower()))
        d_words = set(_re.findall(r"\w+", (doc_text or "").lower()))
        if not q_words:
            return 0.0
        return len(q_words & d_words) / len(q_words)

    # ── TODO 1: VKB权威知识库批量导入器 ──
    def import_vkb_corpus(self, source_path: str, format: str = "jsonl") -> int:
        """
        从外部语料源批量导入权威知识到向量库。
        支持格式：JSONL、Markdown、ATT&CK STIX 2.1

        实施要点：
        1. 每条文档必须带 source_authority 字段（如 "ATT&CK v15"）
        2. 自动分块（chunk_size=512, overlap=64）
        3. 去重检查（基于sha256哈希）
        4. 返回实际导入数量

        Args:
            source_path: 语料文件路径
            format: 语料格式（jsonl/md/stix2）
        Returns:
            成功导入的文档数量
        """
        import hashlib
        import json
        import os

        if not os.path.exists(source_path):
            logger.error(f"VKB corpus source not found: {source_path}")
            return 0

        docs = []
        if format.lower() == "jsonl":
            with open(source_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        doc = json.loads(line)
                        docs.append(doc)
                    except json.JSONDecodeError:
                        continue
        elif format.lower() == "md":
            with open(source_path, "r", encoding="utf-8") as f:
                content = f.read()
            sections = content.split("\n## ")
            for i, section in enumerate(sections):
                if not section.strip():
                    continue
                lines = section.strip().split("\n")
                title = lines[0].strip() if lines else f"Section {i}"
                text = "\n".join(lines[1:]) if len(lines) > 1 else section
                docs.append({
                    "text": text.strip(),
                    "title": title,
                    "source_authority": "Markdown Manual",
                })
        elif format.lower() == "stix2":
            try:
                from stix2 import Bundle
                with open(source_path, "r", encoding="utf-8") as f:
                    stix_data = json.load(f)
                bundle = Bundle(**stix_data)
                for obj in bundle.objects:
                    obj_dict = dict(obj)
                    obj_type = obj_dict.get("type", "unknown")
                    if obj_type in ("attack-pattern", "malware", "tool", "vulnerability"):
                        name = obj_dict.get("name", "")
                        description = obj_dict.get("description", "")
                        external_refs = obj_dict.get("external_references", [])
                        authority = "STIX2 ATT&CK"
                        for ref in external_refs:
                            if ref.get("source_name") == "mitre-attack":
                                authority = f"ATT&CK {ref.get('external_id', '')}"
                                break
                        docs.append({
                            "text": f"{name}\n{description}",
                            "title": name,
                            "source_authority": authority,
                            "external_id": obj_dict.get("external_references", [{}])[0].get("external_id", "") if external_refs else "",
                        })
            except Exception as exc:
                logger.warning(f"STIX2 parsing failed: {exc}")
        else:
            logger.error(f"Unsupported format: {format}")
            return 0

        inserted = 0
        for doc in docs:
            text = str(doc.get("text", "")).strip()
            if not text:
                continue
            content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if content_hash in self._ingested_hashes:
                continue

            chunks = self._chunk(text, size=self.chunk_size, overlap=self.chunk_overlap)
            for chunk_index, chunk in enumerate(chunks):
                chunk_hash = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
                if chunk_hash in self._ingested_hashes:
                    continue
                self._ingested_hashes.add(chunk_hash)
                metadata = {
                    "source_authority": doc.get("source_authority", "Unknown"),
                    "title": doc.get("title", ""),
                    "external_id": doc.get("external_id", ""),
                    "chunk_index": chunk_index,
                    "total_chunks": len(chunks),
                }
                if self.memory and hasattr(self.memory, "add"):
                    try:
                        self.memory.add(texts=[chunk], metadatas=[metadata])
                        inserted += 1
                    except Exception as exc:
                        logger.debug(f"VKB corpus ingest chunk failed: {exc}")

        logger.info(f"VKB corpus imported: {inserted} chunks from {len(docs)} documents")
        return inserted

    # ── TODO 2: 检索置信度门控阈值动态调整 ──
    def adaptive_confidence_threshold(self, query: str, context: Dict) -> float:
        """
        根据查询复杂度动态调整置信度阈值。
        简单查询适当降低阈值（更多回答），复杂/高危查询提高阈值（更多拒答）。

        Args:
            query: 用户查询
            context: {"alert_type": "phishing", "severity": "critical"}
        Returns:
            0-1之间的动态阈值

        实现要点：
        - 高危告警（severity=critical）阈值默认0.8
        - 普通查询阈值默认0.6
        - 结合检索结果数量动态调整
        """
        base_threshold = self.min_score

        severity = context.get("severity", "").lower()
        alert_type = context.get("alert_type", "").lower()

        if severity == "critical":
            base_threshold = 0.8
        elif severity == "high":
            base_threshold = 0.75
        elif severity == "medium":
            base_threshold = 0.65

        high_risk_keywords = ["攻击", "入侵", "漏洞", "后门", "勒索", "恶意", "cve", "exploit", "ransomware"]
        query_lower = query.lower()
        for keyword in high_risk_keywords:
            if keyword in query_lower:
                base_threshold = min(1.0, base_threshold + 0.05)
                break

        query_length = len(query)
        if query_length < 10:
            base_threshold = max(0.3, base_threshold - 0.1)
        elif query_length > 50:
            base_threshold = min(1.0, base_threshold + 0.05)

        evidence_count = context.get("evidence_count", 0)
        if evidence_count >= 5:
            base_threshold = max(0.3, base_threshold - 0.05)
        elif evidence_count == 0:
            base_threshold = min(1.0, base_threshold + 0.1)

        return round(max(0.1, min(1.0, base_threshold)), 2)

    # ── TODO 3: 多路召回融合策略 ──
    def hybrid_retrieval(self, query: str, k: int = 10) -> List[Dict]:
        """
        同时使用稠密检索（embedding相似度）和稀疏检索（BM25关键词），
        用RRF（Reciprocal Rank Fusion）融合排序。

        实施要点：
        1. 稠密检索：使用ChromaDB的embedding相似度
        2. 稀疏检索：使用自定义BM25（rank_bm25库）
        3. RRF公式：score = sum(1/(60 + rank_i) for each method)
        4. 取top-k返回
        """
        from rank_bm25 import BM25Okapi
        import re

        dense_results: List[Dict] = []
        sparse_results: List[Dict] = []

        if self.memory is not None:
            try:
                raw = self.memory.search(query, limit=k * 2) or []
                for r in raw:
                    if isinstance(r, dict):
                        dense_results.append({
                            "id": r.get("id", ""),
                            "text": r.get("text", ""),
                            "source": r.get("source", "local_vector_db"),
                            "score": float(r.get("score", 0.5)),
                        })
            except Exception:
                logger.debug("Dense retrieval failed", exc_info=True)

        if self.memory is not None and hasattr(self.memory, "get_all"):
            try:
                all_docs = self.memory.get_all() or []
                if all_docs:
                    tokenized_corpus = [
                        re.findall(r"\w+", str(doc.get("text", "")).lower())
                        for doc in all_docs
                    ]
                    if any(tokenized_corpus):
                        bm25 = BM25Okapi(tokenized_corpus)
                        tokenized_query = re.findall(r"\w+", query.lower())
                        if tokenized_query:
                            bm25_scores = bm25.get_scores(tokenized_query)
                            for idx, score in enumerate(bm25_scores):
                                if score > 0:
                                    doc = all_docs[idx]
                                    sparse_results.append({
                                        "id": doc.get("id", ""),
                                        "text": doc.get("text", ""),
                                        "source": doc.get("source", "bm25_search"),
                                        "score": float(score),
                                    })
                            sparse_results.sort(key=lambda x: x["score"], reverse=True)
            except Exception:
                logger.debug("Sparse retrieval failed", exc_info=True)

        dense_ranks = {item["id"]: idx + 1 for idx, item in enumerate(dense_results)}
        sparse_ranks = {item["id"]: idx + 1 for idx, item in enumerate(sparse_results)}

        all_ids = set(dense_ranks.keys()) | set(sparse_ranks.keys())
        rrf_scores = {}
        for doc_id in all_ids:
            dense_rank = dense_ranks.get(doc_id, k * 2 + 1)
            sparse_rank = sparse_ranks.get(doc_id, k * 2 + 1)
            rrf_scores[doc_id] = 1 / (60 + dense_rank) + 1 / (60 + sparse_rank)

        combined_results = []
        for doc_id in sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True):
            dense_item = next((d for d in dense_results if d["id"] == doc_id), None)
            sparse_item = next((s for s in sparse_results if s["id"] == doc_id), None)
            item = dense_item or sparse_item or {}
            combined_results.append({
                "id": doc_id,
                "text": item.get("text", ""),
                "source": item.get("source", "hybrid"),
                "score": rrf_scores[doc_id],
                "score_components": {
                    "dense_rank": dense_ranks.get(doc_id, 0),
                    "sparse_rank": sparse_ranks.get(doc_id, 0),
                    "rrf_score": rrf_scores[doc_id],
                },
            })

        return combined_results[:k]

    def _chunk(self, text: str, size: int, overlap: int) -> List[str]:
        """文本分块工具方法。"""
        if len(text) <= size:
            return [text]
        step = max(1, size - overlap)
        chunks = []
        for start in range(0, len(text), step):
            chunk = text[start:start + size]
            if not chunk:
                continue
            chunks.append(chunk)
            if start + size >= len(text):
                break
        return chunks

    def retrieve_and_rerank(
        self, query: str, registry: Any, top_k: int = 4
    ) -> List[Dict[str, Any]]:
        """三路融合重排序检索：BM25 词频 + 向量空间 + VKB 权威漏洞知识库。

        权威源（VKB）默认初始得分较高，参与统一排序；失败时静默退化为纯本地检索。
        """
        alpha, beta, gamma = self._normalized_weights()

        # 1. 本地向量库初步检索
        local_hits: List[Dict[str, Any]] = []
        if self.memory is not None:
            try:
                raw = self.memory.search(query, limit=top_k * 2) or []
                for r in raw:
                    if isinstance(r, dict):
                        local_hits.append({
                            "text": r.get("text", ""),
                            "source": r.get("source", "local_vector_db"),
                            "vector_score": float(r.get("score", 0.5)),
                        })
            except Exception:  # noqa: BLE001
                logger.debug("local vector search failed", exc_info=True)

        # 2. 外部 VKB 权威漏洞知识库检索（高可信来源）
        vkb_hits: List[Dict[str, Any]] = []
        if registry is not None and hasattr(registry, "execute_skill"):
            try:
                vkb_resp = registry.execute_skill(
                    "vkb_retrieve", {"query": query, "top_k": 3}, context={}
                )
                hits = (vkb_resp.get("data") or {}).get("hits") or vkb_resp.get("hits") or []
                for h in hits:
                    if not isinstance(h, dict):
                        continue
                    ident = h.get("id") or h.get("cve") or "vkb_entry"
                    vkb_hits.append({
                        "text": h.get("text") or h.get("desc") or h.get("description") or "",
                        "source": f"VKB::{ident}",
                        "vector_score": float(h.get("score", 0.85)),  # 权威源初始高分
                    })
            except Exception:  # noqa: BLE001
                logger.debug("vkb_retrieve augment skipped", exc_info=True)

        # 合并候选集
        candidates = local_hits + vkb_hits

        # 3. 三路加权算分与过滤 (α·BM25 + β·向量 + γ·CrossEncoder近似)
        reranked: List[Dict[str, Any]] = []
        for cand in candidates:
            bm25 = self.compute_bm25_similarity(query, cand["text"])
            vec = max(0.0, min(1.0, cand.get("vector_score", 0.5)))
            # 仿 CrossEncoder：短语级交互得分（向量 + 词频加权）
            cross = 0.8 * vec + 0.2 * bm25
            final_score = alpha * bm25 + beta * vec + gamma * cross

            if final_score >= self.min_score:
                reranked.append({
                    "text": cand["text"],
                    "source": cand["source"],
                    "score": round(final_score, 6),
                    "score_components": {
                        "bm25": round(bm25, 6),
                        "embedding": round(vec, 6),
                        "cross_encoder": round(cross, 6),
                    },
                })

        reranked.sort(key=lambda x: x["score"], reverse=True)
        # 去重（相同 source + 文本前64字）
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for item in reranked:
            key = (item.get("source", ""), (item.get("text", "") or "")[:64])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:top_k]

    def grounded_answer_loop(
        self,
        llm_router: Any,
        query: str,
        registry: Any,
    ) -> Dict[str, Any]:
        """防幻觉生成总入口：检索门控 → 主动拒答 → 引用忠实度后置拦截。

        Steps:
          1. retrieve_and_rerank — 三路融合重排序
          2. 置信门控拒答 — 证据不足时主动拒答（宁缺毋滥）
          3. 强制上下文角标引用生成 — 要求 LLM 每句标注来源编号
          4. CitationProcessor 后置校验 — 拦截幻觉虚构角标

        Returns:
            dict with keys:
              - answer: str
              - refused: bool
              - refusal_reason: str
              - faithfulness: float (0~1)
              - citations: List[dict]（检索到的证据列表）
        """
        from nexus.cang.citation_processor import CitationProcessor

        # 步骤 1: 检索与重排序
        evidences = self.retrieve_and_rerank(query, registry)

        # 步骤 2: 置信门控主动拒答 — 所有证据均低于置信阈值时直接拒答
        if not evidences:
            return {
                "answer": (
                    "【鉴真防幻觉安全守卫】检测到当前本地与权威漏洞知识底座中"
                    "关于此问题的置信证据不足（θ_retrieval 门控触发）。"
                    "系统高安全级拒答，避免幻觉臆测。"
                ),
                "refused": True,
                "refusal_reason": (
                    f"No retrieved evidence passed the retrieval score gate "
                    f"(θ_retrieval={self.min_score:.2f})."
                ),
                "faithfulness": 0.0,
                "citations": [],
            }

        # 步骤 3: 强制上下文角标引用生成（要求 LLM 每句标注来源编号）
        context_str = "\n".join([
            f"[证据 {idx + 1}] (来源: {e['source']}): {e['text']}"
            for idx, e in enumerate(evidences)
        ])
        prompt = (
            "你必须仅根据以下给出的确凿证据回答用户的研判请求。严禁臆造或发散。\n"
            "你回答中的每一句事实陈述，都必须在句尾使用方括号标注其引用的证据编号，如 [1]。\n\n"
            f"【确凿证据】:\n{context_str}\n\n"
            f"【研判请求】:\n{query}"
        )

        messages = [{"role": "user", "content": prompt}]
        try:
            if hasattr(llm_router, "chat"):
                resp = llm_router.chat(messages, task="operations", temperature=0.0)
            else:
                resp = llm_router(messages)
            llm_answer = resp.get("content", "") if isinstance(resp, dict) else str(resp)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM chat failed in grounded_answer_loop: %s", exc)
            llm_answer = ""

        if not llm_answer:
            return {
                "answer": "【鉴真防幻觉安全守卫】LLM 生成失败，拒答以防幻觉。",
                "refused": True,
                "refusal_reason": "LLM returned empty response.",
                "faithfulness": 0.0,
                "citations": evidences,
            }

        # 步骤 4: 引用闭环后置校验（CitationProcessor）
        allowed_sources = [e["source"] for e in evidences]
        citation_proc = CitationProcessor(
            allowed_sources=allowed_sources,
            faithfulness_threshold=self.faithfulness_threshold,
            allow_no_citation=False,
        )
        verdict = citation_proc.post_verify_answer(llm_answer, evidences)

        if verdict.get("status") == "failed":
            return {
                "answer": (
                    "【鉴真防幻觉安全守卫】检测到大模型生成的研判报告存在幻觉"
                    "或超范围虚构引用。已拦截。"
                    f"详细原因: {verdict.get('reason', '')}"
                ),
                "refused": True,
                "refusal_reason": f"Citation verification failed: {verdict.get('reason', '')}",
                "faithfulness": float(verdict.get("faithfulness", 0.0)),
                "citations": evidences,
            }

        return {
            "answer": llm_answer,
            "refused": False,
            "refusal_reason": "",
            "faithfulness": float(verdict.get("faithfulness", 1.0)),
            "citations": evidences,
        }

    def _normalized_weights(self) -> tuple:
        weights = self.rerank_weights or (0.3, 0.3, 0.4)
        total = sum(max(0.0, float(w)) for w in weights)
        if total <= 0:
            return (0.3, 0.3, 0.4)
        return tuple(max(0.0, float(w)) / total for w in weights)


__all__ = ["SecurityRAG", "AdvancedSecurityRAG"]