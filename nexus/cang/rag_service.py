"""RAG服务模块：管理向量数据库连接、LLM适配器和RAG查询流程。"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from chromadb import Client, PersistentClient, Collection
from chromadb.api.types import Documents, Embeddings, Metadata

from nexus.llm.factory import get_llm_adapter, get_default_llm
from nexus.cang.security_rag import SecurityRAG, AdvancedSecurityRAG
from nexus.cang.citation_processor import CitationProcessor
from nexus.cang.seed_data import seed_security_rag, SECURITY_KB_SEED
from nexus.evals.rag_metrics import RAGMetrics

logger = logging.getLogger("nexus.cang.rag_service")

_RAG_INSTANCE: Optional["RAGService"] = None


def _create_embedding_function():
    """创建嵌入函数，优先使用ONNXMiniLM_L6_V2语义嵌入。"""
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
        embedding_function = ONNXMiniLM_L6_V2()
        logger.info("[RAG] Using ONNXMiniLM_L6_V2 embedding function (semantic)")
        return embedding_function, "ONNXMiniLM_L6_V2"
    except Exception as exc:
        logger.warning(f"[RAG] Failed to load ONNXMiniLM_L6_V2: {exc}")
    
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        
        class SentenceTransformerEmbedding:
            def __init__(self, model):
                self._model = model
            
            def __call__(self, input):
                return self._model.encode(input).tolist()
            
            def name(self):
                return "sentence_transformers"
        
        embedding_function = SentenceTransformerEmbedding(model)
        logger.info("[RAG] Using SentenceTransformer embedding function (semantic)")
        return embedding_function, "SentenceTransformer"
    except Exception as exc:
        logger.warning(f"[RAG] Failed to load SentenceTransformer: {exc}")
    
    logger.warning("[RAG] Falling back to SimpleEmbeddingFunction (hash-based, poor semantic quality)")
    
    class SimpleEmbeddingFunction:
        def __init__(self):
            self._dim = 384

        def name(self):
            return "simple_hash"

        def __call__(self, input):
            import numpy as np
            import hashlib
            results = []
            for text in input:
                text_str = str(text)
                vec = np.zeros(self._dim, dtype=np.float64)
                for i in range(self._dim):
                    seed = f"{text_str}_{i}"
                    h = hashlib.sha256(seed.encode()).digest()
                    vec[i] = int.from_bytes(h[:8], 'big') / (2**64 - 1)
                vec = (vec - vec.mean()) / (vec.std() + 1e-8)
                vec = np.nan_to_num(vec, nan=0.0, posinf=1e10, neginf=-1e10)
                results.append(vec.tolist())
            return results
    
    return SimpleEmbeddingFunction(), "SimpleEmbeddingFunction"


class RAGService:
    """统一RAG服务封装，管理向量数据库和LLM适配器。"""

    def __init__(self):
        self._client: Optional[Client] = None
        self._collection: Optional[Collection] = None
        self._llm = None
        self._security_rag: Optional[SecurityRAG] = None
        self._advanced_rag: Optional[AdvancedSecurityRAG] = None
        self._embedding_function_name = ""
        self._init_chromadb()
        self._init_llm()
        self._init_rag()

    def _get_or_reconnect_collection(self) -> Optional[Collection]:
        """获取集合，必要时重新连接。"""
        if self._client is None:
            persist_dir = os.environ.get("CHROMA_PERSIST_DIR", "")
            if not persist_dir:
                _project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                persist_dir = os.path.join(_project_root, ".nexus", "chroma")
            os.makedirs(persist_dir, exist_ok=True)
            self._client = PersistentClient(path=persist_dir)

        if self._collection is None:
            embedding_function, self._embedding_function_name = _create_embedding_function()
            self._collection = self._client.get_or_create_collection(
                name="security_knowledge_base",
                metadata={"description": "Security RAG knowledge base (CWE/ATT&CK/Regulatory)"},
                embedding_function=embedding_function,
            )

        return self._collection

    def _recreate_collection(self):
        """重新创建集合（用于切换嵌入函数或修复问题）。"""
        if self._client:
            try:
                self._client.delete_collection('security_knowledge_base')
                logger.info("[RAG] Deleted existing collection")
            except Exception:
                pass

        embedding_function, self._embedding_function_name = _create_embedding_function()
        self._collection = self._client.get_or_create_collection(
            name="security_knowledge_base",
            metadata={"description": "Security RAG knowledge base (CWE/ATT&CK/Regulatory)"},
            embedding_function=embedding_function,
        )
        logger.info(f"[RAG] Recreated collection with {self._embedding_function_name}")

    def _rebuild_chroma(self, persist_dir: str, embedding_function):
        """HNSW索引损坏时，删除整个ChromaDB目录并重建。"""
        import shutil
        try:
            self._client = None
            self._collection = None
            if os.path.exists(persist_dir):
                shutil.rmtree(persist_dir)
                logger.info(f"[RAG] Deleted corrupted ChromaDB directory: {persist_dir}")
            os.makedirs(persist_dir, exist_ok=True)
            self._client = PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name="security_knowledge_base",
                metadata={"description": "Security RAG knowledge base (CWE/ATT&CK/Regulatory)"},
                embedding_function=embedding_function,
            )
            logger.info(f"[RAG] ChromaDB rebuilt at {persist_dir}")
        except Exception as exc:
            logger.error(f"[RAG] Failed to rebuild ChromaDB: {exc}")

    def _init_chromadb(self):
        persist_dir = os.environ.get("CHROMA_PERSIST_DIR", "")
        if not persist_dir:
            _project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            persist_dir = os.path.join(_project_root, ".nexus", "chroma")
        os.makedirs(persist_dir, exist_ok=True)
        self._client = PersistentClient(path=persist_dir)

        embedding_function, self._embedding_function_name = _create_embedding_function()

        self._collection = self._client.get_or_create_collection(
            name="security_knowledge_base",
            metadata={"description": "Security RAG knowledge base (CWE/ATT&CK/Regulatory)"},
            embedding_function=embedding_function,
        )

        try:
            _ = self._collection.count()
            logger.info(f"[RAG] ChromaDB initialized at {persist_dir} with {self._embedding_function_name} ({self._collection.count()} docs)")
        except Exception as exc:
            if "hnsw" in str(exc).lower() or "index" in str(exc).lower():
                logger.warning(f"[RAG] HNSW index corrupted, rebuilding collection: {exc}")
                self._rebuild_chroma(persist_dir, embedding_function)
            else:
                logger.error(f"[RAG] ChromaDB init check failed: {exc}")

    def _init_llm(self):
        try:
            self._llm = get_default_llm()
            logger.info(f"[RAG] LLM adapter initialized: {self._llm.model}")
        except Exception as exc:
            logger.warning(f"[RAG] LLM initialization failed: {exc}")
            self._llm = None

    def _init_rag(self):
        class ChromaEmbedder:
            def __init__(self, collection):
                self._collection = collection

            def __call__(self, texts: List[str]) -> List[List[float]]:
                return self._collection._embedding_function(texts)

        class ChromaVectorStore:
            def __init__(self, collection):
                self._collection = collection

            def add(self, ids: List[str], embeddings: List[List[float]], metadatas: List[Dict], documents: List[str]):
                self._collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    metadatas=metadatas,
                    documents=documents,
                )

            def upsert(self, ids: List[str], embeddings: List[List[float]], metadatas: List[Dict], documents: List[str]):
                self._collection.upsert(
                    ids=ids,
                    embeddings=embeddings,
                    metadatas=metadatas,
                    documents=documents,
                )

            def query(self, query_embedding: List[float], top_k: int):
                results = self._collection.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                    include=["documents", "metadatas", "distances"],
                )
                return results

        if self._collection:
            embedder = ChromaEmbedder(self._collection)
            vector_store = ChromaVectorStore(self._collection)
            self._security_rag = SecurityRAG(
                embedder=embedder,
                vector_store=vector_store,
                min_score=0.30,
                min_citations=1,
                faithfulness_threshold=0.95,
            )

            class AdvancedRAGMemoryWrapper:
                def __init__(self, collection):
                    self._collection = collection

                def add(self, texts: List[str], metadatas: List[Dict]):
                    ids = [f"adv-{i}-{hash(t) % 1000000}" for i, t in enumerate(texts)]
                    self._collection.add(ids=ids, documents=texts, metadatas=metadatas)

                def search(self, query: str, limit: int = 10):
                    from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
                    try:
                        embed_fn = ONNXMiniLM_L6_V2()
                        query_embedding = embed_fn([query])[0]
                        results = self._collection.query(
                            query_embeddings=[query_embedding],
                            n_results=limit,
                            include=["documents", "metadatas", "distances"],
                        )
                        hits = []
                        docs = (results.get("documents") or [[]])[0]
                        metadatas = (results.get("metadatas") or [[]])[0]
                        distances = (results.get("distances") or [[]])[0]
                        ids = (results.get("ids") or [[]])[0]
                        for i, text in enumerate(docs):
                            score = max(0.0, 1.0 - float(distances[i]) / 2.0) if i < len(distances) else 0.0
                            metadata = metadatas[i] if i < len(metadatas) else {}
                            doc_id = ids[i] if i < len(ids) else f"doc-{i}"
                            hits.append({
                                "id": doc_id,
                                "text": text,
                                "source": metadata.get("source", "local_vector_db"),
                                "score": score,
                                "metadata": metadata,
                            })
                        return hits
                    except Exception:
                        return []

                def get_all(self):
                    try:
                        results = self._collection.get(include=["documents", "metadatas", "ids"])
                        docs = []
                        if results:
                            documents = results.get("documents", [])
                            metadatas = results.get("metadatas", [])
                            ids = results.get("ids", [])
                            for i, text in enumerate(documents):
                                metadata = metadatas[i] if i < len(metadatas) else {}
                                doc_id = ids[i] if i < len(ids) else f"doc-{i}"
                                docs.append({
                                    "id": doc_id,
                                    "text": text,
                                    "source": metadata.get("source", "local_vector_db"),
                                    "metadata": metadata,
                                })
                        return docs
                    except Exception:
                        return []

            memory_wrapper = AdvancedRAGMemoryWrapper(self._collection)
            self._advanced_rag = AdvancedSecurityRAG(
                vector_memory=memory_wrapper,
                min_score=0.30,
                faithfulness_threshold=0.70,
            )
            logger.info("[RAG] SecurityRAG and AdvancedSecurityRAG initialized")

    def seed_knowledge_base(self) -> int:
        """初始化安全知识库种子。"""
        if not self._security_rag:
            return 0
        try:
            count = seed_security_rag(self._security_rag, SECURITY_KB_SEED)
            logger.info(f"[RAG] Seeded {count} chunks from {len(SECURITY_KB_SEED)} documents")
            return count
        except Exception as exc:
            logger.error(f"[RAG] Failed to seed knowledge base: {exc}")
            if "does not exist" in str(exc):
                logger.info("[RAG] Reconnecting collection and retrying...")
                self._recreate_collection()
                self._init_rag()
                try:
                    count = seed_security_rag(self._security_rag, SECURITY_KB_SEED)
                    logger.info(f"[RAG] Seeded {count} chunks after reconnect")
                    return count
                except Exception as retry_exc:
                    logger.error(f"[RAG] Failed to seed after reconnect: {retry_exc}")
            return 0

    def ingest_documents(self, documents: List[Dict[str, Any]]) -> int:
        """批量导入文档到向量库。"""
        if not self._security_rag:
            return 0
        try:
            return self._security_rag.ingest(documents)
        except Exception as exc:
            logger.error(f"[RAG] Failed to ingest documents: {exc}")
            if "does not exist" in str(exc):
                self._recreate_collection()
                self._init_rag()
                try:
                    return self._security_rag.ingest(documents)
                except Exception as retry_exc:
                    logger.error(f"[RAG] Failed to ingest after reconnect: {retry_exc}")
            return 0

    def retrieve(self, query: str, top_k: int = 6) -> List[Dict[str, Any]]:
        """检索相关证据。"""
        if not self._security_rag:
            return []
        try:
            return self._security_rag.retrieve(query, top_k=top_k)
        except Exception as exc:
            if "hnsw" in str(exc).lower() or "index" in str(exc).lower():
                logger.warning(f"[RAG] HNSW error during retrieve, rebuilding: {exc}")
                persist_dir = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    ".nexus", "chroma"
                )
                embedding_function, _ = _create_embedding_function()
                self._rebuild_chroma(persist_dir, embedding_function)
                self._init_rag()
                self.seed_knowledge_base()
                try:
                    return self._security_rag.retrieve(query, top_k=top_k)
                except Exception as retry_exc:
                    logger.error(f"[RAG] Retrieve failed after rebuild: {retry_exc}")
                    return []
            logger.error(f"[RAG] Retrieve failed: {exc}")
            return []

    def retrieve_with_vkb(self, query: str, registry=None, top_k: int = 6) -> List[Dict[str, Any]]:
        """融合本地向量库与VKB权威知识库检索。"""
        if not self._security_rag:
            return []
        return self._security_rag.retrieve_with_vkb(registry, query, top_k=top_k)

    def hybrid_retrieval(self, query: str, k: int = 10) -> List[Dict[str, Any]]:
        """多路召回融合策略（稠密+稀疏+RRF）。"""
        if not self._advanced_rag:
            return []
        return self._advanced_rag.hybrid_retrieval(query, k=k)

    def grounded_answer(self, query: str, registry=None, enforce_citations: bool = True) -> Dict[str, Any]:
        """证据锚定回答：检索→重排→生成→引用校验。"""
        if not self._security_rag or not self._llm:
            return {
                "answer": "RAG服务未完全初始化，请检查LLM配置。",
                "citations": [],
                "refused": True,
                "evidence": [],
                "error": "RAG service not initialized",
            }

        return self._security_rag.grounded_answer(
            llm=self._llm,
            query=query,
            registry=registry,
            enforce_citations=enforce_citations,
        )

    def grounded_answer_loop(self, query: str, registry=None) -> Dict[str, Any]:
        """高级防幻觉生成：检索门控→主动拒答→引用忠实度后置拦截。"""
        if not self._advanced_rag or not self._llm:
            return {
                "answer": "高级RAG服务未完全初始化，请检查LLM配置。",
                "refused": True,
                "refusal_reason": "Advanced RAG service not initialized",
                "faithfulness": 0.0,
                "citations": [],
            }

        return self._advanced_rag.grounded_answer_loop(
            llm_router=self._llm,
            query=query,
            registry=registry,
        )

    def verify_citations(self, answer: str, cited_docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """引用闭环校验。"""
        processor = CitationProcessor(
            allowed_sources=[doc.get("source", "") for doc in cited_docs],
            faithfulness_threshold=0.95,
            allow_no_citation=False,
        )
        return processor.post_verify_answer(answer, cited_docs)

    def evaluate_rag(self, question: str, answer: str, contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估RAG质量指标。"""
        return RAGMetrics.evaluate_rag(question, answer, contexts)

    def get_collection_stats(self) -> Dict[str, Any]:
        """获取向量库统计信息。"""
        if not self._collection:
            return {"error": "Collection not initialized"}
        return {
            "count": self._collection.count(),
            "name": self._collection.name,
            "metadata": self._collection.metadata,
        }

    def import_vkb_corpus(self, source_path: str, format: str = "jsonl") -> int:
        """导入VKB权威知识库语料。"""
        if not self._advanced_rag:
            return 0
        return self._advanced_rag.import_vkb_corpus(source_path, format=format)


def get_rag_service() -> RAGService:
    """获取全局RAG服务实例（单例）。"""
    global _RAG_INSTANCE
    if _RAG_INSTANCE is None:
        _RAG_INSTANCE = RAGService()
    return _RAG_INSTANCE


def init_rag_service():
    """初始化RAG服务并加载知识库种子。"""
    service = get_rag_service()
    service.seed_knowledge_base()


__all__ = ["RAGService", "get_rag_service", "init_rag_service"]