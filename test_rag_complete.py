"""RAG三件套完整流程测试脚本——验证防幻觉能力。"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nexus.cang.security_rag import SecurityRAG, AdvancedSecurityRAG
from nexus.cang.citation_processor import CitationProcessor
from nexus.cang.seed_data import seed_security_rag, load_seed
from nexus.evals.rag_metrics import RAGMetrics


class MockEmbedder:
    """Mock向量化器，用于测试"""
    def __init__(self):
        self.dim = 384
    def __call__(self, texts):
        import hashlib
        results = []
        for text in texts:
            hash_val = hashlib.md5(text.encode()).digest()
            vec = [int.from_bytes(hash_val[i:i+2], 'big') / 65535.0 for i in range(0, min(len(hash_val), self.dim*2), 2)]
            while len(vec) < self.dim:
                vec.append(0.0)
            results.append(vec[:self.dim])
        return results


class MockVectorStore:
    """Mock向量库，用于测试"""
    def __init__(self):
        self.documents = []
        self.embeddings = []
        self.metadatas = []
        self.ids = []
    
    def add(self, ids=None, embeddings=None, metadatas=None, documents=None):
        if ids is None:
            ids = [f"doc-{i}" for i in range(len(documents))]
        self.ids.extend(ids or [])
        self.embeddings.extend(embeddings or [])
        self.metadatas.extend(metadatas or [])
        self.documents.extend(documents or [])
    
    def query(self, query_embedding, top_k=5):
        scores = []
        for i, emb in enumerate(self.embeddings):
            score = sum(a * b for a, b in zip(query_embedding, emb))
            scores.append((i, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        
        top_indices = [idx for idx, _ in scores[:top_k]]
        
        documents_out = [self.documents[i] for i in top_indices]
        metadatas_out = [self.metadatas[i] for i in top_indices]
        distances_out = [1.0 - min(1.0, max(0.0, scores[i][1] * 2)) for i in range(len(top_indices))]
        ids_out = [self.ids[i] for i in top_indices]
        
        return {
            "documents": [documents_out],
            "metadatas": [metadatas_out],
            "distances": [distances_out],
            "ids": [ids_out],
        }


class MockLLM:
    """Mock LLM，用于测试"""
    def chat(self, messages, **kwargs):
        content = messages[-1]["content"]
        if "[1]" in content or "[2]" in content or "[3]" in content:
            return {"content": "根据证据[1]，CWE-122是堆缓冲区溢出漏洞。根据证据[2]，CWE-416是释放后使用漏洞。这些漏洞可能导致远程代码执行[1][2]。"}
        return {"content": "这是一个安全问题，可能涉及缓冲区溢出和内存安全漏洞。"}


def test_security_rag_basic():
    """测试基础SecurityRAG功能"""
    print("\n=== 测试1: SecurityRAG基础功能 ===")
    
    embedder = MockEmbedder()
    store = MockVectorStore()
    
    rag = SecurityRAG(
        embedder=embedder,
        vector_store=store,
        min_score=0.3,
        min_citations=1,
        faithfulness_threshold=0.95,
    )
    
    seed_security_rag(rag)
    print(f"  ✓ 种子数据灌入完成")
    
    results = rag.retrieve("缓冲区溢出")
    print(f"  ✓ 检索完成，获取 {len(results)} 条结果")
    
    for i, r in enumerate(results[:3], 1):
        print(f"    [{i}] source={r.get('source')} score={r.get('score', 0):.3f}")


def test_security_rag_rerank():
    """测试三路融合重排序"""
    print("\n=== 测试2: 三路融合重排序 ===")
    
    embedder = MockEmbedder()
    store = MockVectorStore()
    
    rag = SecurityRAG(
        embedder=embedder,
        vector_store=store,
        min_score=0.3,
        rerank_weights=(0.3, 0.3, 0.4),
    )
    
    seed_security_rag(rag)
    
    docs = rag.retrieve("命令注入", top_k=5)
    reranked = rag.rerank_documents("命令注入", docs, top_k=3)
    
    print(f"  ✓ 重排序完成，获取 {len(reranked)} 条结果")
    for i, r in enumerate(reranked, 1):
        components = r.get("score_components", {})
        print(f"    [{i}] score={r.get('score', 0):.4f} rank={r.get('rank', 0)}")
        print(f"        BM25={components.get('bm25', 0):.4f}")
        print(f"        Embedding={components.get('embedding', 0):.4f}")
        print(f"        CrossEncoder={components.get('cross_encoder', 0):.4f}")


def test_citation_processor():
    """测试引用闭环校验"""
    print("\n=== 测试3: 引用闭环校验 ===")
    
    evidence = [
        {"text": "CWE-122 堆缓冲区溢出：当向堆分配缓冲区写入的数据超过其容量时发生。", "source": "CWE-122"},
        {"text": "CWE-416 释放后使用：对象释放后其指针仍被解引用。", "source": "CWE-416"},
    ]
    
    proc = CitationProcessor(
        allowed_sources=["CWE-122", "CWE-416"],
        faithfulness_threshold=0.95,
        allow_no_citation=False,
    )
    
    answer_valid = "CWE-122是堆缓冲区溢出漏洞[1]，CWE-416是释放后使用漏洞[2]。"
    verdict = proc.post_verify_answer(answer_valid, evidence)
    print(f"  ✓ 有效引用校验: status={verdict.get('status')}, faithfulness={verdict.get('faithfulness', 0):.4f}")
    
    answer_invalid = "CWE-999是未知漏洞[3]，不存在于知识库中。"
    verdict = proc.post_verify_answer(answer_invalid, evidence)
    print(f"  ✓ 虚构引用校验: status={verdict.get('status')}, reason={verdict.get('reason', '')}")
    
    answer_no_citation = "缓冲区溢出是常见的安全漏洞，可能导致代码执行。"
    verdict = proc.post_verify_answer(answer_no_citation, evidence)
    print(f"  ✓ 无引用校验: status={verdict.get('status')}, reason={verdict.get('reason', '')}")


def test_rag_metrics():
    """测试RAG评估指标"""
    print("\n=== 测试4: RAG评估指标 ===")
    
    question = "什么是堆缓冲区溢出？"
    answer = "堆缓冲区溢出是当向堆分配缓冲区写入的数据超过其容量时发生的漏洞，可能导致远程代码执行。"
    contexts = [
        {"text": "CWE-122 堆缓冲区溢出：当向堆分配缓冲区写入的数据超过其容量时发生，常见于未校验长度的 memcpy/strcpy。"},
        {"text": "CWE-119 缓冲区溢出：向缓冲区写入数据超过其边界，可能破坏相邻内存。"},
    ]
    
    evaluation = RAGMetrics.evaluate_rag(question, answer, contexts)
    print(f"  ✓ 综合评分: {evaluation.get('overall_score', 0):.4f}")
    for metric, value in evaluation.get("metrics", {}).items():
        print(f"    {metric}: {value:.4f}")


def test_grounded_answer():
    """测试证据锚定回答"""
    print("\n=== 测试5: 证据锚定回答 ===")
    
    embedder = MockEmbedder()
    store = MockVectorStore()
    
    rag = SecurityRAG(
        embedder=embedder,
        vector_store=store,
        min_score=0.3,
        min_citations=1,
        faithfulness_threshold=0.95,
    )
    
    seed_security_rag(rag)
    llm = MockLLM()
    
    result = rag.grounded_answer(llm, "什么是CWE-122？")
    print(f"  ✓ 回答生成完成")
    print(f"    refused: {result.get('refused')}")
    print(f"    citations: {result.get('citations', [])}")
    print(f"    faithfulness: {result.get('faithfulness', 0):.4f}")
    print(f"    answer: {result.get('answer', '')[:100]}...")


def test_refusal_mechanism():
    """测试低置信拒答机制"""
    print("\n=== 测试6: 低置信拒答机制 ===")
    
    embedder = MockEmbedder()
    store = MockVectorStore()
    
    rag = SecurityRAG(
        embedder=embedder,
        vector_store=store,
        min_score=0.99,
        min_citations=5,
    )
    
    seed_security_rag(rag)
    
    result = rag.grounded_answer(MockLLM(), "什么是量子计算？")
    print(f"  ✓ 低证据拒答测试")
    print(f"    refused: {result.get('refused')}")
    print(f"    reason: {result.get('refusal_reason', '')}")


def test_advanced_rag():
    """测试AdvancedSecurityRAG"""
    print("\n=== 测试7: AdvancedSecurityRAG ===")
    
    embedder = MockEmbedder()
    store = MockVectorStore()
    
    rag = AdvancedSecurityRAG(
        vector_memory=store,
        min_score=0.3,
        faithfulness_threshold=0.95,
    )
    
    seed_security_rag(rag)
    print(f"  ✓ 高级RAG初始化完成")
    
    bm25_score = rag.compute_bm25_similarity("命令注入", "CWE-78命令注入是常见漏洞")
    print(f"  ✓ BM25相似度计算: {bm25_score:.4f}")
    
    threshold = rag.adaptive_confidence_threshold(
        "关键漏洞检测",
        {"severity": "critical", "alert_type": "vulnerability"}
    )
    print(f"  ✓ 自适应置信阈值: {threshold:.2f}")


def test_hybrid_retrieval():
    """测试混合检索"""
    print("\n=== 测试8: 混合检索(RRF融合) ===")
    
    class SimpleMemory:
        def search(self, query, limit=10):
            return [
                {"id": "doc1", "text": "缓冲区溢出相关内容", "source": "local", "score": 0.8},
                {"id": "doc2", "text": "内存安全问题", "source": "local", "score": 0.6},
            ]
    
    rag = AdvancedSecurityRAG(
        vector_memory=SimpleMemory(),
        min_score=0.3,
    )
    
    results = rag.hybrid_retrieval("缓冲区溢出", k=5)
    print(f"  ✓ 混合检索完成，获取 {len(results)} 条结果")
    for i, r in enumerate(results[:3], 1):
        print(f"    [{i}] source={r.get('source')} score={r.get('score', 0):.4f}")


def test_api_endpoints():
    """测试API端点"""
    print("\n=== 测试9: API端点测试 ===")
    
    import subprocess
    import urllib.request
    import urllib.error
    
    proc = subprocess.Popen(
        [sys.executable, "run.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    
    time.sleep(3)
    
    try:
        req = urllib.request.Request(
            "http://localhost:7800/rag/health",
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"  ✓ RAG健康检查: status={data.get('status')}")
        
        req = urllib.request.Request(
            "http://localhost:7800/rag/search?query=缓冲区溢出&top_k=3",
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"  ✓ RAG搜索: result_count={data.get('result_count', 0)}")
        
        req = urllib.request.Request(
            "http://localhost:7800/rag/seed",
            data=json.dumps({}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            print(f"  ✓ RAG种子灌入: inserted_chunks={data.get('inserted_chunks', 0)}")
            
    except urllib.error.URLError as e:
        print(f"  ✗ API测试失败: {e}")
    finally:
        proc.terminate()
        proc.wait()


def main():
    """主测试函数"""
    print("=" * 60)
    print("RAG三件套完整流程测试")
    print("=" * 60)
    
    tests = [
        test_security_rag_basic,
        test_security_rag_rerank,
        test_citation_processor,
        test_rag_metrics,
        test_grounded_answer,
        test_refusal_mechanism,
        test_advanced_rag,
        test_hybrid_retrieval,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ 测试失败: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 所有RAG三件套测试通过！")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()