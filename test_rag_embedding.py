import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nexus.cang.rag_service import get_rag_service

print("=== RAG嵌入和检索测试 ===")

rag_service = get_rag_service()
print(f"向量库统计: {rag_service.get_collection_stats()}")

print("\n1. 测试嵌入函数:")
try:
    embeddings = rag_service._security_rag._embed_many(["CWE-122"])
    print(f"   ✓ 嵌入成功，向量维度: {len(embeddings[0])}")
except Exception as e:
    print(f"   ✗ 嵌入失败: {e}")

print("\n2. 测试直接向量化查询:")
try:
    query_embedding = rag_service._security_rag._embed_many(["CWE-122"])[0]
    raw_results = rag_service._collection.query(
        query_embeddings=[query_embedding],
        n_results=3,
        include=["documents", "metadatas", "distances"],
    )
    print(f"   ✓ 查询成功")
    print(f"   documents: {raw_results.get('documents', [])}")
    print(f"   distances: {raw_results.get('distances', [])}")
except Exception as e:
    print(f"   ✗ 查询失败: {e}")

print("\n3. 测试SecurityRAG检索:")
try:
    results = rag_service.retrieve("CWE-122", top_k=3)
    print(f"   ✓ 检索完成，结果数: {len(results)}")
    for i, r in enumerate(results):
        print(f"     {i+1}. score={r.get('score'):.4f}, source={r.get('source')}, text={r.get('text', '')[:50]}")
except Exception as e:
    print(f"   ✗ 检索失败: {e}")

print("\n4. 测试中文查询:")
try:
    results = rag_service.retrieve("堆缓冲区溢出", top_k=3)
    print(f"   ✓ 检索完成，结果数: {len(results)}")
    for i, r in enumerate(results):
        print(f"     {i+1}. score={r.get('score'):.4f}, source={r.get('source')}, text={r.get('text', '')[:50]}")
except Exception as e:
    print(f"   ✗ 检索失败: {e}")
