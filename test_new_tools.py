import requests
import json

print('=== 测试新集成工具调用 ===')

test_cases = [
    {
        "name": "符号切片分析",
        "message": "对这段代码进行符号切片分析: int main() { int x = 1; int y = x + 2; return y; }",
        "mode": "security"
    },
    {
        "name": "堆内存验证",
        "message": "验证这段代码的堆内存安全性",
        "mode": "security"
    },
    {
        "name": "全量规则扫描",
        "message": "对目标进行全量安全规则扫描",
        "mode": "security"
    },
    {
        "name": "依赖漏洞扫描",
        "message": "扫描项目依赖中的CVE漏洞",
        "mode": "security"
    }
]

for i, tc in enumerate(test_cases):
    print(f"\n{'='*50}")
    print(f"测试 {i+1}: {tc['name']}")
    print(f"{'='*50}")
    try:
        r = requests.post('http://localhost:7800/agent/chat', json={
            'message': tc['message'],
            'mode': tc['mode'],
            'session_id': f'test_new_{i}'
        }, timeout=60)
        result = r.json()
        
        tool_calls = result.get('tool_calls', [])
        tool_results = result.get('tool_results', [])
        
        print(f"工具调用数量: {len(tool_calls)}")
        for call in tool_calls:
            print(f"  - 工具名称: {call.get('name')}")
            print(f"    参数: {json.dumps(call.get('args', {}), ensure_ascii=False)}")
        
        print(f"\n工具结果数量: {len(tool_results)}")
        for res in tool_results:
            print(f"  - 工具: {res.get('tool_name')}")
            print(f"    状态: {res.get('status')}")
        
        if 'answer' in result:
            print(f"\n回答摘要: {result['answer'][:300]}...")
            
    except Exception as e:
        print(f"请求失败: {e}")

print(f"\n{'='*50}")
print("新工具测试完成")
print(f"{'='*50}")
