import requests
import json

BASE_URL = "http://localhost:7800"

print('=== 测试智能体对话功能 ===')

test_cases = [
    {
        "name": "CTF模式 - 端口扫描",
        "data": {
            "message": "扫描目标 http://192.168.1.1 的端口",
            "mode": "ctf",
            "session_id": "test_ctf_001"
        }
    },
    {
        "name": "安全事件模式 - 代码漏洞分析",
        "data": {
            "message": "分析这段代码的安全漏洞: void func(char* input) { char buf[10]; strcpy(buf, input); }",
            "mode": "security",
            "session_id": "test_sec_001"
        }
    },
    {
        "name": "新工具调用 - 符号切片",
        "data": {
            "message": "对项目进行符号切片分析",
            "mode": "security",
            "session_id": "test_newtool_001"
        }
    },
    {
        "name": "通用模式 - 漏洞知识查询",
        "data": {
            "message": "什么是SQL注入漏洞？",
            "mode": "general",
            "session_id": "test_gen_001"
        }
    }
]

for test_case in test_cases:
    print(f"\n{'='*50}")
    print(f"测试: {test_case['name']}")
    print(f"{'='*50}")
    try:
        r = requests.post(f"{BASE_URL}/agent/chat", json=test_case['data'], timeout=60)
        print(f"状态码: {r.status_code}")
        if r.status_code == 200:
            result = r.json()
            print(f"响应类型: {result.get('type', 'unknown')}")
            if 'content' in result:
                content = result['content']
                if isinstance(content, str):
                    print(f"响应内容: {content[:500]}...")
                else:
                    print(f"响应内容: {json.dumps(content, ensure_ascii=False)[:500]}...")
            elif 'tool_calls' in result:
                tool_calls = result['tool_calls']
                print(f"工具调用数量: {len(tool_calls)}")
                for tc in tool_calls:
                    print(f"  - 工具: {tc.get('tool_name')}")
                    print(f"    参数: {json.dumps(tc.get('arguments', {}), ensure_ascii=False)}")
        else:
            print(f"错误响应: {r.text[:200]}")
    except Exception as e:
        print(f"请求失败: {e}")

print(f"\n{'='*50}")
print("智能体对话测试完成")
print(f"{'='*50}")
