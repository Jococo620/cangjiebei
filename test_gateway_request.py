import requests

print("=== 检查网关发送的工具定义 ===")

response = requests.get("http://localhost:7800/skills")
data = response.json()

print("生成工具定义:")
tools = []
for skill in data.get("skills", []):
    if skill.get("danger_level") in ("safe", "medium"):
        tool = {
            "type": "function",
            "function": {
                "name": skill.get("skill_id", ""),
                "description": skill.get("description", ""),
                "parameters": {
                    "type": "object",
                    "properties": skill.get("input_schema", {}).get("properties", {}),
                    "required": skill.get("input_schema", {}).get("required", [])
                }
            }
        }
        tools.append(tool)
        print(f"\n工具: {skill.get('skill_id')}")
        print(f"描述: {skill.get('description')}")
        print(f"参数: {skill.get('input_schema', {}).get('properties', {})}")

print(f"\n工具总数: {len(tools)}")