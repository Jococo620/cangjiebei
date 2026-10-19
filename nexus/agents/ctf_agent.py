"""CTF智能体 - LLM驱动的自适应CTF攻击流程
实现自适应攻击规划：信息收集→LLM分析→漏洞检测→LLM决策→漏洞利用→Flag提取
集成Sympas安全工具链和本地CTF MCP工具链
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("ctf_agent")

CTF_MCP_URL = "http://127.0.0.1:2267"


def _sympas_sse_url() -> str:
    """SymPas SSE MCP 地址，由 SYMPAS_MCP_URL / SYMPAS_MCP_HOST 等环境变量驱动。"""
    from nexus.config import get_sympas_base_url, get_sympas_token

    base = get_sympas_base_url().rstrip("/")
    token = get_sympas_token()
    return f"{base}/sse?api_key={token}" if token else f"{base}/sse"

FLAG_PATTERNS = [
    r"flag\{.*?\}", r"FLAG\{.*?\}", r"ctf\{.*?\}", r"CTF\{.*?\}",
    r"key\{.*?\}", r"secret\{.*?\}", r"token\{.*?\}",
]

LLM_SYSTEM_PROMPT = """你是鉴真CTF智能体，专精CTF竞赛攻防。你将基于工具调用结果做出自适应决策。

可用工具类别：
- 侦察：port_scan(端口扫描), dir_brute(目录爆破), http_request(HTTP请求), service_fingerprint(服务指纹), dns_info(DNS信息), sensitive_files(敏感文件)
- 漏洞检测：sql_inject(SQLi检测), xss_test(XSS检测), upload_test(上传检测), ssrf_test(SSRF检测), lfi_rfi_test(LFI/RFI检测), command_inject(命令注入检测)
- 利用：exploit_sqli(SQLi利用), http_request(通用请求), find_flag(Flag搜索)
- 辅助：encode_decode(编解码), crypto_analysis(密码分析), hash_crack(Hash破解), jwt_analysis(JWT分析), binary_analysis(二进制分析), stego_analysis(隐写分析)

输出格式：JSON
{
  "analysis": "当前态势分析",
  "next_action": "tool_name 或 'complete'",
  "action_params": {},
  "reasoning": "为什么选择这个动作"
}

决策原则：
1. 先侦察（端口扫描→目录爆破→指纹识别），再针对性检测
2. 发现漏洞后立即利用
3. 每个响应都检查是否包含flag
4. 如果当前方向无果，切换策略
5. 找到flag后标记complete
"""


class CTFAgent:
    """LLM驱动的CTF竞赛智能体"""

    def __init__(self, event_sink=None):
        self.event_sink = event_sink
        self.tool_trace = []
        self.context = {
            "target_url": "",
            "open_ports": [],
            "discovered_paths": [],
            "server_info": {},
            "technologies": [],
            "vulnerabilities": [],
            "flags_found": [],
            "vkb_knowledge": [],
        }
        self._llm_config = None

    def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        if callable(self.event_sink):
            self.event_sink(event_type, data)
        logger.info(f"[CTF Agent] {event_type}: {json.dumps(data)[:200]}")

    def _init_llm(self) -> Dict[str, Any]:
        """加载LLM配置"""
        if self._llm_config is not None:
            return self._llm_config
        try:
            import os
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                ".nexus", "llm_config.json"
            )
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    self._llm_config = json.load(f)
                    return self._llm_config
        except Exception as e:
            logger.warning(f"LLM config load failed: {e}")
        return {}

    def _llm_chat(self, messages: List[Dict]) -> str:
        """调用LLM"""
        config = self._init_llm()
        if not config:
            return ""
        api_key = config.get("api_key", "")
        base_url = config.get("base_url", "")
        model = config.get("model", "deepseek-chat")
        if not api_key or not base_url:
            return ""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 800,
            }
            resp = requests.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            logger.error(f"LLM API error: {resp.status_code}")
            return ""
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return ""

    def _call_ctf_mcp(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            url = f"{CTF_MCP_URL}{endpoint}"
            resp = requests.post(url, json=data, timeout=30)
            return resp.json()
        except Exception as exc:
            logger.error(f"CTF MCP call failed: {endpoint} - {exc}")
            return {"success": False, "error": str(exc)}

    def _call_sympas(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from nexus.adapters.sse_mcp_client import call_sse_mcp
            result = call_sse_mcp(
                sse_url=_sympas_sse_url(),
                method="tools/call",
                params={"name": tool_name, "arguments": data},
                timeout=60,
            )
            return result
        except Exception as exc:
            logger.warning(f"Sympas tool {tool_name} call failed: {exc}")
            return {"success": False, "error": str(exc)}

    def _find_flags_in_text(self, text: str) -> List[str]:
        """多格式flag搜索"""
        flags = []
        for pattern in FLAG_PATTERNS:
            flags.extend(re.findall(pattern, text, re.IGNORECASE))
        return list(set(flags))

    def _llm_decide_action(self, history: List[Dict]) -> Dict[str, Any]:
        """LLM决策下一步动作"""
        context_str = json.dumps(self.context, ensure_ascii=False, default=str)[:3000]
        history_str = json.dumps(history[-10:], ensure_ascii=False, default=str)[:3000]

        messages = [
            {"role": "system", "content": LLM_SYSTEM_PROMPT},
            {"role": "user", "content": f"当前上下文:\n{context_str}\n\n工具执行历史(最近10步):\n{history_str}\n\n请决策下一步。"},
        ]
        resp = self._llm_chat(messages)
        if not resp:
            return {"next_action": "", "reasoning": "LLM不可用，使用默认流程"}
        try:
            start = resp.find("{")
            end = resp.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(resp[start:end])
        except Exception:
            pass
        return {"next_action": "", "reasoning": f"LLM输出解析失败: {resp[:200]}"}

    def run_ctf_mission(self, target_url: str) -> Dict[str, Any]:
        """LLM驱动的自适应CTF任务"""
        self.tool_trace = []
        self.context = {
            "target_url": target_url,
            "open_ports": [],
            "discovered_paths": [],
            "server_info": {},
            "technologies": [],
            "vulnerabilities": [],
            "flags_found": [],
            "vkb_knowledge": [],
        }
        self._emit("ctf_mission_started", {"target_url": target_url})
        logger.info(f"[CTF] Starting LLM-driven mission for: {target_url}")

        history = []
        max_steps = 20
        llm_available = bool(self._init_llm())

        # 固定Phase1: 信息收集（必做）
        self._emit("phase_start", {"phase": "reconnaissance", "description": "信息收集阶段"})
        self._reconnaissance(target_url)
        history.append({"step": "reconnaissance", "result": "completed", "context": self.context})

        # 自适应Phase2+: LLM决策循环
        if llm_available:
            self._emit("phase_start", {"phase": "adaptive_exploitation", "description": "LLM驱动的自适应攻击"})
            for step_num in range(max_steps):
                decision = self._llm_decide_action(history)
                action = decision.get("next_action", "")
                reasoning = decision.get("reasoning", "")
                self._emit("llm_decision", {
                    "step": step_num + 1,
                    "action": action,
                    "reasoning": reasoning,
                    "analysis": decision.get("analysis", "")
                })

                if action == "complete" or not action:
                    if self.context["flags_found"]:
                        self._emit("mission_complete", {"reason": "Flag已找到", "flags": self.context["flags_found"]})
                        break
                    elif step_num >= 3:
                        self._emit("mission_complete", {"reason": "LLM判断无更多可探索方向"})
                        break
                    continue

                result = self._execute_tool(action, decision.get("action_params", {}), target_url)
                history.append({
                    "step": step_num + 1,
                    "tool": action,
                    "result": result.get("summary", ""),
                    "flags": result.get("flags_found", [])
                })

                if result.get("flags_found"):
                    self.context["flags_found"].extend(result["flags_found"])
                    self._emit("flag_found", {"flags": result["flags_found"]})
                    break

                if step_num >= max_steps - 1:
                    self._emit("mission_complete", {"reason": f"达到最大步数({max_steps})"})
        else:
            # LLM不可用时回退到固定流程
            self._emit("phase_start", {"phase": "fallback_fixed_pipeline", "description": "LLM不可用，使用固定流程"})
            self._fallback_scan_and_exploit(target_url)

        # 生成报告
        final_result = {
            "target_url": target_url,
            "phase": "success" if self.context["flags_found"] else "completed",
            "open_ports": self.context["open_ports"],
            "discovered_paths": self.context["discovered_paths"],
            "server_info": self.context["server_info"],
            "technologies": self.context["technologies"],
            "vulnerabilities": self.context["vulnerabilities"],
            "flags_found": list(set(self.context["flags_found"])),
            "vkb_knowledge": self.context["vkb_knowledge"],
            "tool_execution_trace": self.tool_trace,
            "total_steps": len(history),
            "llm_driven": llm_available,
        }
        self._emit("ctf_mission_completed", final_result)
        logger.info(f"[CTF] Mission completed: {final_result['phase']}, flags: {final_result['flags_found']}")
        return final_result

    def _reconnaissance(self, target_url: str) -> None:
        """信息收集阶段（固定执行）"""
        parsed_url = re.match(r"https?://([^:/]+)(?::(\d+))?", target_url)
        if parsed_url:
            host = parsed_url.group(1)
            port = int(parsed_url.group(2)) if parsed_url.group(2) else (443 if "https" in target_url else 80)

            self._emit("tool_call", {"tool": "port_scan", "action": f"端口扫描 {host}"})
            port_result = self._call_ctf_mcp("/ctf/port_scan", {
                "host": host, "ports": [21, 22, 80, 443, 8080, 8443, 3306, 5432, 6379, 8888]
            })
            self.tool_trace.append({"tool": "port_scan", "description": f"端口扫描 {host}",
                "result": "success" if port_result.get("success") else "failed"})
            if port_result.get("success"):
                self.context["open_ports"] = port_result.get("open_ports", [])

        self._emit("tool_call", {"tool": "dir_brute", "action": f"目录爆破 {target_url}"})
        dir_result = self._call_ctf_mcp("/ctf/dir_brute", {"url": target_url})
        self.tool_trace.append({"tool": "dir_brute", "description": f"目录爆破 {target_url}",
            "result": "success" if dir_result.get("success") else "failed"})
        if dir_result.get("success"):
            self.context["discovered_paths"] = dir_result.get("found_paths", [])

        self._emit("tool_call", {"tool": "http_request", "action": f"获取首页 {target_url}"})
        http_result = self._call_ctf_mcp("/ctf/http_request", {"method": "GET", "url": target_url})
        self.tool_trace.append({"tool": "http_request", "description": f"获取首页 {target_url}",
            "result": "success" if http_result.get("success") else "failed"})
        if http_result.get("success"):
            self.context["server_info"] = {
                "status_code": http_result.get("status_code"),
                "server": http_result.get("headers", {}).get("Server", ""),
                "content_length": http_result.get("content_length")
            }
            content = http_result.get("text", "")
            tech_patterns = {"PHP": r"\.php|\?php|<\?php", "Python": r"Flask|Django|werkzeug",
                "Node.js": r"Express|Node", "Apache": r"Apache", "Nginx": r"Nginx",
                "MySQL": r"MySQL", "SQLite": r"SQLite", "PostgreSQL": r"PostgreSQL"}
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    self.context["technologies"].append(tech)
            flags = self._find_flags_in_text(content)
            if flags:
                self.context["flags_found"].extend(flags)
                self._emit("flag_found", {"flags": flags, "source": "首页内容"})

        # 敏感文件扫描
        self._emit("tool_call", {"tool": "sensitive_files", "action": "敏感文件扫描"})
        sens_result = self._call_ctf_mcp("/ctf/sensitive_files", {"url": target_url})
        self.tool_trace.append({"tool": "sensitive_files", "description": "敏感文件扫描",
            "result": "success" if sens_result.get("success") else "failed"})
        if sens_result.get("success"):
            for found in sens_result.get("found_files", []):
                flags = self._find_flags_in_text(found.get("content", ""))
                if flags:
                    self.context["flags_found"].extend(flags)
                    self._emit("flag_found", {"flags": flags, "source": f"敏感文件 {found.get('path')}"})

        # RAG知识库检索
        tech_keywords = " ".join(self.context["technologies"]) + " " + self.context["server_info"].get("server", "")
        if tech_keywords.strip():
            self._emit("tool_call", {"tool": "vkb_retrieve", "action": f"检索漏洞知识库: {tech_keywords}"})
            vkb_result = self._call_sympas("vkb_retrieve", {"query": tech_keywords.strip()})
            self.tool_trace.append({"tool": "vkb_retrieve", "description": f"检索漏洞知识库",
                "result": "success" if vkb_result.get("success") else "failed"})
            if vkb_result.get("success"):
                self.context["vkb_knowledge"] = vkb_result.get("results", [])

    def _execute_tool(self, tool_name: str, params: Dict[str, Any], target_url: str) -> Dict[str, Any]:
        """执行LLM决策的工具"""
        endpoint_map = {
            "port_scan": "/ctf/port_scan",
            "dir_brute": "/ctf/dir_brute",
            "sql_inject": "/ctf/sql_inject",
            "xss_test": "/ctf/xss_test",
            "upload_test": "/ctf/upload_test",
            "ssrf_test": "/ctf/ssrf_test",
            "lfi_rfi_test": "/ctf/lfi_rfi_test",
            "command_inject": "/ctf/command_inject",
            "http_request": "/ctf/http_request",
            "find_flag": "/ctf/find_flag",
            "exploit_sqli": "/ctf/exploit_sqli",
            "sensitive_files": "/ctf/sensitive_files",
            "service_fingerprint": "/ctf/service_fingerprint",
            "dns_info": "/ctf/dns_info",
            "encode_decode": "/ctf/encode_decode",
            "crypto_analysis": "/ctf/crypto_analysis",
            "hash_crack": "/ctf/hash_crack",
            "jwt_analysis": "/ctf/jwt_analysis",
            "binary_analysis": "/ctf/binary_analysis",
            "stego_analysis": "/ctf/stego_analysis",
        }

        endpoint = endpoint_map.get(tool_name)
        if not endpoint:
            return {"summary": f"未知工具: {tool_name}"}

        if "url" not in params and tool_name in ("sql_inject", "xss_test", "upload_test", "ssrf_test",
            "lfi_rfi_test", "command_inject", "http_request", "sensitive_files", "exploit_sqli"):
            params["url"] = target_url
        if "host" not in params and tool_name == "port_scan":
            parsed = re.match(r"https?://([^:/]+)", target_url)
            if parsed:
                params["host"] = parsed.group(1)
        if "text" not in params and tool_name == "find_flag":
            params["text"] = json.dumps(self.context, ensure_ascii=False, default=str)

        self._emit("tool_call", {"tool": tool_name, "action": f"LLM决策执行 {tool_name}", "params": params})
        result = self._call_ctf_mcp(endpoint, params)
        self.tool_trace.append({
            "tool": tool_name,
            "description": f"LLM决策执行 {tool_name}",
            "result": "success" if result.get("success") else "failed",
            "params": params,
        })

        flags = []
        result_text = json.dumps(result, ensure_ascii=False, default=str)
        flags = self._find_flags_in_text(result_text)
        if flags:
            self.context["flags_found"].extend(flags)
            self._emit("flag_found", {"flags": flags, "source": tool_name})

        if result.get("vulnerabilities"):
            for vuln in result["vulnerabilities"]:
                vuln["source_tool"] = tool_name
                self.context["vulnerabilities"].append(vuln)

        return {"summary": f"{tool_name} executed", "flags_found": flags, "raw": result}

    def _fallback_scan_and_exploit(self, target_url: str) -> None:
        """LLM不可用时的固定扫描流程"""
        self._emit("phase_start", {"phase": "vulnerability_scanning", "description": "漏洞扫描"})
        discovered = self.context.get("discovered_paths", [])
        interesting = [p for p in discovered if p.get("status_code") in [200, 301, 302]]

        default_params = {
            "/users": {"id": "1"}, "/api/search": {"q": "test"}, "/article": {"id": "1"},
            "/products": {"category": "test"}, "/test/sqli": {"user": "admin"}, "/search": {"q": "test"},
        }

        for path_info in interesting[:8]:
            url = path_info["url"]
            path = path_info["path"]
            params = {}
            if "?" in url:
                qs = url.split("?")[1]
                for pair in qs.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[k] = v
            elif path in default_params:
                params = default_params[path]

            if params:
                self._emit("tool_call", {"tool": "sql_inject", "action": f"SQLi检测 {url}"})
                sqli = self._call_ctf_mcp("/ctf/sql_inject", {"url": url.split("?")[0], "params": params})
                self.tool_trace.append({"tool": "sql_inject", "description": f"SQLi检测 {url}",
                    "result": "success" if sqli.get("success") else "failed"})
                if sqli.get("vulnerabilities"):
                    self.context["vulnerabilities"].extend([{
                        "type": "SQL Injection", "url": url, "cwe": "CWE-89", "severity": "critical",
                        "params": sqli.get("vulnerable_params", []), "details": sqli.get("vulnerabilities", [])
                    }])
                    self._emit("vulnerability_found", {"type": "SQL Injection", "url": url})
                    for vp in sqli.get("vulnerable_params", []):
                        self._emit("tool_call", {"tool": "exploit_sqli", "action": f"SQLi利用 {url} param={vp}"})
                        exploit = self._call_ctf_mcp("/ctf/exploit_sqli", {
                            "url": url.split("?")[0], "param": vp, "technique": "union"
                        })
                        self.tool_trace.append({"tool": "exploit_sqli", "description": f"SQLi利用 {url}",
                            "result": "success" if exploit.get("success") else "failed"})
                        if exploit.get("flags_found"):
                            self.context["flags_found"].extend(exploit["flags_found"])
                            self._emit("flag_found", {"flags": exploit["flags_found"], "source": "exploit_sqli"})

                self._emit("tool_call", {"tool": "lfi_rfi_test", "action": f"LFI检测 {url}"})
                lfi = self._call_ctf_mcp("/ctf/lfi_rfi_test", {"url": url.split("?")[0], "params": params})
                self.tool_trace.append({"tool": "lfi_rfi_test", "description": f"LFI检测 {url}",
                    "result": "success" if lfi.get("success") else "failed"})
                if lfi.get("vulnerabilities"):
                    self.context["vulnerabilities"].extend([{
                        "type": "LFI/RFI", "url": url, "cwe": "CWE-22", "severity": "high",
                        "details": lfi.get("vulnerabilities", [])
                    }])
                    self._emit("vulnerability_found", {"type": "LFI/RFI", "url": url})

                self._emit("tool_call", {"tool": "command_inject", "action": f"命令注入检测 {url}"})
                cmd = self._call_ctf_mcp("/ctf/command_inject", {"url": url.split("?")[0], "params": params})
                self.tool_trace.append({"tool": "command_inject", "description": f"命令注入检测 {url}",
                    "result": "success" if cmd.get("success") else "failed"})
                if cmd.get("vulnerabilities"):
                    self.context["vulnerabilities"].extend([{
                        "type": "Command Injection", "url": url, "cwe": "CWE-78", "severity": "critical",
                        "details": cmd.get("vulnerabilities", [])
                    }])
                    self._emit("vulnerability_found", {"type": "Command Injection", "url": url})

            if "upload" in path.lower():
                self._emit("tool_call", {"tool": "upload_test", "action": f"上传检测 {url}"})
                upl = self._call_ctf_mcp("/ctf/upload_test", {"url": url})
                self.tool_trace.append({"tool": "upload_test", "description": f"上传检测 {url}",
                    "result": "success" if upl.get("success") else "failed"})
                if upl.get("is_vulnerable"):
                    self.context["vulnerabilities"].append({
                        "type": "File Upload", "url": url, "cwe": "CWE-434", "severity": "high",
                        "details": upl.get("vulnerable_files", [])
                    })
                    self._emit("vulnerability_found", {"type": "File Upload", "url": url})

            self._emit("tool_call", {"tool": "http_request", "action": f"获取内容 {url}"})
            content = self._call_ctf_mcp("/ctf/http_request", {"method": "GET", "url": url})
            self.tool_trace.append({"tool": "http_request", "description": f"获取内容 {url}",
                "result": "success" if content.get("success") else "failed"})
            if content.get("text"):
                flags = self._find_flags_in_text(content["text"])
                if flags:
                    self.context["flags_found"].extend(flags)
                    self._emit("flag_found", {"flags": flags, "source": url})

    def analyze_ctf_challenge(self, challenge_description: str) -> Dict[str, Any]:
        """LLM驱动的CTF题目分析"""
        self._emit("analyze_challenge", {"description": challenge_description})
        logger.info(f"[CTF] Analyzing challenge with LLM: {challenge_description[:100]}")

        messages = [
            {"role": "system", "content": "你是CTF竞赛分析专家。分析题目描述，识别漏洞类型并制定攻击计划。输出JSON格式。"},
            {"role": "user", "content": f"分析以下CTF题目并制定攻击计划:\n{challenge_description}\n\n输出JSON: {{\"identified_types\": [...], \"attack_plan\": [...], \"suggested_tools\": [...], \"difficulty\": \"easy/medium/hard\"}}"},
        ]
        resp = self._llm_chat(messages)

        if resp:
            try:
                start = resp.find("{")
                end = resp.rfind("}") + 1
                if start >= 0 and end > start:
                    result = json.loads(resp[start:end])
                    result["llm_driven"] = True
                    self._emit("analysis_complete", result)
                    return result
            except Exception:
                pass

        # 回退到正则匹配
        patterns = {
            "sql_injection": [r"sql注入", r"SQL注入", r"database", r"login", r"查询", r"union"],
            "xss": [r"xss", r"XSS", r"跨站", r"脚本", r"script"],
            "file_upload": [r"上传", r"upload", r"文件上传"],
            "ssrf": [r"ssrf", r"SSRF", r"服务器端请求"],
            "lfi": [r"文件读取", r"路径遍历", r"include", r"\.\./"],
            "rce": [r"命令执行", r"远程代码", r"RCE", r"shell"],
            "crypto": [r"加密", r"crypto", r"解密", r"hash"],
            "web": [r"web", r"Web", r"网站", r"http"],
        }

        identified = []
        for vtype, keywords in patterns.items():
            for kw in keywords:
                if re.search(kw, challenge_description, re.IGNORECASE):
                    identified.append(vtype)
                    break

        plan = ["1. 信息收集：端口扫描、目录爆破", "2. 漏洞扫描：针对性检测",
                "3. 漏洞利用：根据结果利用", "4. Flag提取"]
        for t in identified:
            if t == "sql_injection":
                plan.append("🔍 重点关注：SQL注入，尝试UNION注入")
            elif t == "xss":
                plan.append("🔍 重点关注：XSS漏洞")
            elif t == "file_upload":
                plan.append("🔍 重点关注：文件上传，尝试Webshell")
            elif t == "rce":
                plan.append("🔍 重点关注：命令执行")
            elif t == "crypto":
                plan.append("🔍 重点关注：密码学分析")

        result = {
            "challenge_description": challenge_description,
            "identified_types": identified,
            "attack_plan": plan,
            "llm_driven": False,
        }
        self._emit("analysis_complete", result)
        return result
