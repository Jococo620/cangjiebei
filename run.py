import os
import sys
import threading
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Windows 控制台默认 GBK，无法输出 emoji，统一用 UTF-8 输出避免 UnicodeEncodeError
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

def start_ctf_mcp_server():
    """启动CTF MCP服务"""
    ctf_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "ctf_mcp_server.py")
    print(f"🎯 正在启动 CTF MCP 服务端...")
    try:
        proc = subprocess.Popen(
            [sys.executable, ctf_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "CTF_MCP_PORT": "2267"}
        )
        time.sleep(3)
        if proc.poll() is None:
            print(f"✅ CTF MCP 服务端启动成功 (端口: 2267)")
            return proc
        else:
            stdout, stderr = proc.communicate()
            print(f"❌ CTF MCP 服务端启动失败: {stderr.decode('utf-8', errors='ignore')}")
            return None
    except Exception as e:
        print(f"❌ CTF MCP 服务端启动异常: {e}")
        return None

if __name__ == "__main__":
    port = int(os.environ.get("NEXUS_PORT", "7800"))

    # 本地 sympas MCP (2266) 已废弃，sympas 工具迁移到云端 SSE MCP 6239
    ctf_proc = start_ctf_mcp_server()

    print(f"🚀 CangSight 安全运营超级智能体启动中...")
    print(f"📡 服务器端口: http://localhost:{port}")
    print(f"🌐 前端界面: http://localhost:{port}/frontend/dashboard/")
    print(f"🔧 API接口: http://localhost:{port}/run/cang")
    print(f"💡 健康检查: http://localhost:{port}/health")
    try:
        from nexus.config import get_sympas_base_url
        sympas_url = get_sympas_base_url()
    except Exception:
        sympas_url = "未配置"
    print(f"☁️  Sympas MCP服务（SSE）: {sympas_url}")
    print(f"🎯 CTF MCP服务: http://localhost:2267")
    print("=" * 60)

    from nexus.gateway.app import app
    debug = os.environ.get("NEXUS_DEBUG", "0").lower() in ("1", "true", "yes", "on")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True, use_reloader=False)