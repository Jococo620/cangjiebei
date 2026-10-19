"""SSE MCP 客户端适配器（纯 socket 实现，绕过本地代理）

标准 MCP SSE 协议：
1. 客户端 GET /sse → SSE 长连接
2. 服务器推送 endpoint 事件（相对路径）
3. 客户端 POST {endpoint} JSON-RPC → 202 Accepted
4. 服务器通过 SSE 流推送 message 事件返回响应

用 socket 直连避免本地 HTTP 代理（Clash）拦截 SSE 长连接。
"""

import json
import logging
import socket
import threading
import time
from queue import Queue, Empty
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("nexus.adapters.sse_mcp")


class SSEMCPClient:
    """MCP SSE 客户端（纯 socket + requests POST）

    用法:
        client = SSEMCPClient("http://host:6239/sse?api_key=xxx")
        client.connect()
        result = client.call("tools/list", {})
        client.close()
    """

    def __init__(self, sse_url: str, timeout: int = 60):
        self.sse_url = sse_url
        self.timeout = timeout
        self.endpoint: Optional[str] = None
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._response_queue: Queue = Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        parsed = urlparse(sse_url)
        self._host = parsed.hostname
        self._port = parsed.port or 80
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._sse_path = parsed.path or "/"
        if parsed.query:
            self._sse_path = f"{self._sse_path}?{parsed.query}"

    def connect(self) -> bool:
        """建立 SSE 连接（socket 直连，绕过代理）"""
        if self._connected:
            return True

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(15)
            self._sock.connect((self._host, self._port))

            request = (
                f"GET {self._sse_path} HTTP/1.1\r\n"
                f"Host: {self._host}:{self._port}\r\n"
                f"Accept: text/event-stream\r\n"
                f"Cache-Control: no-cache\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            self._sock.sendall(request.encode())

            # 启动后台读线程
            self._reader_thread = threading.Thread(
                target=self._read_sse_stream,
                daemon=True,
                name="sse-reader",
            )
            self._reader_thread.start()

            # 等待 endpoint 事件
            deadline = time.time() + 15
            while time.time() < deadline and not self._stop.is_set():
                if self.endpoint:
                    self._connected = True
                    logger.info(f"SSE connected, endpoint: {self.endpoint}")
                    return True
                time.sleep(0.1)

            logger.error("SSE 连接超时：未收到 endpoint 事件")
            return False

        except (socket.error, OSError) as e:
            logger.error(f"SSE 连接失败: {e}")
            return False

    def _read_sse_stream(self):
        """后台线程：读 SSE 流，缓冲拼接完整事件"""
        buffer = ""
        event_type = ""
        data_lines = []
        headers_done = False
        try:
            while not self._stop.is_set():
                try:
                    chunk = self._sock.recv(8192)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="ignore")

                # 第一次读取：跳过 HTTP headers
                if not headers_done:
                    if "\r\n\r\n" in buffer:
                        _, buffer = buffer.split("\r\n\r\n", 1)
                        headers_done = True
                    elif "\n\n" in buffer:
                        _, buffer = buffer.split("\n\n", 1)
                        headers_done = True
                    else:
                        continue  # headers 还没读完

                # 按行处理缓冲区
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.rstrip("\r")

                    if line == "":
                        # 空行 = 事件结束
                        if event_type and data_lines:
                            self._dispatch_event(event_type, "\n".join(data_lines))
                        event_type = ""
                        data_lines = []
                    elif line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())
                    elif line.startswith(":"):
                        pass  # 心跳

        except Exception as e:
            if not self._stop.is_set():
                logger.error(f"SSE 流读取异常: {e}")
        finally:
            if not self._stop.is_set():
                self._response_queue.put(None)

    def _dispatch_event(self, event_type: str, data: str):
        """分发 SSE 事件"""
        if event_type == "endpoint":
            if data.startswith("/"):
                self.endpoint = f"{self._base_url}{data}"
            elif data.startswith("http"):
                self.endpoint = data
            else:
                from urllib.parse import urljoin
                self.endpoint = urljoin(self._base_url, data)
            logger.info(f"Received endpoint: {self.endpoint}")

        elif event_type == "message":
            try:
                response = json.loads(data)
                self._response_queue.put(response)
            except json.JSONDecodeError as e:
                logger.error(f"SSE message 解析失败: {e}")

        elif event_type == "error":
            logger.error(f"SSE server error: {data}")

    def call(self, method: str, params: Dict[str, Any], request_id: int) -> Optional[Dict[str, Any]]:
        """同步调用 MCP 工具"""
        if not self.endpoint:
            return None

        request_data = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }

        try:
            # POST 用 requests，显式禁用代理
            resp = requests.post(
                self.endpoint,
                json=request_data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
                proxies={"http": None, "https": None},  # 显式禁用代理
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"POST 请求失败: {e}")
            return None

        # 等待匹配 id 的响应（从 SSE 流）
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                response = self._response_queue.get(timeout=1.0)
                if response is None:
                    logger.error("SSE 连接已断开")
                    return None
                if response.get("id") == request_id:
                    return response
                self._response_queue.put(response)  # 放回不匹配的
            except Empty:
                if self._stop.is_set():
                    return None

        logger.error(f"等待响应超时 (id={request_id})")
        return None

    def close(self):
        """关闭连接"""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._connected = False
        self.endpoint = None


def call_sse_mcp(sse_url: str, method: str, params: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
    """调用 SSE MCP 工具（高级接口）"""
    request_id = int(time.time() * 1000) % 1000000
    client = SSEMCPClient(sse_url, timeout=timeout)

    if not client.connect():
        return {"status": "error", "message": f"SSE 连接失败: {sse_url}"}

    try:
        result = client.call(method, params, request_id)
        if result is None:
            return {"status": "error", "message": "SSE 请求无响应"}

        if "result" in result:
            tool_result = result["result"]
            if isinstance(tool_result, dict):
                if "content" in tool_result:
                    content = tool_result["content"]
                    if isinstance(content, list) and content:
                        texts = [item.get("text", "") for item in content if isinstance(item, dict)]
                        if texts:
                            return {"status": "success", "data": "\n".join(texts), "raw": result}
                if "tools" in tool_result:
                    return {"status": "success", "data": tool_result, "raw": result}
            return {"status": "success", "data": tool_result, "raw": result}

        if "error" in result:
            err = result["error"]
            return {
                "status": "error",
                "message": err.get("message", "Unknown error") if isinstance(err, dict) else str(err),
                "raw": result,
            }

        return {"status": "success", "data": result}

    finally:
        client.close()


def list_sse_mcp_tools(sse_url: str, timeout: int = 60) -> Dict[str, Any]:
    """列出 SSE MCP 服务器上的所有可用工具"""
    return call_sse_mcp(sse_url, "tools/list", {}, timeout=timeout)


__all__ = ["SSEMCPClient", "call_sse_mcp", "list_sse_mcp_tools"]
