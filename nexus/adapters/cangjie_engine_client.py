from __future__ import annotations

import os
import time
import atexit
import subprocess
from typing import Any, Dict, List, Optional

import requests

ENGINE_PORT = 2270
BASE_URL = f"http://127.0.0.1:{ENGINE_PORT}"
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_EXE = os.path.join(_ROOT, "cangjie_engine", "bin", "cangjie_engine.exe")
# 仓颉运行时库目录（cjnative DLL）：优先读取 CANGJIE_RUNTIME 环境变量，
# 未设置时回退到本机 SDK 安装路径；现场演示可显式指定。
_RUNTIME = os.environ.get(
    "CANGJIE_RUNTIME",
    r"D:\cangjie\sdk120\cangjie\runtime\lib\windows_x86_64_cjnative",
)


class CangjieEngineClient:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.available: Optional[bool] = None

    def _already_up(self) -> bool:
        try:
            r = requests.get(BASE_URL + "/health", timeout=(1, 2))
            return r.status_code == 200
        except requests.RequestException:
            return False

    def start(self, timeout: float = 8.0) -> bool:
        if self.available is not None:
            return self.available
        if self._already_up():
            self.available = True
            return True
        if not os.path.exists(_EXE):
            self.available = False
            return False
        env = dict(os.environ)
        if os.path.isdir(_RUNTIME):
            env["PATH"] = _RUNTIME + os.pathsep + env.get("PATH", "")
        try:
            self.proc = subprocess.Popen(
                [_EXE], env=env, cwd=os.path.dirname(_EXE),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except OSError:
            self.available = False
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.available = False
                return False
            if self._already_up():
                self.available = True
                atexit.register(self.stop)
                return True
            time.sleep(0.3)
        self.available = False
        self.stop()
        return False

    def health(self) -> Dict[str, Any]:
        if not self.start():
            return {"engine": "cangjie", "available": False, "status": "unavailable"}
        try:
            data = requests.get(BASE_URL + "/health", timeout=(1, 3)).json()
            data["available"] = True
            return data
        except requests.RequestException:
            return {"engine": "cangjie", "available": False, "status": "unreachable"}

    def plan_dag(self, graph_text: str) -> Dict[str, Any]:
        if not self.start():
            return {"available": False, "source": "python_fallback"}
        try:
            r = requests.post(BASE_URL + "/dag/plan", data=graph_text.encode("utf-8"),
                              headers={"Content-Type": "text/plain"}, timeout=(2, 20))
            r.raise_for_status()
            text = r.text
            levels: List[List[str]] = []
            costs: Dict[str, int] = {}
            for line in text.split("\n"):
                if line.startswith("LEVEL"):
                    parts = line.split("|")[1:]
                    levels.append(parts)
                elif line.startswith("COST"):
                    p = line.split("|")
                    if len(p) >= 3:
                        costs[p[1]] = int(p[2])
            return {"available": True, "source": "cangjie", "raw": text,
                    "ok": text.startswith("OK"), "levels": levels, "costs": costs}
        except (requests.RequestException, ValueError) as exc:
            return {"available": False, "source": "python_fallback", "error": str(exc)}

    def decide(self, tool: str, scope_allowed: bool, approval_valid: bool,
               remaining_ms: int) -> Dict[str, Any]:
        """调用仓颉策略决策核 /policy/decide，返回三态 Verdict。"""
        body = f"{tool}|{'true' if scope_allowed else 'false'}|{'true' if approval_valid else 'false'}|{remaining_ms}"
        if not self.start():
            return {"available": False, "source": "python_fallback"}
        try:
            r = requests.post(BASE_URL + "/policy/decide", data=body.encode("utf-8"),
                              headers={"Content-Type": "text/plain"}, timeout=(2, 10))
            r.raise_for_status()
            text = r.text.strip()
            verdict, sep, reason = text.partition("|")
            return {"available": True, "source": "cangjie", "verdict": verdict,
                    "reason": reason if sep else None, "raw": text}
        except (requests.RequestException, ValueError) as exc:
            return {"available": False, "source": "python_fallback", "error": str(exc)}

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


_client = CangjieEngineClient()


def get_cangjie_engine() -> CangjieEngineClient:
    return _client
