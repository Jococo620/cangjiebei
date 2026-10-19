"""pytest 全局配置：把项目根目录加入 sys.path，并统一 UTF-8 输出。

Windows 控制台默认 GBK，测试断言信息若含 emoji/中文可能导致 UnicodeEncodeError，
这里与 run.py 保持一致的 reconfigure 策略，保证 CI 与本机均可稳定运行。
"""

import os
import sys

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
