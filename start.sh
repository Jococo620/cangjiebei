#!/bin/bash
# ============================================
# 鉴真智能体 一键启动脚本 (Linux/Mac)
# ============================================

set -e

echo "============================================"
echo "  鉴真智能体 一键启动脚本 (Linux/Mac)"
echo "============================================"
echo ""

# 检查Python是否安装
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[错误] 未检测到Python，请先安装Python 3.9+"
    echo "Ubuntu/Debian: sudo apt install python3 python3-venv"
    echo "MacOS: brew install python3"
    exit 1
fi

# 确定Python命令
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
else
    PYTHON_CMD="python"
fi

# 检查Python版本
PY_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "[信息] 检测到Python版本: $PY_VERSION"

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# 检查虚拟环境是否存在
if [ -f "venv/bin/activate" ]; then
    echo "[信息] 虚拟环境已存在，跳过创建步骤"
else
    echo "[步骤] 创建虚拟环境..."
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo "[错误] 创建虚拟环境失败"
        exit 1
    fi
    echo "[完成] 虚拟环境创建成功"
fi

# 激活虚拟环境
source venv/bin/activate

# 升级pip
echo "[步骤] 升级pip到最新版本..."
pip install --upgrade pip -q

# 安装依赖
echo "[步骤] 安装项目依赖（首次可能需要几分钟）..."
pip install -r requirements.txt -q 2>/dev/null || pip install -r requirements.txt

# 检查配置文件
if [ ! -f ".nexus/llm_config.json" ]; then
    echo ""
    echo "[提示] 首次使用需要配置LLM，运行以下命令："
    echo "  python -c \"from nexus.config import init_llm_config; init_llm_config()\""
    echo "或直接编辑 .nexus/llm_config.json"
    echo ""
fi

echo "============================================"
echo "  启动服务中..."
echo "============================================"
echo ""
echo "  前端界面: http://localhost:7800/frontend/dashboard/"
echo "  API接口:  http://localhost:7800/run/cang"
echo "  健康检查: http://localhost:7800/health"
echo ""
echo "  按 Ctrl+C 停止服务"
echo "============================================"
echo ""

python run.py
