#!/usr/bin/env bash
# CangSight 一键部署脚本（华为云 / Ubuntu 22.04）
# 用法：sudo bash deploy.sh [部署目录] [对外端口] [运行用户]
#   部署目录默认 /opt/cangsight
#   对外端口默认 7800（避开现有 contractflow 的 8000）
#   运行用户默认 root（比赛演示最省事，生产建议专用用户）
set -euo pipefail

APP_DIR="${1:-/opt/cangsight}"
PORT="${2:-7800}"
RUN_USER="${3:-root}"
MIRROR="https://mirrors.huaweicloud.com/repository/pypi/simple"

echo "==> CangSight 部署配置"
echo "    部署目录 : $APP_DIR"
echo "    对外端口 : $PORT"
echo "    运行用户 : $RUN_USER"

if [ "$(id -u)" -ne 0 ]; then
  echo "!! 请用 root 运行：sudo bash deploy.sh [部署目录] [端口] [运行用户]"
  exit 1
fi

if [ ! -f "$APP_DIR/requirements.txt" ]; then
  echo "!! 未找到 $APP_DIR/requirements.txt"
  echo "   请先把项目源码上传到 $APP_DIR，例如："
  echo "   scp -r CangSight/* root@YOUR_SERVER_IP:$APP_DIR/"
  exit 1
fi

command -v python3 >/dev/null || { echo "!! 缺少 python3"; exit 1; }
python3 -V

# 1. 虚拟环境
if [ ! -d "$APP_DIR/venv" ]; then
  echo "==> 创建虚拟环境"
  python3 -m venv "$APP_DIR/venv"
fi

# 2. 安装依赖（华为云镜像加速）
echo "==> 安装依赖（华为云镜像）"
"$APP_DIR/venv/bin/pip" install -U pip -i "$MIRROR" -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -i "$MIRROR"

# 3. 生成 systemd 服务
echo "==> 写入 systemd 服务"
cat > /etc/systemd/system/cangsight.service <<EOF
[Unit]
Description=CangSight Security Super Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
User=$RUN_USER
Group=$RUN_USER
Environment=NEXUS_PORT=$PORT
Environment=SYMPAS_MCP_URL=http://YOUR_SYMPAS_IP:6239
Environment=PYTHONUTF8=1
ExecStart=$APP_DIR/venv/bin/python run.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now cangsight

echo ""
echo "==> 部署完成，还需手动完成以下步骤："
echo "1) 配置 LLM key：编辑 $APP_DIR/.nexus/llm_config.json"
echo "   { \"provider\": \"deepseek\", \"api_key\": \"你的key\", \"model\": \"deepseek-chat\", \"base_url\": \"https://api.deepseek.com\" }"
echo "2) 华为云控制台 -> 安全组 -> 放行 TCP $PORT"
echo "3) 查看状态：sudo systemctl status cangsight"
echo "4) 查看日志：sudo journalctl -u cangsight -f"
echo "5) 内网自检：curl http://127.0.0.1:$PORT/health"
echo "6) 外网访问：http://YOUR_SERVER_IP:$PORT/frontend/dashboard/"
echo "7) 验证 SymPas：curl http://YOUR_SYMPAS_IP:6239/ui/  （若不通改内网地址）"
