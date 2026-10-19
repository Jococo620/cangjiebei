#!/usr/bin/env bash
# 同步「过程演示」场景差异化改动到华为云服务器
# 用法：bash deploy/sync_scenario.sh [host]
#   host 默认 root@YOUR_SERVER_IP
set -euo pipefail

HOST="${1:-root@YOUR_SERVER_IP}"
DIR="/opt/cangsight"

# 本地相对路径 -> 服务器相对路径（均在 /opt/cangsight 下）
FILES=(
  "nexus/gateway/app.py"
  "demo_assets/scenario_templates.json"
  "frontend/dashboard/js/app.js"
  "frontend/dashboard/index.html"
  "frontend/dashboard/css/judge.css"
)

for f in "${FILES[@]}"; do
  echo "==> 上传 $f"
  scp "$f" "$HOST:$DIR/$f"
done

echo ""
echo "==> 重启 cangsight 服务"
ssh "$HOST" "systemctl restart cangsight && sleep 8 && systemctl is-active cangsight"

echo "==> 健康检查（带重试，服务冷启动约需 6~8 秒）"
ssh "$HOST" 'for i in 1 2 3 4 5; do out=$(curl -s http://127.0.0.1:7800/health); if [ -n "$out" ]; then echo "$out"; break; fi; sleep 3; done'
echo ""
echo "==> 同步完成。外网访问 http://YOUR_SERVER_IP:7800/frontend/dashboard/ （强制刷新 Ctrl+F5）"
