# 鉴真智能体 (CangSight)

「鉴真」(CangSight) 是一个面向「仓颉杯」智能编程大赛（CCF ChinaSoft 2026 综合系统类）的 **AI + 安全大模型平台智能体**：以「证据锚定 RAG + 可验证 CoT + ReAct 零干预闭环」为核心，构建可落地、可复现、可审计的安全运营超级智能体。

项目同时内置一套由 **仓颉语言（Cangjie）** 编写的 DAG 任务规划引擎（`cangjie_engine/`），用于安全处置流程的拓扑排序与并行度计算，体现国产编程语言在智能体工程链路中的落地。

## 项目架构

```
CangSight/
├── nexus/
│   ├── agents/            # 智能体实现
│   │   ├── base_agent.py       # 统一智能体抽象基类
│   │   ├── ooda_agent.py       # OODA 决策循环智能体
│   │   ├── ctf_agent.py        # CTF 攻防智能体
│   │   └── cangsight_agent.py  # CangSight 核心实现
│   ├── core/              # 技能注册、DAG 规划、安全护栏
│   ├── gateway/           # REST API 服务 + HITL 审批网关
│   ├── llm/               # LLM 适配器工厂与路由（DeepSeek/通义千问/Qwen/OpenAI）
│   ├── cang/              # RAG、场景模板、低代码编排、ReAct 演示、基线流程
│   ├── integrations/      # xdr/（Wazuh + 通用 REST 厂商）、ecc/
│   ├── adapters/          # 仓颉引擎客户端、SymPas MCP、SSE 客户端
│   ├── prompts/           # 系统提示词与 CoT/ReAct 模板
│   └── config.py          # 配置管理（LLM / SymPas 地址可配置）
├── cangjie_engine/        # 仓颉语言 DAG 规划引擎（编译产物 + .cj 源码）
├── skills/                # SymPas 技能集（sympas_mcp_skills.json）
├── scripts/               # CTF MCP 服务、网关启动、知识库扩充
├── frontend/dashboard/    # Web 控制台（SOC 风格）
├── demo_assets/           # 演示场景模板
├── docs/                  # 提交材料（项目说明/团队分工/AI工具说明/原创性声明/测试说明/RAG评测/演示说明）
├── tests/                 # pytest 自动化测试套件
├── requirements.txt       # 依赖清单
├── start.bat / start.sh   # 一键启动脚本
└── run.py                 # 主启动入口
```

## 核心能力

1. **智能对话**：自动识别用户输入类型，调用 SymPas 技能结合 LLM 分析反馈完整回答
2. **证据锚定 RAG**：检索 + 重排 + 引用闭环，低分拒答，防幻觉可复现
3. **OODA 决策循环**：观察→判断→决策→行动，9 阶段安全事件闭环
4. **可验证 CoT**：链式推理全程可追溯，关键步骤可复核
5. **HITL 人机协同**：高危动作强制人工审批
6. **EAT 审计链**：全程可追溯的安全审计
7. **仓颉 DAG 规划**：由仓颉语言引擎完成处置流程拓扑排序与并行度计算
8. **CTF 攻防**：集成 SymPas 静态分析工具的漏洞扫描与利用

## 快速开始

### 方式一：一键启动（推荐）

**Windows 用户：**
```batch
双击 start.bat
```

**Linux/Mac 用户：**
```bash
chmod +x start.sh
./start.sh
```

脚本会自动创建虚拟环境、安装依赖，并启动 CTF MCP 服务（2267）与主服务（7800）。

### 方式二：手动启动

**1. 创建虚拟环境并安装依赖**

```bash
# Windows
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. 配置 LLM**

首次使用需要配置 LLM 提供商，支持：
- **deepseek**（默认，deepseek-chat / deepseek-reasoner）
- **tongyi**（通义千问）
- **qwen**
- **openai**（OpenAI 兼容接口）

```bash
python -c "from nexus.config import init_llm_config; init_llm_config()"
```

或手动编辑 `.nexus/llm_config.json`：

```json
{
    "provider": "deepseek",
    "api_key": "your_api_key",
    "model": "deepseek-chat",
    "base_url": "https://api.deepseek.com"
}
```

**3. 启动服务**

```bash
python run.py
```

**4. 访问界面**

打开浏览器访问：`http://localhost:7800/frontend/dashboard/`

## 关键外部服务

| 服务 | 默认地址 | 说明 |
|------|----------|------|
| SymPas MCP | `http://localhost:6239` | 本组自研静态分析工具；通过 `SYMPAS_MCP_URL` 覆盖云端地址 |
| CTF MCP | `http://localhost:2267` | 本地 CTF 工具链 |
| 仓颉引擎 | `http://127.0.0.1:2270` | 仓颉语言 DAG 规划引擎；运行时库目录可用 `CANGJIE_RUNTIME` 指定 |

## 技术栈

| 类别 | 技术 |
|------|------|
| 后端框架 | Flask |
| 向量数据库 | ChromaDB |
| 语义嵌入 | ONNX + SentenceTransformer |
| LLM 调用 | DeepSeek / 通义千问 / Qwen / OpenAI 兼容 |
| 任务规划 | 仓颉语言（Cangjie）DAG 规划引擎 |
| MCP 服务 | SymPas MCP + CTF MCP（Flask HTTP Server） |
| 前端 | 原生 HTML/CSS/JS（SOC 风格） |

## 系统要求

- **Python** >= 3.9
- **操作系统**：Windows 10+ / Linux / macOS
- **内存**：>= 4GB（用于语义嵌入模型）
- **网络**：首次安装需联网下载依赖包

## 常见问题

### Q: 依赖安装慢怎么办？
使用国内镜像加速：
```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: 启动后提示端口占用？
检查并释放占用的端口：7800（主服务）、2267（CTF MCP）、2270（仓颉引擎）、6239（SymPas MCP）。

### Q: 如何切换 LLM 提供商？
编辑 `.nexus/llm_config.json` 文件修改 `provider` 字段，或在系统设置页面修改。

### Q: 如何对接 SymPas / XDR？
SymPas 地址通过环境变量 `SYMPAS_MCP_URL` 配置；XDR 平台在「系统设置 → XDR 平台配置」中选择 Wazuh 或通用 REST 厂商并填写连接信息。

## 测试

```bash
pip install pytest
python -m pytest          # 运行全部自动化测试（60 个用例，离线可复现）
python -m pytest -v       # 查看明细
```

测试覆盖配置管理、引用闭环防幻觉、场景模板/低代码互转、知识库种子与 STIX 导出、RAG 低置信拒答、仓颉引擎客户端降级回退、哈希链签名等核心逻辑。详见 `docs/测试说明.md`。

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /health | 健康检查 |
| POST | /agent/chat | 智能对话 |
| POST | /agent/scenario | 场景生成 |
| POST | /run/cang | CangSight 智能体运行 |
| POST | /agents/runs | 创建任务 |
| GET | /cwe/search | CWE 知识库搜索 |
| POST | /code/scan | 代码扫描 |

## 许可

本项目仅用于比赛用途。
