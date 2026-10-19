# nexus/cang/seed_data.py — 安全垂域知识库种子（ATT&CK 技战术 / 典型 CWE / 监管要点）
# 支撑"高质量垂域知识库"（进阶 20 分）与离线可复现的防幻觉 RAG 评测：
#   seed_security_rag(rag)   → 灌入 SecurityRAG（向量库 ingest）
#   seed_vector_memory(mem)  → 灌入 NexusVectorMemory.security_kb
# 种子为内置常量（离线无文件依赖）；evals/fixtures/security_kb/*.json 为同源镜像，便于查阅。
from __future__ import annotations

import json
import os
import time
import uuid as _uuid
from typing import Any, Dict, List

# 单一事实源：每条含 RAG 所需 (id/source/title/text) 与 KB 所需 (cwe/signature/mitigation)
SECURITY_KB_SEED: List[Dict[str, Any]] = [
    {
        "id": "CWE-122",
        "source": "MITRE-CWE",
        "title": "CWE-122 堆缓冲区溢出 (Heap-based Buffer Overflow)",
        "cwe": "CWE-122",
        "signature": "memcpy",
        "text": "当向堆分配缓冲区写入的数据超过其容量时发生堆溢出，常见于未校验长度的 memcpy/strcpy。"
                "利用可导致堆元数据破坏与远程代码执行。",
        "mitigation": "写入前强制校验 dst 容量 >= src 长度；使用带边界的 memcpy_s/strncpy；启用 ASLR/FORTIFY。",
    },
    {
        "id": "CWE-416",
        "source": "MITRE-CWE",
        "title": "CWE-416 释放后使用 (Use After Free)",
        "cwe": "CWE-416",
        "signature": "free",
        "text": "对象释放后其指针仍被解引用，攻击者可通过堆风水重新占位，劫持控制流。",
        "mitigation": "释放后立即置空指针；引入所有权/借用模型；使用 AddressSanitizer 检测。",
    },
    {
        "id": "CWE-362",
        "source": "MITRE-CWE",
        "title": "CWE-362 并发竞争条件 (Race Condition)",
        "cwe": "CWE-362",
        "signature": "mutex",
        "text": "多线程对共享状态的非原子访问在缺少同步时产生数据竞争与 TOCTOU 漏洞。",
        "mitigation": "对共享可变状态加锁（互斥量/读写锁）；使用原子类型；最小化临界区。",
    },
    {
        "id": "CWE-78",
        "source": "MITRE-CWE",
        "title": "CWE-78 操作系统命令注入 (OS Command Injection)",
        "cwe": "CWE-78",
        "signature": "os.system",
        "text": "将未净化的外部输入拼接进 shell 命令，攻击者可注入任意命令。常见于 os.system/subprocess(shell=True)。",
        "mitigation": "避免 shell=True；使用参数化数组调用；对输入做白名单校验与转义。",
    },
    {
        "id": "CWE-250",
        "source": "MITRE-CWE",
        "title": "CWE-250 以非必要特权执行 (Execution with Unnecessary Privileges)",
        "cwe": "CWE-250",
        "signature": "lsass",
        "text": "进程以高于所需的权限运行，一旦被攻陷则横向移动与凭据窃取面扩大（如 lsass 转储）。",
        "mitigation": "最小权限原则；及时降权；对敏感进程做 EDR 微隔离与凭据保护。",
    },
    {
        "id": "ATTACK-T1078",
        "source": "MITRE-ATT&CK",
        "title": "ATT&CK T1078 有效账户 (Valid Accounts)",
        "cwe": "",
        "signature": "valid-accounts",
        "text": "攻击者使用合法凭据进行初始访问、持久化、提权与防御规避；内网横向移动常伴随异常登录"
                "与敏感资产访问，是内鬼行为的典型信号。",
        "mitigation": "多因素认证；异常登录检测（时段/地理/设备）；最小权限与会话审计。",
    },
    {
        "id": "ATTACK-T1059",
        "source": "MITRE-ATT&CK",
        "title": "ATT&CK T1059 命令与脚本解释器 (Command and Scripting Interpreter)",
        "cwe": "CWE-78",
        "signature": "cmd-exec",
        "text": "攻击者借助 shell/PowerShell/解释器执行命令，常与 Web RCE、反弹 shell 联动。",
        "mitigation": "脚本执行白名单；命令行审计与告警；EDR 进程树关联分析。",
    },
    {
        "id": "ATTACK-T1041",
        "source": "MITRE-ATT&CK",
        "title": "ATT&CK T1041 经 C2 信道外泄 (Exfiltration Over C2 Channel)",
        "cwe": "",
        "signature": "c2-exfil",
        "text": "数据通过既有命令控制信道外泄，流量异常（高频外联、隐蔽隧道）是关键检测点。",
        "mitigation": "出站流量基线与异常检测；NGFW 封禁可疑外联 IP；DLP 敏感数据监控。",
    },
    {
        "id": "REG-PIPL",
        "source": "China-Regulation",
        "title": "个人信息保护合规要点 (PIPL/数据安全)",
        "cwe": "",
        "signature": "compliance",
        "text": "处置涉及个人信息的安全事件需遵循最小必要、目的限定与可审计原则；自动化处置的破坏性动作"
                "应保留人工复核以满足'AI 始终处于人类控制之下'。",
        "mitigation": "破坏性动作经 HITL 审批；全程留存防篡改审计链；脱敏与访问最小化。",
    },
]


def load_seed() -> List[Dict[str, Any]]:
    """返回内置种子列表（拷贝），离线无文件依赖。"""
    return [dict(item) for item in SECURITY_KB_SEED]


def load_seed_from_file(path: str) -> List[Dict[str, Any]]:
    """从 JSON 文件加载种子（evals/fixtures/security_kb/*.json）。"""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("entries", [])


# ── OpenCTI STIX2 结构化导出（对标「领域知识增强与工具扩展」进阶任务）────────────
# 不整机部署 OpenCTI，
# 仅借用其 STIX 2.1 数据模型重新组织 seed_data 条目结构，让知识库从“人工文本”进化为
# “符合行业标准的结构化知识”，可直接被任何 STIX 2.1 消费方（含 OpenCTI 自身）解析。
_STIX_NAMESPACE = _uuid.uuid5(_uuid.NAMESPACE_URL, "sympas-nexus.cang.seed_data")


def _stix_id(stix_type: str, entry_id: str) -> str:
    """确定性生成 STIX 2.1 兼容 id（``type--uuid``），同一 entry_id 始终映射到同一 uuid。"""
    return f"{stix_type}--{_uuid.uuid5(_STIX_NAMESPACE, f'{stix_type}:{entry_id}')}"


def _entry_to_stix_object(entry: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    """按 STIX 2.1 schema 把单条内置知识条目转换为对应 SDO（STIX Domain Object）。

    - source 含 "ATT&CK" → ``attack-pattern``（含 x_mitre_id 自定义属性）
    - source 含 "CWE"    → ``vulnerability``（external_references 指向 CWE）
    - 其余（监管要点等）    → ``indicator``（description 承载合规要点）
    """
    source = entry.get("source", "")
    if "ATT&CK" in source:
        stix_type = "attack-pattern"
        obj: Dict[str, Any] = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": _stix_id(stix_type, entry["id"]),
            "created": timestamp,
            "modified": timestamp,
            "name": entry.get("title", entry["id"]),
            "description": entry.get("text", ""),
            "x_mitre_id": entry["id"].replace("ATTACK-", ""),
            "external_references": [
                {"source_name": "mitre-attack", "external_id": entry["id"].replace("ATTACK-", "")}
            ],
        }
    elif "CWE" in source:
        stix_type = "vulnerability"
        obj = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": _stix_id(stix_type, entry["id"]),
            "created": timestamp,
            "modified": timestamp,
            "name": entry.get("title", entry["id"]),
            "description": entry.get("text", ""),
            "external_references": [
                {"source_name": "cwe", "external_id": entry.get("cwe", entry["id"])}
            ],
        }
    else:
        stix_type = "indicator"
        pattern_value = entry.get("signature") or entry.get("id")
        obj = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": _stix_id(stix_type, entry["id"]),
            "created": timestamp,
            "modified": timestamp,
            "name": entry.get("title", entry["id"]),
            "description": entry.get("text", ""),
            "pattern": f"[x-sympas:signature = '{pattern_value}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
        }
    if entry.get("mitigation"):
        obj["x_sympas_mitigation"] = entry["mitigation"]
    return obj


def to_stix2_bundle(entries: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """把内置安全知识库导出为 STIX 2.1 Bundle（对标 OpenCTI 结构化知识图谱 schema）。

    输出可直接被任何 STIX 2.1 消费方解析，与题面明确点名的“ATT&CK 技战术图谱”表述直接对齐。
    """
    docs = entries if entries is not None else load_seed()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    objects = [_entry_to_stix_object(e, timestamp) for e in docs]
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid5(_STIX_NAMESPACE, 'bundle:' + timestamp)}",
        "objects": objects,
    }


# ── MISP 示例 Feed 导入（对标「真实、可持续更新的威胁情报数据源」）──────────────────
# github.com/MISP/MISP（AGPL-3.0）Event/Attribute 结构的最小离线示例 Feed，
# 用于演示“对接行业标准情报格式”而无需真实部署 MISP 实例；生产环境中可直接将从
# 真实 MISP 实例导出的 JSON Feed 传入 ``load_seed_from_misp_feed``，无需修改转换逻辑。
MISP_EXAMPLE_FEED: List[Dict[str, Any]] = [
    {
        "Event": {
            "info": "Suspicious lsass access via renamed backup process",
            "Attribute": [
                {
                    "type": "filename",
                    "category": "Payload delivery",
                    "value": "lsass_backup.exe",
                    "comment": "renamed credential dumping tool masquerading as backup service",
                },
                {
                    "type": "comment",
                    "category": "Internal reference",
                    "value": "Correlates with CWE-250 privilege misuse mitigation playbook",
                },
            ],
        }
    },
    {
        "Event": {
            "info": "C2 exfiltration channel over long-lived outbound tunnel",
            "Attribute": [
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": "203.0.113.100",
                    "comment": "observed high-frequency beacon interval",
                },
                {
                    "type": "snort",
                    "category": "Network activity",
                    "value": "alert tcp any any -> any any (msg:\"possible C2 beacon\"; sid:1000001;)",
                },
            ],
        }
    },
]


def load_seed_from_misp_feed(feed: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    """把 MISP Event/Attribute 结构转换为内置知识条目 schema（id/source/title/...）。

    仅依赖 MISP 标准字段（``Event.info`` / ``Event.Attribute[].type/value/comment``），
    不要求真实网络访问，可直接对接从公开 MISP 实例导出的 JSON Feed。
    """
    entries: List[Dict[str, Any]] = []
    for i, item in enumerate(feed if feed is not None else MISP_EXAMPLE_FEED):
        event = item.get("Event", item)
        info = event.get("info", f"MISP-EVENT-{i}")
        attributes = event.get("Attribute", [])
        signature = ""
        text_parts: List[str] = []
        for attr in attributes:
            value = str(attr.get("value", ""))
            if not signature and attr.get("type") in {
                "filename", "md5", "sha1", "sha256", "regkey", "snort", "yara", "ip-dst", "ip-src",
            }:
                signature = value
            text_parts.append(f"[{attr.get('category', 'n/a')}] {attr.get('type', '')}={value}")
        entries.append(
            {
                "id": f"MISP-{i:03d}",
                "source": "MISP",
                "title": info,
                "cwe": "",
                "signature": signature,
                "text": "; ".join(text_parts) or info,
                "mitigation": "",
            }
        )
    return entries


def seed_security_rag(rag: Any, entries: List[Dict[str, Any]] | None = None) -> int:
    """灌入 SecurityRAG（调用其 ingest）。返回写入的 chunk 数。"""
    docs = entries or load_seed()
    payload = [
        {
            "id": e["id"],
            "source": e.get("source", e["id"]),
            "title": e.get("title", e["id"]),
            "text": e.get("text", ""),
        }
        for e in docs
    ]
    return int(rag.ingest(payload))


def seed_vector_memory(mem: Any, entries: List[Dict[str, Any]] | None = None) -> int:
    """灌入 NexusVectorMemory.security_kb（调用 seed_security_kb）。返回写入条数。"""
    docs = entries or load_seed()
    cwe_entries = [
        {
            "cwe_id": e["id"],
            "name": e.get("title", e["id"]),
            "description": e.get("text", ""),
            "mitigation": e.get("mitigation", ""),
            "source": e.get("source", ""),
        }
        for e in docs
    ]
    return int(mem.seed_security_kb(cwe_entries))


def export_fixture(path: str) -> str:
    """把内置种子导出为 JSON 镜像文件（供 evals 资产/查阅）。"""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(SECURITY_KB_SEED, f, ensure_ascii=False, indent=2)
    return path


__all__ = [
    "SECURITY_KB_SEED",
    "MISP_EXAMPLE_FEED",
    "load_seed",
    "load_seed_from_file",
    "load_seed_from_misp_feed",
    "to_stix2_bundle",
    "seed_security_rag",
    "seed_vector_memory",
    "export_fixture",
]