"""nexus.core.task_intake — 鉴真智能体任务理解四入口统一解析器。

四个入口：
  1. ``parse_natural_language``  — 自然语言任务描述透传给意图理解层。
  2. ``parse_structured_dag``    — 结构化 DAG（JSON/YAML）校验后透传给 DAGPlanner。
  3. ``parse_archive``           — 压缩文件（zip）安全解压 + 项目级上下文抽取。
  4. ``parse_openapi_document``  — OpenAPI/Swagger 契约校验 + 端点可达性任务派生。

所有入口返回统一的 :class:`TaskIntakeResult`，其 ``task_list`` 字段可直接展开为
``DAGPlanner.add_node(**task)`` 调用参数（skill_id/params/depends_on/node_id）。
"""
from __future__ import annotations

import json
import logging
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nexus.task_intake")

MAX_COMPRESSION_RATIO = 200
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_MEMBER_COUNT = 10000

ENTRY_TYPES = ("natural_language", "structured_dag", "archive", "openapi")


class TaskIntakeError(ValueError):
    pass


@dataclass
class TaskIntakeResult:
    entry_type: str
    ok: bool
    task_list: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entry_type": self.entry_type,
            "ok": self.ok,
            "task_list": self.task_list,
            "metadata": self.metadata,
            "errors": self.errors,
        }


def parse_natural_language(text: str) -> TaskIntakeResult:
    cleaned = (text or "").strip()
    if not cleaned:
        return TaskIntakeResult("natural_language", False, errors=["自然语言任务描述为空"])
    return TaskIntakeResult(
        "natural_language",
        True,
        task_list=[
            {
                "skill_id": "agent_context",
                "params": {"query": cleaned},
                "depends_on": [],
                "node_id": "nl_intent",
            }
        ],
        metadata={"raw_text": cleaned, "length": len(cleaned)},
    )


def parse_structured_dag(dag: Dict[str, Any]) -> TaskIntakeResult:
    if not isinstance(dag, dict):
        return TaskIntakeResult("structured_dag", False, errors=["结构化任务必须为 JSON/YAML 对象"])
    nodes = dag.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return TaskIntakeResult("structured_dag", False, errors=["结构化任务需包含非空的 'nodes' 列表"])

    errors: List[str] = []
    task_list: List[Dict[str, Any]] = []
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"节点 {idx} 必须为对象")
            continue
        if "skill_id" not in node:
            errors.append(f"节点 {idx} 缺少必需字段 'skill_id'")
            continue
        task_list.append({
            "skill_id": node["skill_id"],
            "params": node.get("params", {}),
            "depends_on": node.get("depends_on", []),
            "node_id": node.get("node_id", f"node_{idx}"),
        })

    if errors:
        return TaskIntakeResult("structured_dag", False, errors=errors)

    return TaskIntakeResult(
        "structured_dag",
        True,
        task_list=task_list,
        metadata={"node_count": len(task_list)},
    )


def inspect_archive(path: str, *, max_total_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES) -> Dict[str, Any]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            files: List[str] = []
            total_uncompressed = 0
            total_compressed = 0
            for info in zf.infolist():
                if info.filename.startswith((".", "/")) or ".." in info.filename:
                    return {"safe": False, "reason": "path traversal detected", "files": []}
                if info.is_dir():
                    continue
                files.append(info.filename)
                total_uncompressed += info.file_size
                total_compressed += info.compress_size

            if len(files) > MAX_MEMBER_COUNT:
                return {"safe": False, "reason": f"too many members ({len(files)} > {MAX_MEMBER_COUNT})", "files": files}
            if total_uncompressed > max_total_bytes:
                return {"safe": False, "reason": f"uncompressed size exceeds {max_total_bytes} bytes", "files": files}
            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > MAX_COMPRESSION_RATIO:
                    return {"safe": False, "reason": f"compression ratio {ratio:.1f}x exceeds {MAX_COMPRESSION_RATIO}x", "files": files}

            return {"safe": True, "reason": "ok", "files": files, "uncompressed_size": total_uncompressed}
    except zipfile.BadZipFile:
        return {"safe": False, "reason": "invalid zip file", "files": []}


def parse_archive(path: str) -> TaskIntakeResult:
    report = inspect_archive(path)
    if not report["safe"]:
        return TaskIntakeResult("archive", False, errors=[report["reason"]])

    return TaskIntakeResult(
        "archive",
        True,
        task_list=[
            {
                "skill_id": "agent_context",
                "params": {"archive_path": path, "files": report["files"]},
                "depends_on": [],
                "node_id": "archive_analysis",
            }
        ],
        metadata={"files": report["files"], "uncompressed_size": report["uncompressed_size"]},
    )


def derive_reachability_tasks_from_openapi(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = doc.get("paths", {})
    task_list: List[Dict[str, Any]] = []
    node_id_counter = 0

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue
            summary = operation.get("summary", "") or operation.get("description", "")
            task_list.append({
                "skill_id": "agent_context",
                "params": {
                    "api_path": path,
                    "api_method": method.upper(),
                    "api_summary": summary,
                    "api_operation": operation,
                },
                "depends_on": [],
                "node_id": f"openapi_{node_id_counter}",
            })
            node_id_counter += 1

    return task_list


def parse_openapi_document(doc: Dict[str, Any]) -> TaskIntakeResult:
    if not isinstance(doc, dict):
        return TaskIntakeResult("openapi", False, errors=["OpenAPI文档必须为JSON对象"])

    openapi_version = doc.get("openapi") or doc.get("swagger")
    if not openapi_version:
        return TaskIntakeResult("openapi", False, errors=["缺少openapi或swagger版本字段"])

    paths = doc.get("paths", {})
    if not paths:
        return TaskIntakeResult("openapi", False, errors=["OpenAPI文档中未定义任何路径"])

    task_list = derive_reachability_tasks_from_openapi(doc)

    return TaskIntakeResult(
        "openapi",
        True,
        task_list=task_list,
        metadata={"openapi_version": openapi_version, "path_count": len(paths), "operation_count": len(task_list)},
    )


def detect_entry_type(source: str, path_hint: str = "") -> str:
    if path_hint:
        lower = path_hint.lower()
        if lower.endswith((".zip", ".tar", ".gz", ".rar")):
            return "archive"
        if lower.endswith((".json", ".yaml", ".yml")):
            if "openapi" in lower or "swagger" in lower:
                return "openapi"
            if "dag" in lower or "workflow" in lower:
                return "structured_dag"

    try:
        import json
        parsed = json.loads(source)
        if isinstance(parsed, dict):
            if "openapi" in parsed or "swagger" in parsed:
                return "openapi"
            if "nodes" in parsed or "tasks" in parsed:
                return "structured_dag"
    except Exception:
        pass

    try:
        import yaml
        parsed = yaml.safe_load(source)
        if isinstance(parsed, dict):
            if "openapi" in parsed or "swagger" in parsed:
                return "openapi"
            if "nodes" in parsed or "tasks" in parsed:
                return "structured_dag"
    except Exception:
        pass

    if source.startswith("data:application/zip") or source.startswith("data:application/x-zip-compressed"):
        return "archive"

    return "natural_language"


def intake_task(data: Dict[str, Any]) -> TaskIntakeResult:
    entry_type = data.get("entry_type")
    content = data.get("content")

    if entry_type not in ENTRY_TYPES:
        return TaskIntakeResult("unknown", False, errors=[f"未知入口类型: {entry_type}"])

    if entry_type == "natural_language":
        return parse_natural_language(content)
    elif entry_type == "structured_dag":
        return parse_structured_dag(content)
    elif entry_type == "archive":
        return parse_archive(content)
    elif entry_type == "openapi":
        return parse_openapi_document(content)
    else:
        return TaskIntakeResult(entry_type, False, errors=[f"入口类型 {entry_type} 未实现"])
