"""CangSight 基础任务一键执行入口。

实现基线流程：
1) agent_context 初始化
2) code_scan 全量告警获取
3) sympas_slice_table + sympas-hv 二次验证降噪
4) generate_mr + LLM 生成合规摘要
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

from nexus.config import get_sympas_auth_headers, resolve_sympas_endpoint
from nexus.llm.router import get_model_router


def _tool_post(tool_name: str, payload: Dict[str, Any], timeout: int = 180) -> Dict[str, Any]:
    from nexus.adapters.sympas_failover import call_sympas_tool
    return call_sympas_tool(tool_name, payload, timeout=timeout)


def _extract_alerts(scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(scan_result, dict):
        return []

    issues = scan_result.get("issues")
    if isinstance(issues, list):
        return [item for item in issues if isinstance(item, dict)]

    findings = scan_result.get("findings")
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]

    nested = scan_result.get("data", {}).get("findings")
    if isinstance(nested, list):
        return [item for item in nested if isinstance(item, dict)]

    report_files = (
        scan_result.get("report", {})
        .get("stage1_pattern_scan", {})
        .get("files", [])
    )
    if isinstance(report_files, list):
        return [item for item in report_files if isinstance(item, dict)]

    return []


def _pick_target_file(project_path: str, alert: Dict[str, Any]) -> str:
    candidates = [
        alert.get("file"),
        alert.get("path"),
        alert.get("source"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    root = Path(project_path)
    if root.is_file():
        return str(root)

    for suffix in ("*.c", "*.cc", "*.cpp", "*.h", "*.hpp", "*.py"):
        found = next(root.rglob(suffix), None)
        if found:
            return str(found)

    return project_path


def _build_slice_criteria(alert: Dict[str, Any]) -> str:
    variable = alert.get("variable") or alert.get("target_variable") or "var"
    function = alert.get("function") or alert.get("entry") or "main"
    return f"{variable}@{function}"


def _is_true_positive(
    slice_result: Dict[str, Any],
    hv_result: Dict[str, Any],
) -> Tuple[bool, Dict[str, Any]]:
    slice_entries = (
        slice_result.get("slice_entries")
        or slice_result.get("data", {}).get("slice_table")
        or slice_result.get("data", {}).get("rows")
        or []
    )
    has_path = bool(slice_entries)

    verdict = str(
        hv_result.get("verdict")
        or hv_result.get("data", {}).get("verdict")
        or hv_result.get("status", "unknown")
    ).lower()

    hv_confirm = verdict not in {"no_issue", "safe", "ok", "success"}
    return has_path and hv_confirm, {
        "has_slice_path": has_path,
        "hv_verdict": verdict,
    }


def _generate_compliance_report(tp_list: List[Dict[str, Any]], mr_result: Dict[str, Any]) -> str:
    lines = [
        "Generate a concise GB/T 18336 and MLPS 2.0 level-3 style security report.",
        "Include vulnerability summary, CVSS-style severity, ATT&CK mapping, and remediation guidance.",
        "Only use evidence from the tool outputs below.",
        "",
        f"Confirmed vulnerabilities: {len(tp_list)}",
    ]

    for item in tp_list[:20]:
        cwe = item.get("cwe") or item.get("rule_id") or "unknown"
        line = item.get("line")
        file_path = item.get("file") or item.get("path") or "unknown"
        lines.append(f"- cwe={cwe}, file={file_path}, line={line}")

    if mr_result:
        lines.append("")
        lines.append("Metamorphic relation result summary:")
        lines.append(str(mr_result)[:2000])

    prompt = "\n".join(lines)
    router = get_model_router()
    response = router.chat([{"role": "user", "content": prompt}], task="report")
    content = response.get("content", "")
    if content:
        return content

    return (
        "[UNVERIFIED] LLM provider unavailable. "
        "Fallback compliance summary: vulnerabilities were confirmed by slice + hv evidence."
    )


def run_cangsight_baseline(project_path: str) -> Dict[str, Any]:
    """运行 CangSight 基线流程并返回可复现统计结果。"""
    project = Path(project_path)
    is_dir = project.is_dir()

    context_payload: Dict[str, Any] = {
        "query": f"project context for {project_path}",
        "target": project_path,
    }
    if is_dir:
        context_payload["target_dir"] = project_path
    else:
        context_payload["file"] = project_path

    context_result = _tool_post("agent_context", context_payload)

    scan_payload: Dict[str, Any] = {"target_dir": project_path} if is_dir else {"file": project_path}
    scan_result = _tool_post("code_scan", scan_payload)
    alerts_raw = _extract_alerts(scan_result)

    true_positive: List[Dict[str, Any]] = []
    false_positive: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []

    for alert in alerts_raw:
        target_file = _pick_target_file(project_path, alert)
        criteria = _build_slice_criteria(alert)
        slice_result = _tool_post(
            "sympas_slice_table",
            {
                "file": target_file,
                "criteria": criteria,
            },
        )
        hv_result = _tool_post(
            "sympas-hv",
            {
                "file": target_file,
            },
        )
        is_tp, diag = _is_true_positive(slice_result, hv_result)
        diagnostics.append(
            {
                "alert": alert,
                "target_file": target_file,
                "criteria": criteria,
                "slice_status": slice_result.get("status"),
                "hv_status": hv_result.get("status"),
                **diag,
            }
        )
        if is_tp:
            true_positive.append(alert)
        else:
            false_positive.append(alert)

    # 使用首个 TP 对应文件尝试生成蜕变关系，作为合规报告附加证据。
    mr_result: Dict[str, Any] = {}
    if true_positive:
        mr_target = _pick_target_file(project_path, true_positive[0])
        mr_result = _tool_post("generate_mr", {"file": mr_target})

    fpm_rate = len(false_positive) / max(len(alerts_raw), 1)
    denoise_rate = 1.0 - fpm_rate

    report = _generate_compliance_report(true_positive, mr_result)

    return {
        "status": "success",
        "project_path": project_path,
        "sympas_endpoint": resolve_sympas_endpoint("/tools/code_scan"),
        "context_status": context_result.get("status", "unknown"),
        "scan_status": scan_result.get("status", "unknown"),
        "total_alerts": len(alerts_raw),
        "tp": len(true_positive),
        "fp": len(false_positive),
        "fpm_rate": round(fpm_rate, 4),
        "denoise_rate": round(denoise_rate, 4),
        "tp_list": true_positive,
        "fp_list": false_positive,
        "diagnostics": diagnostics,
        "mr_result": mr_result,
        "report": report,
    }


__all__ = ["run_cangsight_baseline"]