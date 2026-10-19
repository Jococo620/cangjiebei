"""CangSight 场景模板与低代码编排互转工具。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional


@dataclass
class LowCodeNode:
    """低代码节点配置。"""

    node_id: str
    node_type: str
    skill_id: str
    params: Dict[str, Any]
    display_name: str


@dataclass
class LowCodeEdge:
    """低代码边配置。"""

    source: str
    target: str
    condition: str = ""


@dataclass
class LowCodeScenario:
    """低代码场景配置，与方案文档接口保持一致。"""

    scenario_id: str
    scenario_name: str
    trigger: str
    nodes: List[LowCodeNode]
    edges: List[LowCodeEdge]
    hitl_required: bool = False


def _node(
    node_id: str,
    skill_id: str,
    params: Optional[Dict[str, Any]] = None,
    depends_on: Optional[Iterable[str]] = None,
    danger_level: Optional[str] = None,
) -> Dict[str, Any]:
    node = {
        "node_id": node_id,
        "skill_id": skill_id,
        "params": dict(params or {}),
        "depends_on": list(depends_on or []),
    }
    if danger_level:
        node["danger_level"] = danger_level
    return node


def alert_triage_dag(alert_id: str, sources: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """告警误报剔除场景。"""
    telemetry_sources = list(sources or ("traffic", "endpoint", "log"))
    return {
        "scenario": "alert_triage",
        "nodes": [
            _node("fetch", "fetch_alert", {"alert_id": alert_id}),
            _node(
                "enrich",
                "correlate_telemetry",
                {
                    "alert": "${fetch.alert}",
                    "sources": telemetry_sources,
                },
                depends_on=["fetch"],
            ),
            _node(
                "triage",
                "detection_gpt_triage",
                {"evidence": "${enrich.correlation}"},
                depends_on=["enrich"],
            ),
            _node(
                "verdict",
                "ops_gpt_verdict",
                {
                    "triage": "${triage.result}",
                    "require_citation": True,
                },
                depends_on=["triage"],
            ),
        ],
    }


def report_generation_dag(
    report_id: str,
    report_scope: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """安全报告自动生成场景。"""
    scope = dict(report_scope or {})
    return {
        "scenario": "report_generation",
        "nodes": [
            _node(
                "fetch",
                "fetch_report_materials",
                {
                    "report_id": report_id,
                    "scope": scope,
                },
            ),
            _node(
                "compile",
                "report_compile",
                {"materials": "${fetch.materials}"},
                depends_on=["fetch"],
            ),
            _node(
                "render",
                "ops_gpt_report",
                {
                    "compiled": "${compile.report_context}",
                    "report_style": scope.get("report_style", "executive"),
                    "require_citation": True,
                },
                depends_on=["compile"],
            ),
        ],
    }


def vuln_closed_loop_dag(target_file: str, cwe: Optional[str] = None) -> Dict[str, Any]:
    """漏洞排查与闭环场景。"""
    mapped_cwe = cwe or "CWE-unknown"
    return {
        "scenario": "vuln_closed_loop",
        "nodes": [
            _node("scan", "code_scan", {"file": target_file}),
            _node(
                "slice",
                "sympas_slice_table",
                {
                    "file": target_file,
                    "criteria": "${scan.primary_criteria}",
                },
                depends_on=["scan"],
            ),
            _node(
                "rank",
                "sbfl_rank",
                {
                    "file": target_file,
                    "cwe": mapped_cwe,
                },
                depends_on=["slice"],
            ),
            _node(
                "repair",
                "agentic_repair",
                {
                    "file": target_file,
                    "cwe": mapped_cwe,
                    "slice_table": "${slice.data}",
                    "ranked_lines": "${rank.data}",
                },
                depends_on=["rank"],
                danger_level="critical",
            ),
            _node(
                "taint_eval",
                "eval_patch_taint",
                {
                    "file": target_file,
                    "patch_diff": "${repair.patch_diff}",
                },
                depends_on=["repair"],
            ),
            _node(
                "quality_gate",
                "plan_quality_gate",
                {
                    "file": target_file,
                    "patch_diff": "${repair.patch_diff}",
                    "cwe": mapped_cwe,
                },
                depends_on=["taint_eval"],
            ),
        ],
    }


_SCENARIO_BUILDERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "alert_triage": alert_triage_dag,
    "report_generation": report_generation_dag,
    "vuln_closed_loop": vuln_closed_loop_dag,
}


def scenario_to_uasp_dag(scenario: str, **kwargs: Any) -> Dict[str, Any]:
    """把场景名称解析为标准 UASP DAG。"""
    normalized = scenario.strip().lower().replace("-", "_")
    if normalized not in _SCENARIO_BUILDERS:
        supported = ", ".join(sorted(_SCENARIO_BUILDERS))
        raise ValueError(f"Unsupported scenario '{scenario}'. Supported: {supported}")

    dag = _SCENARIO_BUILDERS[normalized](**kwargs)
    dag["scenario"] = normalized
    return dag


def dag_to_low_code(
    dag: Mapping[str, Any],
    scene_name: Optional[str] = None,
    scene_title: Optional[str] = None,
) -> Any:
    """把 UASP DAG 转成低代码编排引擎可消费的图结构。"""
    if scene_name is None and ("dag_id" in dag or "edges" in dag):
        return _uasp_dag_to_low_code_scenario(dag)

    actual_scene_name = scene_name or str(dag.get("scenario", "unknown"))
    nodes = []
    edges = []

    for raw_node in dag.get("nodes", []):
        node = deepcopy(dict(raw_node))
        node_id = node["node_id"]
        depends_on = list(node.get("depends_on") or [])
        nodes.append(
            {
                "id": node_id,
                "tool": node["skill_id"],
                "params": deepcopy(node.get("params") or {}),
                "depends_on": depends_on,
                "meta": {
                    "danger_level": node.get("danger_level", "safe"),
                },
            }
        )
        for dep in depends_on:
            edges.append({"source": dep, "target": node_id})

    return {
        "scene": {
            "name": actual_scene_name,
            "title": scene_title or actual_scene_name.replace("_", " ").title(),
            "scenario": dag.get("scenario", actual_scene_name),
        },
        "nodes": nodes,
        "edges": edges,
    }


def low_code_to_dag(flow: Any) -> Dict[str, Any]:
    """把低代码编排结构恢复为 UASP DAG。"""
    if isinstance(flow, LowCodeScenario):
        return _low_code_scenario_to_uasp_dag(flow)

    edge_map: Dict[str, List[str]] = {}
    for edge in flow.get("edges", []):
        source = edge.get("source")
        target = edge.get("target")
        if not source or not target:
            continue
        edge_map.setdefault(target, []).append(source)

    dag_nodes: List[Dict[str, Any]] = []
    for raw_node in flow.get("nodes", []):
        node_id = raw_node.get("id") or raw_node.get("node_id")
        if not node_id:
            continue
        depends_on = list(raw_node.get("depends_on") or edge_map.get(node_id, []))
        meta = raw_node.get("meta") or {}
        node = {
            "node_id": node_id,
            "skill_id": raw_node.get("tool") or raw_node.get("skill_id"),
            "params": deepcopy(raw_node.get("params") or {}),
            "depends_on": depends_on,
        }
        if meta.get("danger_level"):
            node["danger_level"] = meta["danger_level"]
        dag_nodes.append(node)

    scene = flow.get("scene") or {}
    return {
        "scenario": scene.get("scenario") or scene.get("name", "unknown"),
        "nodes": dag_nodes,
    }


def parse_condition(condition_str: str) -> Dict[str, Any]:
    """解析低代码条件表达式为结构化条件。"""
    condition = (condition_str or "").strip()
    if not condition:
        return {}
    parts = condition.split()
    if len(parts) < 3:
        return {"expr": condition}
    op_map = {
        "==": "eq",
        "!=": "ne",
        ">": "gt",
        "<": "lt",
        ">=": "ge",
        "<=": "le",
        "in": "in",
        "not_in": "not_in",
    }
    return {
        "field": parts[0],
        "op": op_map.get(parts[1], parts[1]),
        "value": " ".join(parts[2:]).strip("'\""),
    }


def serialize_condition(condition: Any) -> str:
    """把结构化条件恢复为低代码表达式。"""
    if not condition:
        return ""
    if isinstance(condition, str):
        return condition
    op_map = {
        "eq": "==",
        "ne": "!=",
        "gt": ">",
        "lt": "<",
        "ge": ">=",
        "le": "<=",
        "in": "in",
        "not_in": "not_in",
    }
    if "expr" in condition:
        return str(condition["expr"])
    op = op_map.get(str(condition.get("op", "eq")), str(condition.get("op", "==")))
    value = condition.get("value", "")
    if isinstance(value, str) and op not in {"in", "not_in"}:
        value_repr = f"'{value}'"
    else:
        value_repr = str(value)
    return f"{condition.get('field', '')} {op} {value_repr}".strip()


def _low_code_scenario_to_uasp_dag(scenario: LowCodeScenario) -> Dict[str, Any]:
    dag_nodes = []
    for node in scenario.nodes:
        dag_nodes.append(
            {
                "node_id": node.node_id,
                "node_type": node.node_type,
                "skill_id": node.skill_id,
                "params": deepcopy(node.params),
                "display_name": node.display_name,
                "uasp_protocol": "v1",
            }
        )

    dag_edges = [
        {
            "source": edge.source,
            "target": edge.target,
            "condition": parse_condition(edge.condition),
        }
        for edge in scenario.edges
    ]
    node_ids = [node.node_id for node in scenario.nodes]
    outgoing = {edge.source for edge in scenario.edges}
    incoming = {edge.target for edge in scenario.edges}
    entry_node = scenario.trigger if scenario.trigger in node_ids else next(
        (node_id for node_id in node_ids if node_id not in incoming),
        node_ids[0] if node_ids else "",
    )
    exit_nodes = [node_id for node_id in node_ids if node_id not in outgoing]

    return {
        "dag_id": scenario.scenario_id,
        "dag_name": scenario.scenario_name,
        "scenario": scenario.scenario_id,
        "nodes": dag_nodes,
        "edges": dag_edges,
        "entry_node": entry_node,
        "exit_nodes": exit_nodes,
        "hitl_required": scenario.hitl_required,
    }


def _uasp_dag_to_low_code_scenario(dag: Mapping[str, Any]) -> LowCodeScenario:
    nodes = [
        LowCodeNode(
            node_id=str(node.get("node_id") or node.get("id", "")),
            node_type=str(node.get("node_type") or "action"),
            skill_id=str(node.get("skill_id") or node.get("tool", "")),
            params=deepcopy(dict(node.get("params") or {})),
            display_name=str(
                node.get("display_name")
                or node.get("skill_id")
                or node.get("tool")
                or node.get("node_id")
                or node.get("id")
                or ""
            ),
        )
        for node in dag.get("nodes", [])
    ]
    edges = [
        LowCodeEdge(
            source=str(edge.get("source", "")),
            target=str(edge.get("target", "")),
            condition=serialize_condition(edge.get("condition")),
        )
        for edge in dag.get("edges", [])
    ]
    return LowCodeScenario(
        scenario_id=str(dag.get("dag_id") or dag.get("scenario") or "unknown"),
        scenario_name=str(dag.get("dag_name") or dag.get("scenario") or "unknown"),
        trigger=str(dag.get("entry_node") or (nodes[0].node_id if nodes else "")),
        nodes=nodes,
        edges=edges,
        hitl_required=bool(dag.get("hitl_required", False)),
    )


class ScenarioTemplates:
    """场景模板与低代码映射 facade。"""

    def scenario_to_uasp_dag(
        self,
        scenario_name: str,
        args: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        params = dict(args or {})
        params.update(kwargs)
        return scenario_to_uasp_dag(scenario_name, **params)

    def low_code_to_dag(self, scenario: Any) -> Dict[str, Any]:
        return low_code_to_dag(scenario)

    def dag_to_low_code(self, dag: Mapping[str, Any]) -> Any:
        return dag_to_low_code(dag)


def parse_dsl_condition(condition_str: str) -> Dict[str, Any]:
    """高级条件解析算子（DSL Advanced Operator）：支持 ==, !=, in, not in 等多种控制算子。

    相比 ``parse_condition``，本函数额外支持：
      - ``not in`` 双词算子（需要整体匹配）
      - 列表类型值解析：``risk_level in ['high', 'critical']`` → value=[...]
      - 空条件返回 always-true 结构

    Args:
        condition_str: 低代码条件表达式字符串，如 ``"risk_level == 'high'"``

    Returns:
        结构化条件字典，包含 field / op / value 三元组
    """
    import re as _re

    clean_str = str(condition_str or "").strip()
    if not clean_str:
        return {"field": "always", "op": "true", "value": None}

    # 优先匹配双词算子 "not in"（必须在 "in" 之前）
    _OPERATORS = [
        ("not in", "notin"),
        ("==", "eq"),
        ("!=", "neq"),
        (">=", "ge"),
        ("<=", "le"),
        (">", "gt"),
        ("<", "lt"),
        ("in", "in"),
    ]

    for op_symbol, op_name in _OPERATORS:
        # 使用正则精确匹配操作符（避免 "not in" 被 "in" 误匹配）
        pattern = _re.compile(
            rf"^(.+?)\s+{_re.escape(op_symbol)}\s+(.+)$", _re.IGNORECASE
        )
        m = pattern.match(clean_str)
        if m:
            field_name = m.group(1).strip()
            value_raw = m.group(2).strip()

            # 解析方括号列表值：['high', 'critical'] 或 ["CWE-122"]
            list_match = _re.match(r"^\[(.+)\]$", value_raw)
            if list_match:
                items = _re.split(r"\s*,\s*", list_match.group(1))
                val: Any = [v.strip().strip("'\"") for v in items if v.strip()]
            else:
                # 单值：去掉引号
                val = value_raw.strip("'\"")

            return {"field": field_name, "op": op_name, "value": val}

    # 无法识别的条件 — 原样存储为表达式
    return {"field": "always", "op": "expr", "value": clean_str}


def low_code_to_uasp_dag(scenario: LowCodeScenario) -> Dict[str, Any]:
    """低代码场景定义转统一 UASP DAG 编排格式（高级版，使用 parse_dsl_condition）。

    本函数是 ``_low_code_scenario_to_uasp_dag`` 的公开导出版本，
    使用高级 DSL 条件解析算子（支持 ==, !=, in, not in 列表算子），
    并输出标准 UASP DAG 格式（兼容 cangsight_agent.py 消费）。

    Args:
        scenario: LowCodeScenario 数据类实例

    Returns:
        UASP DAG 字典，包含 dag_id / dag_name / nodes / edges / hitl_required 等字段
    """
    dag_nodes: List[Dict[str, Any]] = []
    for node in scenario.nodes:
        dag_nodes.append({
            "node_id": node.node_id,
            "node_type": node.node_type,
            "skill_id": node.skill_id,
            "params": deepcopy(node.params),
            "display_name": node.display_name,
            "uasp_protocol": "v1",
        })

    dag_edges: List[Dict[str, Any]] = []
    for edge in scenario.edges:
        dag_edges.append({
            "source": edge.source,
            "target": edge.target,
            # 使用高级 DSL 条件解析算子（支持 not in / in / == / != 等）
            "condition": parse_dsl_condition(edge.condition),
        })

    # 自动推断 entry_node 和 exit_nodes
    node_ids = [node.node_id for node in scenario.nodes]
    outgoing_nodes = {edge.source for edge in scenario.edges}
    incoming_nodes = {edge.target for edge in scenario.edges}
    entry_node = (
        scenario.trigger
        if scenario.trigger in node_ids
        else next(
            (nid for nid in node_ids if nid not in incoming_nodes),
            node_ids[0] if node_ids else "",
        )
    )
    exit_nodes = [nid for nid in node_ids if nid not in outgoing_nodes]

    return {
        "dag_id": scenario.scenario_id,
        "dag_name": scenario.scenario_name,
        "scenario": scenario.scenario_id,
        "nodes": dag_nodes,
        "edges": dag_edges,
        "entry_node": entry_node,
        "exit_nodes": exit_nodes,
        "hitl_required": scenario.hitl_required,
    }


__all__ = [
    "LowCodeNode",
    "LowCodeEdge",
    "LowCodeScenario",
    "ScenarioTemplates",
    "alert_triage_dag",
    "report_generation_dag",
    "vuln_closed_loop_dag",
    "scenario_to_uasp_dag",
    "dag_to_low_code",
    "low_code_to_dag",
    "parse_condition",
    "serialize_condition",
    "parse_dsl_condition",
    "low_code_to_uasp_dag",
]