"""符号切片与威胁研判流水线。"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("nexus.analysis.threat")


@dataclass
class SliceResult:
    file: str = ""
    function: str = ""
    variable: str = ""
    slice_entries: List[Dict] = field(default_factory=list)
    total_lines: int = 0
    download_url: str = ""


@dataclass
class TaintResult:
    source: str = ""
    sink: str = ""
    path_nodes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    is_reachable: bool = False


@dataclass
class CWEResult:
    cwe_id: str = ""
    cwe_name: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    severity_score: float = 0.0


@dataclass
class SBFLResult:
    ranking: List[Dict] = field(default_factory=list)
    top_k: int = 0
    average_score: float = 0.0


@dataclass
class ThreatReport:
    file: str = ""
    slice: Optional[SliceResult] = None
    taint: Optional[TaintResult] = None
    cwe: Optional[CWEResult] = None
    sbfl: Optional[SBFLResult] = None
    composite_risk: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


class ThreatAnalysisPipeline:

    def __init__(self, registry):
        self.registry = registry

    def step1_symbolic_slice(
        self, file: str, variable: str, function: str
    ) -> SliceResult:
        try:
            criteria = f"{variable}@{function}"
            resp = self.registry.execute_skill(
                "sympas_slice_table",
                {"file": file, "criteria": criteria},
            )
            data = resp.get("data", {})
            slice_table = data.get("slice_table", [])
            return SliceResult(
                file=file,
                function=function,
                variable=variable,
                slice_entries=slice_table,
                total_lines=data.get("total_lines", len(slice_table)),
                download_url=data.get("download_url", ""),
            )
        except Exception as exc:
            logger.warning(f"Step1 symbolic_slice failed: {exc}")
            return SliceResult(file=file, function=function, variable=variable)

    def step2_taint_trace(
        self, file: str, source: str, sink: str
    ) -> TaintResult:
        try:
            resp = self.registry.execute_skill(
                "taint_path_explainer",
                {"file": file, "source": source, "sink": sink},
            )
            data = resp.get("data", {})
            return TaintResult(
                source=source,
                sink=sink,
                path_nodes=data.get("path_nodes", []),
                confidence=data.get("confidence", 0.0),
                is_reachable=data.get("is_reachable", False),
            )
        except Exception as exc:
            logger.warning(f"Step2 taint_trace failed: {exc}")
            return TaintResult(source=source, sink=sink)

    def step3_cwe_classify(
        self, file: str, findings: List[Dict], slice_data: Dict = None
    ) -> CWEResult:
        try:
            resp = self.registry.execute_skill(
                "cwe_classifier",
                {"file": file, "findings": findings},
            )
            data = resp.get("data", {})
            top_cwe = data.get("top_cwe", {})
            return CWEResult(
                cwe_id=top_cwe.get("cwe_id", ""),
                cwe_name=top_cwe.get("cwe_name", ""),
                confidence=top_cwe.get("confidence", 0.0),
                evidence=top_cwe.get("evidence", []),
                severity_score=top_cwe.get("severity_score", 0.0),
            )
        except Exception as exc:
            logger.warning(f"Step3 cwe_classify failed: {exc}")
            return CWEResult()

    def step4_sbfl_rank(self, file: str, cwe_id: str = "") -> SBFLResult:
        try:
            params = {"file": file, "top_k": 5}
            if cwe_id:
                params["cwe"] = cwe_id
            resp = self.registry.execute_skill("sbfl_rank", params)
            data = resp.get("data", {})
            ranking = data.get("ranking", [])
            return SBFLResult(
                ranking=ranking,
                top_k=data.get("top_k", 5),
                average_score=data.get("average_score", 0.0),
            )
        except Exception as exc:
            logger.warning(f"Step4 sbfl_rank failed: {exc}")
            return SBFLResult()

    def run_full_pipeline(
        self, file: str, context: Dict
    ) -> ThreatReport:
        report = ThreatReport(file=file)

        variable = context.get("variable", "size")
        function = context.get("function", "main")
        report.slice = self.step1_symbolic_slice(file, variable, function)

        if report.slice and report.slice.slice_entries:
            source = report.slice.variable
            sink = context.get("sink", "memcpy")
            report.taint = self.step2_taint_trace(file, source, sink)

        issues = context.get("issues", [])
        slice_data = {"variable": variable, "function": function}
        report.cwe = self.step3_cwe_classify(file, issues, slice_data)

        cwe_id = report.cwe.cwe_id if report.cwe else ""
        report.sbfl = self.step4_sbfl_rank(file, cwe_id)

        report.composite_risk = calculate_composite_risk(
            report.slice, report.taint, report.cwe, report.sbfl
        )
        report.recommendation = report.composite_risk.get("recommendation", "")

        return report


def calculate_composite_risk(
    slice_result: Optional[SliceResult],
    taint_result: Optional[TaintResult],
    cwe_result: Optional[CWEResult],
    sbfl_result: Optional[SBFLResult],
) -> Dict[str, Any]:
    factors = {
        "slice_complexity": 0,
        "taint_reachability": 0,
        "cwe_severity": 0,
        "sbfl_confidence": 0,
    }

    if slice_result and slice_result.total_lines > 0:
        factors["slice_complexity"] = min(slice_result.total_lines, 50)

    if taint_result:
        if taint_result.is_reachable:
            factors["taint_reachability"] = int(taint_result.confidence * 25)
        else:
            factors["taint_reachability"] = 5

    if cwe_result:
        factors["cwe_severity"] = int(cwe_result.severity_score * 2.5)

    if sbfl_result:
        factors["sbfl_confidence"] = int((sbfl_result.average_score / 10.0) * 25)

    overall = sum(factors.values())

    if overall >= 75:
        label = "critical"
    elif overall >= 50:
        label = "high"
    elif overall >= 25:
        label = "medium"
    else:
        label = "low"

    return {
        "overall": overall,
        "factors": factors,
        "label": label,
        "recommendation": f"Risk Level: {label.upper()} ({overall}/100). "
                          f"See detailed threat report for remediation steps.",
    }


def generate_taint_visualization_data(taint_result: TaintResult) -> Dict[str, Any]:
    nodes = []
    edges = []

    for i, node in enumerate(taint_result.path_nodes):
        if i == 0:
            ntype = "source"
        elif i == len(taint_result.path_nodes) - 1:
            ntype = "sink"
        else:
            ntype = "pass_through"
        nodes.append({"id": f"n{i}", "label": node, "type": ntype})

    for i in range(len(nodes) - 1):
        edges.append({
            "from": f"n{i}", "to": f"n{i+1}",
            "label": "data flow",
            "risk": taint_result.confidence,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "critical_path": [n["id"] for n in nodes],
        "statistics": {
            "total_nodes": len(nodes),
            "tainted_nodes": len(nodes),
            "sanitized_nodes": 0,
        },
    }