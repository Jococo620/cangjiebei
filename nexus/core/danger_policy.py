"""危险等级动态调整策略。

同一技能在不同场景/上下文/目标下，危险等级可能不同。
例：agentic_repair 在漏洞挖掘场景 = medium，在应急响应场景 = critical。
"""

from typing import Dict, Any

DEFAULT_LEVELS = {
    "code_scan": "safe", "sympas_slice": "safe",
    "sympas_slice_table": "safe", "cwe_classifier": "safe",
    "taint_path_explainer": "safe", "sbfl_rank": "safe",
    "reachability_query": "safe", "vkb_retrieve": "safe",
    "ast_symbol_extractor": "safe", "sympas-hv": "safe",
    "sca_cve_scanner": "safe", "dep_cluster": "safe",
    "sympas_dep_graph": "safe", "uafr_report": "safe",
    "start_scan": "safe", "sarif_textual_export": "safe",
    "slice_diff": "safe", "sympas_dynamic_slice": "medium",
    "generate_mr": "medium", "eval_patch_taint": "medium",
    "reproduce_fault": "medium", "plan_quality_gate": "medium",
    "patch_safety_verifier": "medium", "skill_doc_generator": "medium",
    "agentic_repair": "high", "plan_case_reproduce": "high",
    "four_layer_demo": "medium", "repair_prompt_bundle": "safe",
    "agent_context": "safe",
    "safe_firewall_ban": "critical",
    "edr_client.micro_isolate": "critical",
    "traffic_hunt.pcap_analyze": "safe",
    "ticket_im.notify_dispatch": "safe",
}

SCENARIO_ADJUSTMENTS = {
    ("agentic_repair", "incident_response"): "critical",
    ("agentic_repair", "vuln_mining"): "medium",
    ("plan_case_reproduce", "incident_response"): "critical",
}

_HIGH_RISK_PATHS = ["/etc/", "/proc/", "/sys/", "C:\\Windows", "/root/", "/var/log"]


class DangerLevelPolicy:

    def __init__(self):
        self.base_levels = dict(DEFAULT_LEVELS)

    def evaluate(
        self,
        skill_id: str,
        scenario: str = "pentest",
        context: Dict = None,
    ) -> str:
        context = context or {}
        levels = []

        base = self.base_levels.get(skill_id, "safe")
        levels.append(base)

        key = (skill_id, scenario)
        if key in SCENARIO_ADJUSTMENTS:
            levels.append(SCENARIO_ADJUSTMENTS[key])

        target = context.get("target_file", "") or context.get("target", "")
        if any(p in target for p in _HIGH_RISK_PATHS):
            levels.append("critical")

        order = {"safe": 0, "medium": 1, "high": 2, "critical": 3}
        return max(levels, key=lambda l: order.get(l, 0))