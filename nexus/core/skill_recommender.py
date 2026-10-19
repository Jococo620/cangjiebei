"""工具组合推荐模块。"""

from typing import Dict, List, Optional

_OBJECTIVE_SKILL_MAP = {
    "漏洞扫描": ["start_scan", "code_scan", "cwe_classifier", "sca_cve_scanner"],
    "漏洞修复": ["agentic_repair", "eval_patch_taint", "plan_quality_gate"],
    "威胁分析": ["sympas_slice", "sympas_slice_table", "taint_path_explainer", "sbfl_rank"],
    "渗透测试": ["start_scan", "code_scan", "sympas_slice", "agentic_repair", "plan_quality_gate"],
    "应急响应": ["code_scan", "reachability_query", "agentic_repair", "plan_quality_gate"],
    "逆向分析": ["uafr_report", "dep_cluster", "ast_symbol_extractor", "cwe_classifier"],
    "漏洞挖掘": ["start_scan", "sympas_slice_table", "sbfl_rank", "sympas-hv", "generate_mr"],
    "安全审计": ["code_scan", "cwe_classifier", "vkb_retrieve", "sbfl_rank"],
    "流量分析": ["traffic_hunt.pcap_analyze", "sympas_slice_table", "cwe_classifier"],
    "EDR分析": ["edr_client.micro_isolate", "agent_context", "cwe_classifier"],
}


def recommend_tool_combination(
    objective: str,
    available_skills: List[str],
    history: List[Dict] = None,
) -> List[str]:
    history = history or []

    best_score = 0
    best_skills = ["code_scan", "cwe_classifier"]

    for keyword, skills in _OBJECTIVE_SKILL_MAP.items():
        if keyword in objective:
            filtered = [s for s in skills if s in available_skills]
            if filtered:
                score = len(filtered)
                if score > best_score:
                    best_score = score
                    best_skills = filtered

    if history:
        skill_success = {}
        for h in history:
            sid = h.get("skill", "")
            if sid not in skill_success:
                skill_success[sid] = {"total": 0, "ok": 0}
            skill_success[sid]["total"] += 1
            if h.get("status") == "ok":
                skill_success[sid]["ok"] += 1

        for sid, stats in skill_success.items():
            if stats["total"] >= 3 and stats["ok"] / stats["total"] >= 0.7:
                if sid not in best_skills and sid in available_skills:
                    best_skills.append(sid)

    return best_skills[:6]