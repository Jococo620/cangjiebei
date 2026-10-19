"""scenario_templates 场景模板与低代码互转单元测试。"""

import pytest

from nexus.cang.scenario_templates import (
    alert_triage_dag,
    report_generation_dag,
    vuln_closed_loop_dag,
    scenario_to_uasp_dag,
    dag_to_low_code,
    low_code_to_dag,
    parse_condition,
    serialize_condition,
)


def test_alert_triage_dag_structure():
    dag = alert_triage_dag("A-1")
    assert dag["scenario"] == "alert_triage"
    ids = [n["node_id"] for n in dag["nodes"]]
    assert ids == ["fetch", "enrich", "triage", "verdict"]
    assert dag["nodes"][-1]["depends_on"] == ["triage"]


def test_report_generation_dag():
    dag = report_generation_dag("R-1")
    assert dag["scenario"] == "report_generation"
    assert len(dag["nodes"]) == 3


def test_vuln_closed_loop_uses_sympas_skills():
    dag = vuln_closed_loop_dag("main.c", cwe="CWE-79")
    skills = {n["skill_id"] for n in dag["nodes"]}
    assert {"code_scan", "sympas_slice_table", "sbfl_rank"} <= skills
    repair = next(n for n in dag["nodes"] if n["node_id"] == "repair")
    assert repair["danger_level"] == "critical"


def test_scenario_to_uasp_dag_unknown_raises():
    with pytest.raises(ValueError):
        scenario_to_uasp_dag("does_not_exist")


def test_scenario_to_uasp_dag_normalizes():
    dag = scenario_to_uasp_dag("Alert-Triage", alert_id="x")
    assert dag["scenario"] == "alert_triage"


def test_dag_low_code_roundtrip():
    dag = alert_triage_dag("A-2")
    flow = dag_to_low_code(dag)
    assert flow["scene"]["name"] == "alert_triage"
    assert len(flow["edges"]) == 3
    restored = low_code_to_dag(flow)
    assert restored["scenario"] == "alert_triage"
    assert [n["node_id"] for n in restored["nodes"]] == ["fetch", "enrich", "triage", "verdict"]


def test_parse_condition_eq():
    assert parse_condition("severity == high") == {"field": "severity", "op": "eq", "value": "high"}


def test_parse_condition_quoted_value():
    assert parse_condition("cwe == 'CWE-79'") == {"field": "cwe", "op": "eq", "value": "CWE-79"}


def test_parse_condition_empty():
    assert parse_condition("") == {}


def test_parse_condition_short_expr():
    assert parse_condition("foo") == {"expr": "foo"}


def test_serialize_condition_roundtrip():
    cond = {"field": "severity", "op": "ge", "value": "medium"}
    assert serialize_condition(cond) == "severity >= 'medium'"
    assert parse_condition(serialize_condition(cond)) == {
        "field": "severity",
        "op": "ge",
        "value": "medium",
    }
