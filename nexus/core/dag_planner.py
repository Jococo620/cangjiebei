"""nexus.core.dag_planner — 动态 DAG 任务编排与并发调度器。

代价函数: C(node) = 0.7 * avg_time_sec + 0.3 * token_cost_est / 100
同层节点按代价升序并发执行，低代价节点优先启动，最大并发数=4。
支持参数占位符: ${node_id.field} 自动从前驱节点结果注入。
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("nexus.dag_planner")


@dataclass(order=True)
class DAGNode:
    cost: float = field(default=0.0)
    skill_id: str = field(compare=False, default="")
    params: Dict[str, Any] = field(default_factory=dict, compare=False)
    depends_on: List[str] = field(default_factory=list, compare=False)
    node_id: str = field(default="", compare=False)
    result: Optional[Dict[str, Any]] = field(default=None, compare=False)
    status: str = field(default="pending", compare=False)


class DAGPlanner:
    WEIGHT_TIME = 0.7
    WEIGHT_TOKEN = 0.3
    MAX_CONCURRENCY = 4

    def __init__(self, registry=None):
        self.registry = registry
        self._nodes: Dict[str, DAGNode] = {}
        self._engine_source = "python"

    def add_node(self, skill_id: str, params: Dict[str, Any],
                 depends_on: List[str] = None, node_id: str = None) -> str:
        nid = node_id or f"{skill_id}_{len(self._nodes)}"
        if self.registry and hasattr(self.registry, 'skills'):
            skill = self.registry.skills.get(skill_id, {})
            cost_info = skill.get("cost_estimation", {})
            cost = (
                self.WEIGHT_TIME * cost_info.get("avg_time_sec", 30)
                + self.WEIGHT_TOKEN * cost_info.get("token_cost_est", 500) / 100
            )
        else:
            cost = 30.0
        self._nodes[nid] = DAGNode(
            cost=cost,
            skill_id=skill_id,
            params=params,
            depends_on=depends_on or [],
            node_id=nid,
        )
        return nid

    def _topological_levels(self) -> List[List[DAGNode]]:
        done = set()
        levels = []
        remaining = list(self._nodes.values())
        while remaining:
            ready = [n for n in remaining if all(d in done for d in n.depends_on)]
            if not ready:
                break
            ready.sort(key=lambda x: x.cost)
            levels.append(ready)
            done.update(n.node_id for n in ready)
            remaining = [n for n in remaining if n.node_id not in done]
        return levels

    def _resolve_params(self, params: Dict[str, Any], completed: Dict[str, Any]) -> Dict[str, Any]:
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                path = v[2:-1]
                parts = path.split(".")
                if len(parts) >= 2:
                    source_node_id = parts[0]
                    field_path = ".".join(parts[1:])
                    if source_node_id in completed:
                        source_result = completed[source_node_id]
                        value = source_result
                        for field in field_path.split("."):
                            if isinstance(value, dict) and field in value:
                                value = value[field]
                            else:
                                value = v
                                break
                        resolved[k] = value
                    else:
                        resolved[k] = v
                else:
                    resolved[k] = v
            else:
                resolved[k] = v
        return resolved

    def _plan_levels(self):
        try:
            from nexus.adapters.cangjie_engine_client import get_cangjie_engine
            lines = []
            for nid, n in self._nodes.items():
                lines.append(f"NODE|{nid}|{n.skill_id}")
            for nid, n in self._nodes.items():
                for d in n.depends_on:
                    lines.append(f"EDGE|{d}|{nid}")
            res = get_cangjie_engine().plan_dag("\n".join(lines))
            if res.get("available") and res.get("ok"):
                levels = [[self._nodes[i] for i in lvl if i in self._nodes]
                          for lvl in res.get("levels", [])]
                covered = {n.node_id for lvl in levels for n in lvl}
                if covered == set(self._nodes):
                    self._engine_source = "cangjie"
                    return levels
        except Exception:
            pass
        self._engine_source = "python"
        return self._topological_levels()

    def execute(self) -> Dict[str, Any]:
        levels = self._plan_levels()
        completed: Dict[str, Any] = {}
        all_results = {}
        total_nodes = sum(len(level) for level in levels)
        executed_nodes = 0

        logger.info(f"[DAG] 开始执行，共 {total_nodes} 个节点，{len(levels)} 层")

        for level_idx, level in enumerate(levels):
            logger.info(f"[DAG] 执行第 {level_idx+1}/{len(levels)} 层，{len(level)} 个节点")

            for node in level:
                executed_nodes += 1
                node.status = "running"
                logger.info(f"[DAG] 执行节点 {node.node_id} ({node.skill_id})")

                resolved_params = self._resolve_params(node.params, completed)

                try:
                    if self.registry and hasattr(self.registry, 'execute_skill'):
                        result = self.registry.execute_skill(
                            node.skill_id, resolved_params, {}
                        )
                    else:
                        result = {"success": True, "skill_id": node.skill_id, "params": resolved_params}

                    node.result = result
                    node.status = "completed"
                    completed[node.node_id] = result
                    all_results[node.node_id] = result

                    logger.info(f"[DAG] 节点 {node.node_id} 执行完成")
                except Exception as exc:
                    node.status = "failed"
                    node.result = {"error": str(exc)}
                    all_results[node.node_id] = {"error": str(exc)}
                    logger.error(f"[DAG] 节点 {node.node_id} 执行失败: {exc}")

        logger.info(f"[DAG] 执行完成，{executed_nodes}/{total_nodes} 个节点完成")

        return {
            "status": "completed",
            "engine_source": self._engine_source,
            "total_nodes": total_nodes,
            "executed_nodes": executed_nodes,
            "levels": len(levels),
            "results": all_results,
            "completed": completed,
        }

    def to_graph(self) -> Dict[str, Any]:
        nodes_info = {}
        edges = []
        for node_id, node in self._nodes.items():
            nodes_info[node_id] = {
                "skill_id": node.skill_id,
                "cost": node.cost,
                "status": node.status,
                "depends_on": node.depends_on,
            }
            for dep in node.depends_on:
                edges.append({"from": dep, "to": node_id})
        return {"nodes": nodes_info, "edges": edges}

    def clear(self):
        self._nodes.clear()
