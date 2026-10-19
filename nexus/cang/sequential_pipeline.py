# nexus/cang/sequential_pipeline.py — 顺序批量流水线执行器
# 借鉴 ECC-main autonomous-loops SequentialPipeline 模式
import os
import json
import time
import logging
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from nexus.core.plugin_registry import NexusPluginRegistry

logger = logging.getLogger("nexus.pipeline")


class SequentialPipelineRunner:
    """对任务列表逐项执行固定 Skill 序列，自动写入检查点

    Pipeline 格式:
      [
        {
          "skill_id": "code_scan",
          "param_template": {"file": "{target_file}"}
        },
        ...
      ]

    TaskItem 格式:
      {"target_file": "/workspace/foo.c", "case_id": "case-01"}
    """

    def __init__(
        self,
        registry: "NexusPluginRegistry",
        pipeline: List[Dict[str, Any]],
    ):
        self.registry = registry
        self.pipeline = pipeline

    def run(
        self,
        task_items: List[Dict[str, Any]],
        checkpoint_dir: str = ".nexus/checkpoints",
    ) -> List[Dict[str, Any]]:
        """执行所有任务项，每步写入检查点，支持断点续跑"""
        os.makedirs(checkpoint_dir, exist_ok=True)
        results: List[Dict[str, Any]] = []

        for idx, item in enumerate(task_items):
            item_results: List[Dict[str, Any]] = []
            logger.info(f"[Pipeline] Task {idx + 1}/{len(task_items)}: {item}")

            for step in self.pipeline:
                # 参数占位符替换
                params = {
                    k: (v.format(**item) if isinstance(v, str) else v)
                    for k, v in step["param_template"].items()
                }
                result = self.registry.execute_skill(step["skill_id"], params)
                item_results.append({
                    "skill_id": step["skill_id"],
                    "result":   result,
                })

                # 每步完成后写入检查点
                cp = {
                    "item_idx": idx,
                    "step":     step["skill_id"],
                    "ts":       time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status":   result.get("status"),
                }
                cp_file = os.path.join(
                    checkpoint_dir, f"cp_{idx}_{step['skill_id']}.json"
                )
                with open(cp_file, "w", encoding="utf-8") as fp:
                    json.dump(cp, fp, ensure_ascii=False)

                if result.get("status") == "error":
                    logger.warning(
                        f"[Pipeline] Step {step['skill_id']} failed for "
                        f"item {idx}: {result.get('message')}"
                    )
                    # 继续执行后续步骤（不中断流水线）

            results.append({"item": item, "steps": item_results})

        logger.info(
            f"[Pipeline] Completed {len(results)} tasks, "
            f"checkpoints in {checkpoint_dir}"
        )
        return results