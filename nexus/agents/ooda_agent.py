"""nexus.agents.ooda_agent — OODA循环智能体（观察-定向-决策-行动）+ Reflexion反思机制。

OODA循环：
  1. Observe（观察）— 收集环境信息和输入
  2. Orient（定向）— 分析信息，建立态势感知
  3. Decide（决策）— 制定行动计划
  4. Act（行动）— 执行计划并观察结果

Reflexion反思机制：
  - 每轮循环后进行反思
  - 记录成功/失败经验
  - 调整下一轮策略
"""
import json
import logging
import os
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger("nexus.ooda_agent")


class OODAState(Enum):
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"
    REFLEXION = "reflexion"


class OODAController:
    def __init__(self, agent_id: str = "ooda_agent", max_cycles: int = 15):
        self.agent_id = agent_id
        self.max_cycles = max_cycles
        self.state = OODAState.OBSERVE
        self.cycle_count = 0
        self.history: List[Dict[str, Any]] = []
        self.reflexion_log: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {}
        self._llm_adapter = None
        self._llm_ready = False

    def _init_llm(self):
        if self._llm_ready:
            return
        try:
            from nexus.llm.factory import get_llm_adapter
            from nexus.llm.llm_adapter import ChatMessage
            from nexus.config import get_llm_provider, get_llm_api_key, get_llm_base_url

            provider = get_llm_provider()
            model = os.environ.get("LLM_MODEL", "deepseek-chat")
            base_url = get_llm_base_url()
            api_key = get_llm_api_key()
            logger.info(f"[OODA] env check: provider={provider}, api_key={'yes' if api_key else 'no'}, env_key={os.environ.get('DEEPSEEK_API_KEY', '')[:10]}")

            if not api_key:
                workspace = os.environ.get("NEXUS_WORKSPACE", "")
                config_paths = []
                if workspace:
                    config_paths.append(os.path.join(workspace, ".nexus", "llm_config.json"))
                config_paths.extend([
                    os.path.join(os.getcwd(), ".nexus", "llm_config.json"),
                    os.path.join(os.getcwd(), "CangSight", ".nexus", "llm_config.json"),
                    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".nexus", "llm_config.json"),
                ])
                for config_path in config_paths:
                    logger.info(f"[OODA] trying config path: {config_path}, exists={os.path.exists(config_path)}")
                    if os.path.exists(config_path):
                        with open(config_path, "r", encoding="utf-8") as f:
                            cfg = json.load(f)
                        api_key = cfg.get("api_key", "")
                        provider = cfg.get("provider", provider)
                        model = cfg.get("model", model)
                        base_url = cfg.get("base_url", base_url)
                        logger.info(f"[OODA] loaded config from {config_path}: provider={provider}, model={model}")
                        break

            if not api_key:
                logger.warning("[OODA] LLM API Key not configured, using rule-based fallback.")
                self._llm_ready = False
                return

            self._llm_adapter = get_llm_adapter(
                provider=provider, model=model, api_key=api_key, base_url=base_url
            )
            self._llm_ready = True
            logger.info(f"[OODA] LLM ready: provider={provider}, model={model}")
        except Exception as e:
            logger.warning(f"[OODA] LLM init failed: {e}, using rule-based fallback.")
            self._llm_ready = False

    def _llm_chat(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> Optional[str]:
        if not self._llm_ready:
            self._init_llm()
        if not self._llm_ready:
            return None
        try:
            from nexus.llm.llm_adapter import ChatMessage
            messages = [
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=user_prompt),
            ]
            response = self._llm_adapter.chat(messages, max_tokens=max_tokens, temperature=0.3)
            if response.is_success:
                return response.content.strip()
            logger.warning(f"[OODA] LLM call failed: {response.error}")
            return None
        except Exception as e:
            logger.warning(f"[OODA] LLM chat error: {e}")
            return None

    def reset(self):
        self.state = OODAState.OBSERVE
        self.cycle_count = 0
        self.history.clear()
        self.reflexion_log.clear()
        self.context.clear()

    def set_objective(self, objective: str):
        self.context["objective"] = objective

    def observe(self, objective: str, cycle: int) -> str:
        self.state = OODAState.OBSERVE
        system_prompt = (
            "你是鉴真安全智能体的「观察」模块。任务：对给定的安全事件目标进行信息收集和环境观察。"
            "用2-4句话描述：当前可观察到的异常迹象、攻击特征、影响范围。不要泛泛而谈，要具体到技术细节。"
        )
        user_prompt = f"安全事件目标：{objective}\n这是第{cycle}轮观察。请描述观察到的安全状况。"
        result = self._llm_chat(system_prompt, user_prompt)
        if not result:
            result = f"观察目标：{objective}。初步检测到异常行为，需要进一步分析。"
        self.history.append({"cycle": cycle, "state": "observe", "data": result})
        logger.info(f"[OODA] 观察(cycle {cycle}): {result[:80]}")
        return result

    def orient(self, observation: str, cycle: int) -> str:
        self.state = OODAState.ORIENT
        system_prompt = (
            "你是鉴真安全智能体的「定向/研判」模块。任务：基于观察结果进行安全分析和态势感知。"
            "用3-5句话描述：攻击类型判断、威胁等级评估、可能的攻击路径、受影响资产。"
            "要给出具体的技术判断，如 CWE 编号、ATT&CK 技术编号等。"
        )
        user_prompt = f"观察结果：{observation}\n这是第{cycle}轮研判。请进行深入分析。"
        result = self._llm_chat(system_prompt, user_prompt)
        if not result:
            input_type = self._classify_input(observation)
            result = f"初步研判：检测到{input_type}类型活动。威胁等级：中危。需进一步调查确认。"
        self.history.append({"cycle": cycle, "state": "orient", "data": result})
        logger.info(f"[OODA] 研判(cycle {cycle}): {result[:80]}")
        return result

    def decide(self, orientation: str, cycle: int) -> str:
        self.state = OODAState.DECIDE
        system_prompt = (
            "你是鉴真安全智能体的「决策」模块。任务：基于研判结果制定处置行动计划。"
            "用2-4句话描述：推荐处置动作（如封禁IP、隔离主机、限速等）、执行优先级、预期效果。"
            "格式：1. 动作名称 - 理由\n2. 动作名称 - 理由"
        )
        user_prompt = f"研判结果：{orientation}\n这是第{cycle}轮决策。请制定处置计划。"
        result = self._llm_chat(system_prompt, user_prompt)
        if not result:
            result = "1. 告警确认 - 核实威胁真实性\n2. 隔离处置 - 限制攻击源访问\n3. 复测验证 - 确认处置效果"
        self.history.append({"cycle": cycle, "state": "decide", "data": result})
        logger.info(f"[OODA] 决策(cycle {cycle}): {result[:80]}")
        return result

    def act(self, decision: str, cycle: int) -> str:
        self.state = OODAState.ACT
        system_prompt = (
            "你是鉴真安全智能体的「行动」模块。任务：模拟执行处置计划并描述执行结果。"
            "用2-3句话描述：已执行的动作、执行结果（成功/部分成功/需审批）、观察到的新情况。"
            "注意：高风险动作（如封禁、隔离）需要HITL审批，请说明已提交审批申请。"
        )
        user_prompt = f"处置计划：{decision}\n这是第{cycle}轮行动。请模拟执行并描述结果。"
        result = self._llm_chat(system_prompt, user_prompt)
        if not result:
            result = "已执行初步检测和告警确认。高风险处置动作已提交HITL审批，等待人工确认后执行。"
        self.history.append({"cycle": cycle, "state": "act", "data": result})
        logger.info(f"[OODA] 行动(cycle {cycle}): {result[:80]}")
        return result

    def reflexion(self, action_result: str, cycle: int) -> str:
        self.state = OODAState.REFLEXION
        system_prompt = (
            "你是鉴真安全智能体的「Reflexion反思」模块。任务：对本轮OODA循环进行反思。"
            "用2-3句话描述：本轮执行的不足、策略改进建议、下一轮应关注的方向。"
        )
        user_prompt = f"行动结果：{action_result}\n这是第{cycle}轮反思。请总结经验并给出改进建议。"
        result = self._llm_chat(system_prompt, user_prompt, max_tokens=512)
        if not result:
            result = "本轮已完成初步分析。下一轮应深入关联分析，关注攻击链路完整性。"
        self.reflexion_log.append({"cycle": cycle, "reflection": result})
        self.history.append({"cycle": cycle, "state": "reflexion", "data": result})
        logger.info(f"[OODA] 反思(cycle {cycle}): {result[:80]}")
        return result

    def run_cycle(self, objective: str, cycle: int, prev_reflexion: str = "") -> Dict[str, Any]:
        self.cycle_count = cycle
        logger.info(f"[OODA] 第 {cycle}/{self.max_cycles} 轮循环开始")

        combined = self._llm_combined_cycle(objective, cycle, prev_reflexion)
        if combined:
            observation = combined.get("observe", "")
            orientation = combined.get("orient", "")
            decision = combined.get("decide", "")
            action_result = combined.get("act", "")
            reflection = combined.get("reflexion", "")
        else:
            observation = self.observe(objective, cycle)
            orientation = self.orient(observation, cycle)
            decision = self.decide(orientation, cycle)
            action_result = self.act(decision, cycle)
            reflection = self.reflexion(action_result, cycle)

        self.history.append({"cycle": cycle, "state": "cycle_complete", "observe": observation, "orient": orientation, "decide": decision, "act": action_result, "reflexion": reflection})

        return {
            "status": "cycle_complete",
            "cycle_count": cycle,
            "state": self.state.value,
            "observe": observation,
            "orient": orientation,
            "decide": decision,
            "act": action_result,
            "reflexion": reflection,
        }

    def _llm_combined_cycle(self, objective: str, cycle: int, prev_reflexion: str = "") -> Optional[Dict[str, str]]:
        """单次LLM调用完成整轮OODA+Reflexion，减少从5次调用到1次。"""
        if not self._llm_ready:
            self._init_llm()
        if not self._llm_ready:
            return None
        try:
            from nexus.llm.llm_adapter import ChatMessage
            system_prompt = (
                "你是鉴真安全智能体的OODA决策循环引擎。请在一次回复中完成完整的OODA+Reflexion循环。"
                "严格按以下JSON格式输出，每个字段2-4句话，内容要具体到技术细节：\n"
                "{\n"
                '  "observe": "观察到的异常迹象、攻击特征、影响范围",\n'
                '  "orient": "攻击类型判断（含CWE/ATT&CK编号）、威胁等级、攻击路径、受影响资产",\n'
                '  "decide": "处置动作（封禁IP/隔离主机/限速等）、执行优先级、预期效果",\n'
                '  "act": "已执行动作描述、执行结果（成功/部分/需审批）、新观察到的情况",\n'
                '  "reflexion": "本轮不足、策略改进建议、下一轮关注方向"\n'
                "}\n只输出JSON，不要输出其他内容。"
            )
            user_prompt = f"安全事件目标：{objective}\n这是第{cycle}轮OODA循环。"
            if prev_reflexion:
                user_prompt += f"\n上一轮反思：{prev_reflexion}\n请基于上轮反思调整本轮策略。"

            messages = [
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=user_prompt),
            ]
            response = self._llm_adapter.chat(messages, max_tokens=2048, temperature=0.3)
            if response.is_success:
                content = response.content.strip()
                if content.startswith("```"):
                    content = content.split("```", 2)
                    content = content[1] if len(content) > 1 else content[0]
                    if content.startswith("json"):
                        content = content[4:]
                result = json.loads(content)
                logger.info(f"[OODA] 合并调用成功(cycle {cycle}): observe={result.get('observe', '')[:60]}")
                return result
            logger.warning(f"[OODA] 合并LLM调用失败: {response.error}")
            return None
        except Exception as e:
            logger.warning(f"[OODA] 合并调用异常: {e}")
            return None

    def _classify_input(self, input_text: str) -> str:
        if not input_text:
            return "未知"
        input_text = input_text.lower()
        if any(keyword in input_text for keyword in ["漏洞", "攻击", "扫描", "安全", "威胁", "入侵"]):
            return "安全分析"
        if any(keyword in input_text for keyword in ["端口", "渗透", "ctf", "靶机"]):
            return "渗透测试"
        if any(keyword in input_text for keyword in ["代码", "切片", "分析", "修复"]):
            return "代码分析"
        return "综合分析"

    def run_cycles(self, cycle_count: int = 3) -> Dict[str, Any]:
        self._init_llm()
        cycles = []
        objective = self.context.get("objective", "")
        prev_reflexion = ""

        for i in range(cycle_count):
            if self.cycle_count >= self.max_cycles:
                break
            cycle_num = i + 1
            result = self.run_cycle(objective, cycle_num, prev_reflexion)
            prev_reflexion = result.get("reflexion", "")
            cycles.append({
                "cycle_number": cycle_num,
                "observe": result["observe"],
                "orient": result["orient"],
                "decide": result["decide"],
                "act": result["act"],
                "reflexion": result["reflexion"],
            })

        return {
            "status": "completed",
            "cycles": cycles,
            "total_cycles": len(cycles),
        }
