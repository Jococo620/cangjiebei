"""nexus.runtime.council — 委员会决策机制。

多个专家角色进行投票决策，支持：
  - 多Agent协同决策
  - 投票表决机制
  - 冲突解决策略
  - 决策置信度评估
"""
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("nexus.council")


@dataclass
class CouncilMember:
    name: str
    role: str
    expertise: List[str]
    vote_weight: float = 1.0


@dataclass
class CouncilDecision:
    proposal: str
    supporting_reasons: List[str]
    opposing_reasons: List[str]
    confidence: float
    final_decision: str
    votes: Dict[str, str]


class Council:
    def __init__(self):
        self.members: List[CouncilMember] = [
            CouncilMember("SecurityAnalyst", "安全分析师", ["漏洞分析", "威胁检测"], 1.5),
            CouncilMember("PenTester", "渗透测试专家", ["渗透测试", "漏洞利用"], 1.5),
            CouncilMember("CodeReviewer", "代码审查专家", ["代码审计", "安全编码"], 1.2),
            CouncilMember("IncidentResponder", "应急响应专家", ["事件响应", "威胁处置"], 1.2),
            CouncilMember("Architect", "架构师", ["系统设计", "安全架构"], 1.0),
        ]
        self.decision_history: List[CouncilDecision] = []

    def add_member(self, name: str, role: str, expertise: List[str], vote_weight: float = 1.0):
        self.members.append(CouncilMember(name, role, expertise, vote_weight))

    def vote(self, proposal: str, context: Dict[str, Any] = None) -> CouncilDecision:
        votes = {}
        supporting_reasons = []
        opposing_reasons = []
        total_weight = sum(m.vote_weight for m in self.members)
        yes_weight = 0.0

        for member in self.members:
            vote = self._member_vote(member, proposal, context)
            votes[member.name] = vote
            if vote == "yes":
                yes_weight += member.vote_weight
                supporting_reasons.append(f"{member.role}({member.name}): 同意")
            elif vote == "no":
                opposing_reasons.append(f"{member.role}({member.name}): 反对")
            else:
                opposing_reasons.append(f"{member.role}({member.name}): 弃权")

        confidence = yes_weight / total_weight if total_weight > 0 else 0.0
        final_decision = "approve" if confidence >= 0.6 else "reject"

        decision = CouncilDecision(
            proposal=proposal,
            supporting_reasons=supporting_reasons,
            opposing_reasons=opposing_reasons,
            confidence=confidence,
            final_decision=final_decision,
            votes=votes,
        )

        self.decision_history.append(decision)
        logger.info(f"[Council] 决策: {final_decision}, 置信度: {confidence:.2f}")

        return decision

    def _member_vote(self, member: CouncilMember, proposal: str, context: Dict[str, Any] = None) -> str:
        proposal_lower = proposal.lower()

        if any(e in proposal_lower for e in member.expertise):
            if "漏洞" in proposal_lower or "攻击" in proposal_lower:
                if member.role == "安全分析师":
                    return "yes"
                if member.role == "渗透测试专家":
                    return "yes"
            if "代码" in proposal_lower or "审计" in proposal_lower:
                if member.role == "代码审查专家":
                    return "yes"
            if "事件" in proposal_lower or "应急" in proposal_lower:
                if member.role == "应急响应专家":
                    return "yes"
            return "yes"
        else:
            return "abstain"

    def get_decision_history(self) -> List[Dict[str, Any]]:
        return [
            {
                "proposal": d.proposal,
                "decision": d.final_decision,
                "confidence": d.confidence,
                "votes": d.votes,
            }
            for d in self.decision_history
        ]

    def get_summary(self) -> Dict[str, Any]:
        total_decisions = len(self.decision_history)
        approved = sum(1 for d in self.decision_history if d.final_decision == "approve")
        rejected = total_decisions - approved
        avg_confidence = sum(d.confidence for d in self.decision_history) / total_decisions if total_decisions > 0 else 0.0

        return {
            "members": [{"name": m.name, "role": m.role} for m in self.members],
            "total_decisions": total_decisions,
            "approved": approved,
            "rejected": rejected,
            "avg_confidence": avg_confidence,
        }
