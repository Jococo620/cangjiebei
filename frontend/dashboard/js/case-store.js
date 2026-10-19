export const CASE_STAGES = [
    { id: "normal", label: "系统正常运行" },
    { id: "detect", label: "检测到 SQL 注入" },
    { id: "correlate", label: "关联攻击证据" },
    { id: "reason", label: "AI 风险研判" },
    { id: "approve", label: "等待 HITL 审批" },
    { id: "approved", label: "操作员已批准" },
    { id: "execute", label: "执行限时封禁" },
    { id: "verify", label: "复测攻击失效" },
    { id: "audit", label: "生成审计闭环" },
];

const INITIAL_STATE = Object.freeze({
    mode: "replay",
    source: "等待场景输入",
    scenarioSource: "等待场景输入",
    caseId: "CASE-WAITING",
    title: "等待场景输入",
    summary: "请在上方输入安全场景，由智能体生成演示流程。",
    risk: "待评估",
    riskLabel: "待评估",
    riskClass: "risk-pending",
    truthState: "initial",
    status: "waiting",
    currentStage: 0,
    furthestStage: 0,
    rejectedStage: null,
    decision: "pending",
    execution: "not-executed",
    verification: "not-verified",
    auditId: "",
    decisionSource: "",
    executionSource: "",
    verificationSource: "",
    auditSource: "",
    executionReceiptId: "",
    verificationReceiptId: "",
    elapsedSec: 0,
    startedAt: "",
    completedAt: "",
    autoplay: false,
    summaryTitle: "等待场景输入",
    summaryText: "请在上方输入安全场景描述，点击「智能体生成演示」后开始。",
    auditEvents: [],
});

export const CASE_TRUTH_STATES = Object.freeze({
    initial: Object.freeze({
        currentStage: 0,
        status: "ready",
        decision: "pending",
        execution: "not-executed",
        verification: "not-verified",
    }),
    attack_detected: Object.freeze({
        currentStage: 1,
        status: "running",
        decision: "pending",
        execution: "not-executed",
        verification: "not-verified",
    }),
    evidence_collected: Object.freeze({
        currentStage: 2,
        status: "running",
        decision: "pending",
        execution: "not-executed",
        verification: "not-verified",
    }),
    ai_assessed: Object.freeze({
        currentStage: 3,
        status: "running",
        decision: "pending",
        execution: "not-executed",
        verification: "not-verified",
    }),
    pending_approval: Object.freeze({
        currentStage: 4,
        status: "awaiting-approval",
        decision: "pending",
        execution: "not-executed",
        verification: "not-verified",
    }),
    approved_not_executed: Object.freeze({
        currentStage: 5,
        status: "approved",
        decision: "approved",
        execution: "not-executed",
        verification: "not-verified",
    }),
    rejected: Object.freeze({
        currentStage: 4,
        status: "rejected",
        decision: "rejected",
        execution: "not-executed",
        verification: "not-verified",
    }),
    expired: Object.freeze({
        currentStage: 4,
        status: "expired",
        decision: "expired",
        execution: "not-executed",
        verification: "not-verified",
    }),
    executing: Object.freeze({
        currentStage: 6,
        status: "executing",
        decision: "approved",
        execution: "executing",
        verification: "not-verified",
    }),
    execution_failed: Object.freeze({
        currentStage: 6,
        status: "execution_failed",
        decision: "approved",
        execution: "failed",
        verification: "not-verified",
    }),
    executed_not_verified: Object.freeze({
        currentStage: 6,
        status: "executed",
        decision: "approved",
        execution: "executed",
        verification: "not-verified",
    }),
    verification_failed: Object.freeze({
        currentStage: 7,
        status: "verification_failed",
        decision: "approved",
        execution: "executed",
        verification: "failed",
    }),
    verified_not_closed: Object.freeze({
        currentStage: 7,
        status: "verified",
        decision: "approved",
        execution: "executed",
        verification: "passed",
    }),
    completed: Object.freeze({
        currentStage: 8,
        status: "completed",
        decision: "approved",
        execution: "executed",
        verification: "passed",
    }),
});

const STATE_STORAGE_KEY = "cangsight-judge-case-v1";
const PERSISTED_FIELDS = Object.freeze([
    "mode",
    "source",
    "scenarioSource",
    "caseId",
    "title",
    "summary",
    "risk",
    "riskLabel",
    "riskClass",
    "truthState",
    "status",
    "currentStage",
    "furthestStage",
    "rejectedStage",
    "decision",
    "execution",
    "verification",
    "auditId",
    "decisionSource",
    "executionSource",
    "verificationSource",
    "auditSource",
    "executionReceiptId",
    "verificationReceiptId",
    "elapsedSec",
    "startedAt",
    "completedAt",
    "summaryTitle",
    "summaryText",
    "auditEvents",
]);

function inferTruthState(state) {
    const byStatus = {
        rejected: "rejected",
        expired: "expired",
        failed: "execution_failed",
        execution_failed: "execution_failed",
        verification_failed: "verification_failed",
        executing: "executing",
        executed: "executed_not_verified",
        verified: "verified_not_closed",
        completed: "completed",
        approved: "approved_not_executed",
        "awaiting-approval": "pending_approval",
    };
    if (byStatus[state?.status]) return byStatus[state.status];
    const byStage = [
        "initial",
        "attack_detected",
        "evidence_collected",
        "ai_assessed",
        "pending_approval",
        "approved_not_executed",
        "executed_not_verified",
        "verified_not_closed",
        "completed",
    ];
    return byStage[state?.currentStage] || "initial";
}

function cloneInitial() {
    return {
        ...INITIAL_STATE,
        auditEvents: [],
    };
}

function loadPersistedReplay() {
    try {
        const raw = window.sessionStorage.getItem(STATE_STORAGE_KEY);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        if (parsed?.mode !== "replay") return null;
        const stage = Number.parseInt(parsed.currentStage, 10);
        if (!Number.isInteger(stage) || stage < 0 || stage >= CASE_STAGES.length) {
            return null;
        }
        const restored = {};
        PERSISTED_FIELDS.forEach((field) => {
            if (Object.hasOwn(parsed, field)) restored[field] = parsed[field];
        });
        restored.currentStage = stage;
        restored.furthestStage = Math.max(stage, Number.parseInt(restored.furthestStage, 10) || 0);
        restored.elapsedSec = Math.max(0, Number.parseInt(restored.elapsedSec, 10) || 0);
        restored.auditEvents = Array.isArray(restored.auditEvents)
            ? restored.auditEvents.slice(-50)
            : [];
        restored.autoplay = false;
        return restored;
    } catch {
        return null;
    }
}

class CaseStore {
    constructor() {
        const restored = {
            ...cloneInitial(),
            ...loadPersistedReplay(),
        };
        const truthState = Object.hasOwn(CASE_TRUTH_STATES, restored.truthState)
            ? restored.truthState
            : inferTruthState(restored);
        this.state = {
            ...restored,
            ...CASE_TRUTH_STATES[truthState],
            truthState,
        };
        this.listeners = new Set();
    }

    subscribe(listener) {
        this.listeners.add(listener);
        listener(this.state);
        return () => this.listeners.delete(listener);
    }

    patch(fields) {
        this.state = {
            ...this.state,
            ...fields,
        };
        this.persist();
        this.emit();
    }

    setTruthState(truthState, fields = {}) {
        const semanticState = CASE_TRUTH_STATES[truthState];
        if (!semanticState) {
            throw new TypeError(`Unknown case truth state: ${truthState}`);
        }
        this.patch({
            ...fields,
            ...semanticState,
            truthState,
        });
    }

    addAudit(event) {
        this.state = {
            ...this.state,
            auditEvents: [
                ...this.state.auditEvents,
                {
                    time: new Date().toISOString(),
                    ...event,
                },
            ],
        };
        this.persist();
        this.emit();
    }

    reset() {
        this.state = cloneInitial();
        this.persist();
        this.emit();
    }

    loadScenario(scenarioData) {
        const c = scenarioData?.case || {};
        this.state = {
            ...cloneInitial(),
            mode: "replay",
            source: "智能体生成回放",
            scenarioSource: "智能体生成回放",
            caseId: c.caseId || `CASE-AUTO-${Date.now()}`,
            title: c.title || "安全事件分析",
            summary: c.summary || "智能体生成的安全场景回放。",
            risk: c.risk || "高风险",
            riskLabel: c.risk || "高风险",
            riskClass: c.riskClass || "risk-high",
            status: "ready",
            truthState: "initial",
            currentStage: 0,
            furthestStage: 0,
            auditId: scenarioData?.auditId || "",
            executionReceiptId: scenarioData?.executionReceiptId || "",
            verificationReceiptId: scenarioData?.verificationReceiptId || "",
            summaryTitle: c.title || "安全事件分析",
            summaryText: c.summary || "智能体生成的安全场景回放。",
            auditEvents: [],
        };
        this.persist();
        this.emit();
    }

    persist() {
        try {
            if (this.state.mode !== "replay") {
                window.sessionStorage.removeItem(STATE_STORAGE_KEY);
                return;
            }
            const persisted = {};
            PERSISTED_FIELDS.forEach((field) => {
                persisted[field] = this.state[field];
            });
            window.sessionStorage.setItem(STATE_STORAGE_KEY, JSON.stringify(persisted));
        } catch {
            // Private browsing or storage policies may disable session storage.
        }
    }

    emit() {
        this.listeners.forEach((listener) => listener(this.state));
    }
}

export const caseStore = new CaseStore();

