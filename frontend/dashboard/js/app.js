import { api } from "./api-client.js";
import { CASE_STAGES, CASE_TRUTH_STATES, caseStore } from "./case-store.js";
import { initCapabilityLab } from "./capability-lab.js";
import { initModelSettings } from "./model-settings.js";
import { initXdrSettings } from "./xdr-settings.js";
import { initAttackChain } from "./attack-chain.js";

const STATUS_COPY = {
    ready: { label: "等待开始", className: "state-ready" },
    running: { label: "正在推进", className: "state-running" },
    "awaiting-approval": { label: "等待人工批准", className: "state-pending" },
    approved: { label: "已批准，未执行", className: "state-pending" },
    executing: { label: "正在执行", className: "state-running" },
    executed: { label: "已执行，待验证", className: "state-running" },
    verified: { label: "验证通过，待审计", className: "state-running" },
    completed: { label: "闭环完成", className: "state-completed" },
    pending: { label: "结果待确认", className: "state-pending" },
    rejected: { label: "已拒绝，未执行", className: "state-failed" },
    expired: { label: "已过期，未执行", className: "state-failed" },
    execution_failed: { label: "执行失败", className: "state-failed" },
    verification_failed: { label: "复测失败，未闭环", className: "state-failed" },
    failed: { label: "执行失败", className: "state-failed" },
    offline: { label: "离线回放", className: "state-pending" },
};

const STEP_STATUS = {
    pending: "待执行",
    current: "当前",
    complete: "已完成",
    rejected: "已拒绝",
};

const DEFAULT_STAGE_COPY = Object.freeze([
    {
        status: "ready",
        summary: "教学商城处于正常基线，等待开始样例回放。",
        title: "未发现异常",
        detail: "请求速率和数据库响应均处于教学基线范围。",
        confidence: "基线",
        topology: "基线正常，尚未检测到攻击",
        evidence: [
            ["等待攻击样本", "pending"],
            ["等待关联", "pending"],
            ["等待确认", "pending"],
            ["等待 RAG", "pending"],
        ],
        progressLabel: "正常运行",
        actions: [
            { type: "thought", name: "基线监控", detail: "请求速率与数据库响应均处于基线，持续监测无异常" },
        ],
    },
    {
        status: "running",
        summary: "XDR 检测到包含布尔盲注特征的异常订单查询。",
        title: "发现 SQL 注入攻击",
        detail: "请求载荷命中 SQL 注入规则，攻击源为脱敏保留地址 203.0.113.24。",
        confidence: "72%",
        topology: "恶意请求已到达 Web 应用，检测节点产生告警",
        evidence: [
            ["' OR 1=1 --", "active"],
            ["响应时延 +824 ms", "active"],
            ["订单 API", "active"],
            ["等待 RAG", "pending"],
        ],
        progressLabel: "发现注入",
        actions: [
            { type: "thought", name: "研判思考", detail: "检测到异常订单查询，载荷疑似布尔盲注" },
            { type: "tool", name: "XDR 规则引擎", detail: "命中 SQL 注入规则，响应时延 +824ms，攻击源 203.0.113.24" },
        ],
    },
    {
        status: "running",
        summary: "请求载荷、响应时延、资产角色和数据库审计片段已被关联。",
        title: "四类证据指向同一攻击链",
        detail: "XDR 遥测与数据库只读审计记录在同一时间窗内吻合，核心资产尚未发现数据写入。",
        confidence: "89%",
        topology: "攻击路径与资产证据完成关联，证据送达 AI 智能体",
        evidence: [
            ["' OR 1=1 --", "complete"],
            ["响应时延 +824 ms", "complete"],
            ["核心资产受探测", "complete"],
            ["等待 RAG", "active"],
        ],
        progressLabel: "汇聚证据",
        actions: [
            { type: "tool", name: "RAG 检索", detail: "检索 SQL 注入处置基线，锚定知识证据" },
            { type: "rag", name: "CWE-89", detail: "命中 SQL 注入（CWE-89）处置基线 3 条" },
        ],
    },
    {
        status: "running",
        summary: "AI 结合直接证据与 RAG 基线，判定为高置信 SQL 注入尝试。",
        title: "高风险，建议限时封禁",
        detail: "建议封禁源 IP 15 分钟并立即复测。证据未支持永久封禁或隔离业务主机。",
        confidence: "94%",
        topology: "AI 已形成可解释建议，尚未触发任何处置",
        evidence: [
            ["' OR 1=1 --", "complete"],
            ["响应时延 +824 ms", "complete"],
            ["核心资产受探测", "complete"],
            ["CWE-89 处置基线", "complete"],
        ],
        progressLabel: "AI 研判",
        actions: [
            { type: "tool", name: "SymPas code_scan", detail: "静态扫描注入载荷，确认危险点位于 /api/orders" },
            { type: "rag", name: "CWE-89", detail: "引用 CWE-89 处置基线，建议限时封禁" },
            { type: "cot", name: "可验证推理", detail: "注入特征明确 + 响应差异 +824ms + 无数据写入 → 高置信" },
        ],
    },
    {
        status: "awaiting-approval",
        summary: "高风险动作已停在 HITL 节点，等待操作员核对影响与回滚方式。",
        title: "等待人工批准",
        detail: "当前没有执行封禁。批准或拒绝必须由操作员明确提交。",
        confidence: "94%",
        topology: "处置路径暂停在 HITL，临时策略尚未下发",
        evidence: [
            ["攻击载荷已确认", "complete"],
            ["响应差异已确认", "complete"],
            ["影响范围已核对", "complete"],
            ["CWE-89 已引用", "complete"],
        ],
        progressLabel: "等待审批",
        actions: [
            { type: "hitl", name: "HITL 审批", detail: "高风险动作暂停，等待操作员核对影响与回滚方式" },
        ],
    },
    {
        status: "approved",
        summary: "操作员已批准限时封禁，动作仍处于未执行状态。",
        title: "已批准，等待执行",
        detail: "批准记录只授权目标为 203.0.113.24、时长为 15 分钟的临时策略。",
        confidence: "已批准",
        topology: "HITL 决策已记录，策略节点等待执行回执",
        evidence: [
            ["攻击载荷已确认", "complete"],
            ["响应差异已确认", "complete"],
            ["影响范围已核对", "complete"],
            ["批准范围已锁定", "complete"],
        ],
        progressLabel: "人工批准",
        actions: [
            { type: "hitl", name: "人工批准", detail: "批准限时封禁 203.0.113.24 共 15 分钟，锁定执行范围" },
        ],
    },
    {
        status: "executed",
        summary: "样例执行器返回临时封禁策略已生效，下一步需要重新发起攻击复测。",
        title: "限时封禁已执行",
        detail: "处置成功来自样例执行回执，不来自倒计时推断。真实模式仅展示服务端最终结果。",
        confidence: "已执行",
        topology: "临时策略已下发，攻击源访问路径被阻断",
        evidence: [
            ["攻击载荷已确认", "complete"],
            ["响应差异已确认", "complete"],
            ["策略回执已收到", "complete"],
            ["等待复测", "active"],
        ],
        progressLabel: "限时封禁",
        actions: [
            { type: "tool", name: "防火墙封禁", detail: "下发临时封禁策略，执行器返回已生效回执" },
        ],
    },
    {
        status: "verified",
        summary: "同一攻击请求复测返回 403，数据库不再收到对应查询。",
        title: "复测确认攻击失效",
        detail: "复测结果与数据库遥测同时满足验证条件，处置结果可以进入审计收口。",
        confidence: "已验证",
        topology: "攻击路径中断，Web 与数据库遥测确认没有穿透",
        evidence: [
            ["复测响应 403", "complete"],
            ["数据库查询 0 次", "complete"],
            ["策略仍在有效期", "complete"],
            ["审计摘要待生成", "active"],
        ],
        progressLabel: "复测验证",
        actions: [
            { type: "verify", name: "复测验证", detail: "重放同一攻击请求返回 403，数据库 0 次查询，确认攻击失效" },
        ],
    },
    {
        status: "completed",
        summary: "发现、研判、审批、处置和复测均已形成可追溯记录。",
        title: "可信安全事件闭环完成",
        detail: "样例审计编号可用于答辩回看。真实 EAT 会话仍需在审计页单独验证签名链。",
        confidence: "闭环",
        topology: "处置与验证证据已汇入审计节点，事件闭环完成",
        evidence: [
            ["复测响应 403", "complete"],
            ["数据库查询 0 次", "complete"],
            ["执行回执已关联", "complete"],
            ["审计摘要已生成", "complete"],
        ],
        progressLabel: "审计闭环",
        actions: [
            { type: "cot", name: "闭环推理", detail: "发现→研判→审批→处置→复测全程留痕，形成可信闭环" },
            { type: "tool", name: "EAT 审计", detail: "生成审计摘要，回执纳入 EAT 签名链" },
        ],
    },
]);

let STAGE_COPY = DEFAULT_STAGE_COPY.map((stage) => ({
    ...stage,
    evidence: stage.evidence.map((e) => [...e]),
    actions: (stage.actions || []).map((a) => ({ ...a })),
}));

let PROGRESS_LABELS = CASE_STAGES.map((s) => s.label);

const DEMO_STAGE_TARGET_SECONDS = Object.freeze([0, 15, 35, 55, 80, 105, 125, 145, 165]);
const DEMO_DURATION_SECONDS = DEMO_STAGE_TARGET_SECONDS.at(-1);
const DEMO_TIME_SCALE = (() => {
    const raw = new URLSearchParams(window.location.search).get("test-time-scale");
    if (raw === null) return 1;
    const requested = Number.parseFloat(raw);
    if (!Number.isFinite(requested)) return 1;
    return Math.max(0.001, Math.min(1, requested));
})();

const DEFAULT_SAMPLE_RECEIPTS = Object.freeze({
    execution: {
        id: "FIXTURE-EXEC-SQLI-006",
        status: "executed",
        source: "官方样例执行回执",
    },
    verification: {
        id: "FIXTURE-VERIFY-SQLI-007",
        status: "passed",
        source: "官方样例复测回执",
    },
    audit: {
        id: "EAT-DEMO-0726-009",
        source: "样例审计摘要，非真实 EAT 签名链",
    },
});

let SAMPLE_RECEIPTS = {
    execution: { ...DEFAULT_SAMPLE_RECEIPTS.execution },
    verification: { ...DEFAULT_SAMPLE_RECEIPTS.verification },
    audit: { ...DEFAULT_SAMPLE_RECEIPTS.audit },
};

const TOPOLOGY_STAGE_STATE = Object.freeze([
    {
        nodes: { web: "complete", database: "complete" },
        edges: {},
    },
    {
        nodes: { attacker: "danger", web: "danger", xdr: "active", database: "pending" },
        edges: { "attack-entry": "danger", "asset-path": "danger", telemetry: "active" },
    },
    {
        nodes: { attacker: "danger", web: "danger", database: "pending", xdr: "complete", ai: "active" },
        edges: {
            "attack-entry": "danger",
            "asset-path": "danger",
            telemetry: "complete",
            evidence: "active",
        },
    },
    {
        nodes: { attacker: "danger", web: "danger", database: "pending", xdr: "complete", ai: "complete", hitl: "active" },
        edges: {
            "attack-entry": "danger",
            "asset-path": "danger",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "active",
        },
    },
    {
        nodes: { attacker: "danger", web: "danger", database: "pending", xdr: "complete", ai: "complete", hitl: "pending" },
        edges: {
            "attack-entry": "danger",
            "asset-path": "danger",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
        },
    },
    {
        nodes: { attacker: "danger", web: "danger", database: "pending", xdr: "complete", ai: "complete", hitl: "complete", policy: "active" },
        edges: {
            "attack-entry": "danger",
            "asset-path": "danger",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
            approval: "complete",
        },
    },
    {
        nodes: { attacker: "blocked", web: "complete", database: "complete", xdr: "complete", ai: "complete", hitl: "complete", policy: "complete", audit: "active" },
        edges: {
            "attack-entry": "interrupted",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
            approval: "complete",
            enforcement: "complete",
            audit: "active",
        },
    },
    {
        nodes: { attacker: "blocked", web: "complete", database: "complete", xdr: "complete", ai: "complete", hitl: "complete", policy: "complete", audit: "active" },
        edges: {
            "attack-entry": "interrupted",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
            approval: "complete",
            enforcement: "complete",
            verification: "complete",
            audit: "active",
        },
    },
    {
        nodes: { attacker: "blocked", web: "complete", database: "complete", xdr: "complete", ai: "complete", hitl: "complete", policy: "complete", audit: "complete" },
        edges: {
            "attack-entry": "interrupted",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
            approval: "complete",
            enforcement: "complete",
            verification: "complete",
            audit: "complete",
        },
    },
]);

const DEFAULT_TRUTH_STATE_COPY = Object.freeze({
    initial: Object.freeze({
        control: ["未申请", "尚未形成处置建议，任何高风险动作都不会自动执行。", "is-pending"],
    }),
    attack_detected: Object.freeze({
        control: ["未申请", "系统正在关联攻击证据，尚未提出高风险处置。", "is-pending"],
    }),
    evidence_collected: Object.freeze({
        control: ["未申请", "证据正在送往 AI 研判，尚未提出高风险处置。", "is-pending"],
    }),
    ai_assessed: Object.freeze({
        control: ["待申请", "AI 已提出限时封禁建议，但尚未获得人工授权。", "is-pending"],
    }),
    pending_approval: Object.freeze({
        control: ["等待批准", "智能体已暂停。必须由操作员明确批准或拒绝。", "is-pending"],
    }),
    approved_not_executed: Object.freeze({
        control: ["已批准", "批准只代表授权；尚未收到执行回执，动作仍为未执行。", "is-complete"],
        toast: "已记录样例批准，动作仍未执行",
    }),
    rejected: Object.freeze({
        terminal: true,
        confidence: "已拒绝",
        summary: "操作员拒绝限时封禁，系统保留证据但不执行处置。",
        title: "已拒绝，动作未执行",
        detail: "攻击路径仍可能有效。可以补充证据、调整建议或重新发起审批。",
        topology: "操作员拒绝处置，路径在 HITL 节点中断，未执行封禁",
        control: ["已拒绝", "操作员拒绝请求，没有执行任何封禁动作。", "is-failed"],
        toast: "操作员已拒绝处置，未执行高风险动作",
        toastType: "error",
    }),
    expired: Object.freeze({
        terminal: true,
        confidence: "已过期",
        summary: "审批窗口已结束，系统没有执行处置动作。",
        title: "审批已过期，动作未执行",
        detail: "需要重新核对证据并创建新的审批请求，不能沿用已过期授权。",
        topology: "审批请求已过期，路径在 HITL 节点中断，未执行封禁",
        control: ["已过期", "审批请求已过期，没有执行任何封禁动作。", "is-failed"],
        toast: "审批请求已过期，未执行高风险动作",
        toastType: "error",
    }),
    executing: Object.freeze({
        awaitExternal: true,
        confidence: "执行中",
        summary: "审批已经通过，动作进入执行阶段，正在等待执行器最终回执。",
        title: "处置正在执行",
        detail: "任务已进入 executing。此时不会显示为已过期，也不会提前宣称攻击已阻断。",
        topology: "处置动作正在执行，攻击失效仍需等待执行与复测回执",
        control: ["执行中", "审批已通过，执行器正在运行，尚无最终结果。", "is-pending"],
    }),
    execution_failed: Object.freeze({
        terminal: true,
        confidence: "执行失败",
        summary: "审批已经通过，但执行器返回失败。动作未完成，攻击仍可能有效。",
        title: "执行失败，攻击未阻断",
        detail: "需要操作员检查执行器、目标与回滚状态；未收到成功回执前不得进入复测成功或闭环。",
        topology: "动作执行失败，处置路径在策略节点中断，攻击仍可能有效",
        control: ["执行失败", "审批已通过，但执行器返回失败。攻击不视为已阻断。", "is-failed"],
        toast: "执行器返回失败，动作未完成，攻击仍可能有效",
        toastType: "error",
        evidence: [
            ["攻击载荷已确认", "complete"],
            ["批准范围已确认", "complete"],
            ["执行器失败回执", "complete"],
            ["复测未执行", "pending"],
        ],
    }),
    executed_not_verified: Object.freeze({
        confidence: "已执行",
        summary: "执行器已返回动作完成回执，但攻击是否失效仍需复测证明。",
        title: "处置已执行，等待复测",
        detail: "批准与执行均已记录；缺少 verification_status 时，不显示攻击已阻断或闭环完成。",
        topology: "临时策略执行回执已收到，攻击失效仍待复测证明",
        control: ["已批准", "执行回执已收到，处置效果仍需以复测证据为准。", "is-complete"],
    }),
    verification_failed: Object.freeze({
        terminal: true,
        confidence: "复测失败",
        summary: "处置动作已有执行回执，但复测没有证明攻击失效，事件不能闭环。",
        title: "复测失败，尚未闭环",
        detail: "需要检查策略生效范围并重新处置。执行成功不等于验证成功。",
        topology: "策略已执行，但复测未证明攻击失效，路径在验证节点中断",
        control: ["复测失败", "动作已执行，但复测证据不足以证明攻击失效。", "is-failed"],
        toast: "复测未证明攻击失效，事件不能闭环",
        toastType: "error",
        evidence: [
            ["执行成功回执", "complete"],
            ["复测请求已发起", "complete"],
            ["攻击仍可达或结果缺失", "active"],
            ["闭环条件未满足", "pending"],
        ],
    }),
    verified_not_closed: Object.freeze({
        confidence: "已验证",
        control: ["已验证", "执行与复测证据均成立，等待生成审计摘要。", "is-complete"],
    }),
    completed: Object.freeze({
        terminal: true,
        control: ["闭环完成", "审批、执行、复测与审计摘要已经关联。", "is-complete"],
        toast: "样例闭环已完成；真实 EAT 签名链仍需在审计页验证",
    }),
});

let TRUTH_STATE_COPY = JSON.parse(JSON.stringify(DEFAULT_TRUTH_STATE_COPY));

const REPLAY_TRUTH_STATES = Object.freeze([
    "initial",
    "attack_detected",
    "evidence_collected",
    "ai_assessed",
    "pending_approval",
    "approved_not_executed",
    "executed_not_verified",
    "verified_not_closed",
    "completed",
]);

const ROUTES = Object.freeze({
    "": { view: "home", title: "首页", mode: "home" },
    workbench: { view: "workbench", title: "能力工作台", mode: "workbench" },
    judge: { view: "current-case", title: "过程展示", mode: "judge" },
    "xdr-monitor": { view: "xdr-monitor", title: "XDR 实时监测" },
    chat: { view: "capabilities", lab: "chat", title: "安全对话" },
    ctf: { view: "capabilities", lab: "ctf", title: "CTF攻防" },
    "threat-analysis": { view: "capabilities", lab: "threat", title: "威胁分析" },
    "code-scan": { view: "capabilities", lab: "code", title: "代码扫描" },
    "cwe-kb": { view: "capabilities", lab: "cwe", title: "CWE知识库" },
    "ooda-timeline": { view: "attack-chain", title: "OODA决策循环" },
    "rag-evidence": { view: "evidence", title: "证据锚定RAG" },
    "eat-chain": {
        view: "audit",
        focus: "#audit-overview-title",
        title: "EAT审计链",
    },
    "hitl-approval": { view: "hitl", title: "HITL人机协同" },
    audit: { view: "case-history", title: "审计日志" },
    settings: { view: "connections", title: "系统设置" },
});

const STAGE_DETAIL_ROUTES = Object.freeze([
    { route: "settings", label: "查看运行边界" },
    { route: "threat-analysis", label: "查看原始请求" },
    { route: "rag-evidence", label: "查看关联证据" },
    { route: "rag-evidence", label: "查看研判依据" },
    { route: "hitl-approval", label: "查看审批任务" },
    { route: "hitl-approval", label: "查看授权记录" },
    { route: "eat-chain", label: "查看执行回执" },
    { route: "threat-analysis", label: "查看复测证据" },
    { route: "eat-chain", label: "验证审计记录" },
]);

const LAB_ROUTES = Object.freeze({
    chat: "chat",
    threat: "threat-analysis",
    code: "code-scan",
    cwe: "cwe-kb",
    ctf: "ctf",
    ooda: "ooda-timeline",
});

const els = (() => {
    const $ = (selector) => document.querySelector(selector);
    const $$ = (selector) => [...document.querySelectorAll(selector)];
    return {
        html: document.documentElement,
        main: $("#main"),
        routeHeading: $("#route-heading"),
        sidebar: $("#primary-sidebar"),
        navToggle: $("#nav-toggle"),
        navLinks: $$("[data-route]"),
        caseDemoLinks: $$("[data-case-demo]"),
        views: $$("[data-view-panel]"),
        interfaceButtons: $$("[data-interface-target]"),
        themeToggle: $("#theme-toggle"),
        connectionButton: $("#connection-button"),
        connectionLabel: $("#connection-label"),
        topSource: $("#top-source"),
        caseSource: $("#case-source"),
        caseTitle: $("#case-title"),
        caseRisk: $("#case-risk"),
        caseSummary: $("#case-summary"),
        caseId: $("#case-id"),
        caseStage: $("#case-stage"),
        caseElapsed: $("#case-elapsed"),
        overallState: $("#overall-state"),
        timelineSteps: $$(".judge-progress-step"),
        summaryTitle: $("#decision-summary-title"),
        summaryText: $("#decision-summary-text"),
        aiConfidence: $("#ai-confidence"),
        agentActionList: $("#agent-action-list"),
        stageDetailLink: $("#stage-detail-link"),
        topologyStatus: $("#topology-status"),
        topologyNodes: $$(".topology-node"),
        topologyEdges: $$(".topology-edge"),
        evidenceCount: $("#evidence-count"),
        keyEvidenceItems: $$("#key-evidence-list li"),
        approvalState: $("#approval-state"),
        approvalDetail: $("#approval-detail"),
        executionState: $("#execution-state"),
        verificationState: $("#verification-state"),
        auditId: $("#audit-id"),
        receiptProvenance: $("#receipt-provenance"),
        receiptProvenanceSummary: $("#receipt-provenance-summary"),
        receiptProvenanceList: $("#receipt-provenance-list"),
        modeNotice: $("#mode-notice"),
        startReplay: $("#start-replay"),
        demoPrev: $("#demo-prev"),
        resumeFurthest: $("#resume-furthest"),
        demoPlay: $("#demo-play"),
        reviewLiveApproval: $("#review-live-approval"),
        syncLive: $("#sync-live"),
        resetCase: $("#reset-case"),
        toggleZoom: $("#toggle-zoom"),
        scenarioInput: $("#scenario-input"),
        scenarioSubmit: $("#scenario-submit"),
        scenarioStatus: $("#scenario-status"),
        scenarioPresets: $$(".scenario-preset"),
        scenarioLibraryToggle: $("#scenario-library-toggle"),
        scenarioCards: $$(".scenario-card"),
        agentStatus: $("#agent-status"),
        approvalDialog: $("#approval-dialog"),
        approvalConfirm: $("#approval-confirm"),
        approveAction: $("#approve-action"),
        rejectAction: $("#reject-action"),
        approvalActionText: $("#approval-action-text"),
        approvalTargetText: $("#approval-target-text"),
        approvalImpactText: $("#approval-impact-text"),
        approvalRollbackText: $("#approval-rollback-text"),
        liveRegion: $("#live-region"),
        toastRegion: $("#toast-region"),
        refreshRuns: $("#refresh-runs"),
        runsBody: $("#runs-table-body"),
        historyLatest: $("#history-latest"),
        historyLatestDetail: $("#history-latest-detail"),
        metricRuns: $("#metric-runs"),
        metricApprovals: $("#metric-approvals"),
        metricAudits: $("#metric-audits"),
        hitlRefresh: $("#hitl-refresh"),
        hitlReview: $("#hitl-review"),
        hitlSummaryTitle: $("#hitl-summary-title"),
        hitlSummaryText: $("#hitl-summary-text"),
        hitlPendingCount: $("#hitl-pending-count"),
        hitlCaseStage: $("#hitl-case-stage"),
        hitlExecutionState: $("#hitl-execution-state"),
        hitlList: $("#hitl-list"),
        ragForm: $("#rag-form"),
        ragQuery: $("#rag-query"),
        ragResult: $("#rag-result"),
        ragResultMeta: $("#rag-result-meta"),
        sourceRows: $$("[data-source-key]"),
        sourceBoundary: $("#source-boundary"),
        verifyAudit: $("#verify-audit"),
        refreshAudit: $("#refresh-audit"),
        auditOverviewTitle: $("#audit-overview-title"),
        auditOverviewText: $("#audit-overview-text"),
        auditSessionCount: $("#audit-session-count"),
        auditChainState: $("#audit-chain-state"),
        auditEventList: $("#audit-event-list"),
        checkServices: $("#check-services"),
        gatewayState: $("#gateway-state"),
        gatewayUrl: $("#gateway-url"),
        gatewaySkills: $("#gateway-skills"),
        gatewayRag: $("#gateway-rag"),
        sympasUrl: $("#sympas-url"),
        sympasState: $("#sympas-state"),
    };
})();

let replayToken = 0;
let autoplayTimer = null;
let elapsedTimer = null;
let latestAuditSession = "";
let pendingLiveApproval = null;
let toastTimer = null;
let capabilityLab = null;
let approvalReturnFocus = null;
/** XDR 告警轮询（每 5s），仅在 mode === "xdr" 时存在 */
let xdrPollTimer = null;
let xdrLastPolledAt = "";

function setStateLabel(element, stateClass, text) {
    const stateClasses = [
        "state-ready",
        "state-running",
        "state-pending",
        "state-completed",
        "state-checking",
        "state-failed",
    ];
    element.classList.remove(...stateClasses);
    element.classList.add(stateClass);
    element.textContent = text;
}

function announce(message) {
    els.liveRegion.textContent = "";
    window.requestAnimationFrame(() => {
        els.liveRegion.textContent = message;
    });
}

function clearToast() {
    window.clearTimeout(toastTimer);
    toastTimer = null;
    els.toastRegion.replaceChildren();
}

function showToast(message, type = "info") {
    clearToast();
    const toast = document.createElement("div");
    const copy = document.createElement("span");
    const dismiss = document.createElement("button");
    toast.className = `toast${type === "error" ? " is-error" : ""}`;
    toast.setAttribute("role", type === "error" ? "alert" : "status");
    copy.className = "toast-copy";
    copy.textContent = message;
    dismiss.className = "toast-dismiss";
    dismiss.type = "button";
    dismiss.setAttribute("aria-label", "关闭通知");
    dismiss.textContent = "关闭";
    dismiss.addEventListener("click", clearToast);
    toast.append(copy, dismiss);
    if (els.toastRegion) {
        els.toastRegion.append(toast);
    }
    toastTimer = window.setTimeout(clearToast, 5200);
}

function safeTextContent(element, value) {
    if (element) {
        element.textContent = value;
    }
}

function safeClassToggle(element, className, force) {
    if (element) {
        element.classList.toggle(className, force);
    }
}

function safeQuery(selector) {
    return document.querySelector(selector);
}

function safeQueryAll(selector) {
    return [...document.querySelectorAll(selector)];
}

function resolveTruthState(state) {
    if (Object.hasOwn(CASE_TRUTH_STATES, state.truthState)) {
        return state.truthState;
    }
    const fallback = {
        rejected: "rejected",
        expired: "expired",
        execution_failed: "execution_failed",
        failed: "execution_failed",
        verification_failed: "verification_failed",
        executing: "executing",
        executed: "executed_not_verified",
        verified: "verified_not_closed",
        completed: "completed",
        approved: "approved_not_executed",
        "awaiting-approval": "pending_approval",
    };
    return fallback[state.status] || REPLAY_TRUTH_STATES[state.currentStage] || "initial";
}

export function setCaseTruthState(truthState, fields = {}, {
    notify = false,
} = {}) {
    const copy = TRUTH_STATE_COPY[truthState];
    if (!copy) {
        throw new TypeError(`Unknown case truth state copy: ${truthState}`);
    }
    clearToast();
    caseStore.setTruthState(truthState, fields);
    if (notify && copy.toast) {
        showToast(copy.toast, copy.toastType || "info");
    }
}

function formatTime(value) {
    if (!value) {
        return "未知";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }
    return new Intl.DateTimeFormat("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
    }).format(date);
}

function statusText(status) {
    const labels = {
        queued: "排队中",
        running: "运行中",
        completed: "已完成",
        failed: "失败",
        cancelled: "已取消",
        pending: "待审批",
        notified: "等待通知",
        approved: "已批准",
        rejected: "已拒绝",
        expired: "已过期",
        executing: "执行中",
    };
    return labels[status] || status || "未知";
}

function showRoute(routeName, {
    updateHistory = true,
    replaceHistory = false,
    labOverride = "",
    syncLab = true,
    focusMain = true,
} = {}) {
    const normalizedRoute = Object.hasOwn(ROUTES, routeName) ? routeName : "";
    const route = ROUTES[normalizedRoute];
    setInterfaceMode(route.mode || "workbench", { announceChange: false });
    const target = els.views.find((view) => view.dataset.viewPanel === route.view);
    if (!target) {
        return;
    }

    els.views.forEach((view) => {
        const active = view === target;
        view.hidden = !active;
        view.classList.toggle("is-active", active);
    });
    els.routeHeading.textContent = route.title;
    document.title = `${route.title}｜鉴真 AI 安全运营超级智能体`;

    els.navLinks.forEach((link) => {
        const active = link.dataset.route === normalizedRoute;
        link.classList.toggle("is-active", active);
        if (active) {
            link.setAttribute("aria-current", "page");
        } else {
            link.removeAttribute("aria-current");
        }
    });

    const demoActive = normalizedRoute === "";
    els.caseDemoLinks.forEach((link) => {
        link.classList.toggle("is-active", demoActive);
        if (demoActive) {
            link.setAttribute("aria-current", "page");
        } else {
            link.removeAttribute("aria-current");
        }
    });

    const labName = labOverride || route.lab;
    if (labName && syncLab) {
        capabilityLab?.selectLab(labName);
    }

    if (updateHistory) {
        const nextUrl = normalizedRoute
            ? `#${normalizedRoute}`
            : `${window.location.pathname}${window.location.search}`;
        const currentRoute = window.location.hash.replace("#", "");
        const sameRoute = normalizedRoute
            ? currentRoute === normalizedRoute
            : window.location.hash === "";
        if (!sameRoute) {
            const method = replaceHistory ? "replaceState" : "pushState";
            window.history[method](null, "", nextUrl);
        }
    }

    els.sidebar.classList.remove("is-open");
    els.navToggle.setAttribute("aria-expanded", "false");
    if (route.focus) {
        window.requestAnimationFrame(() => {
            target.querySelector(route.focus)?.scrollIntoView({ block: "start" });
        });
    } else {
        els.main.scrollTop = 0;
    }
    if (focusMain) {
        els.main.focus({ preventScroll: true });
        announce(`已打开${route.title}`);
    }
}

function setInterfaceMode(mode, { announceChange = true } = {}) {
    const nextMode = mode === "home" || mode === "judge" ? mode : "workbench";
    els.html.dataset.interfaceMode = nextMode;
    els.interfaceButtons.forEach((button) => {
        const active = button.dataset.interfaceTarget === nextMode;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
    });
    if (announceChange) {
        const labels = {
            home: "已返回首页",
            judge: "已切换到过程展示模式",
            workbench: "已切换到能力工作台",
        };
        announce(labels[nextMode] || labels.workbench);
    }
}

function formatElapsed(totalSeconds = 0) {
    const safeSeconds = Math.max(0, Number.parseInt(totalSeconds, 10) || 0);
    const minutes = String(Math.floor(safeSeconds / 60)).padStart(2, "0");
    const seconds = String(safeSeconds % 60).padStart(2, "0");
    return `${minutes}:${seconds}`;
}

function renderTopology(state) {
    const truthState = resolveTruthState(state);
    const truthCopy = TRUTH_STATE_COPY[truthState];
    const stageState = TOPOLOGY_STAGE_STATE[state.currentStage] || TOPOLOGY_STAGE_STATE[0];
    const nodeState = { ...stageState.nodes };
    const edgeState = { ...stageState.edges };

    if (["rejected", "expired"].includes(truthState)) {
        nodeState.hitl = "failed";
        delete nodeState.policy;
        edgeState.recommendation = "interrupted";
        delete edgeState.approval;
    } else if (truthState === "approved_not_executed") {
        nodeState.attacker = "danger";
        nodeState.policy = "pending";
        edgeState["attack-entry"] = "danger";
        delete edgeState.enforcement;
    } else if (truthState === "executing") {
        Object.assign(nodeState, {
            attacker: "danger",
            web: "danger",
            database: "pending",
            xdr: "complete",
            ai: "complete",
            hitl: "complete",
            policy: "active",
            audit: "pending",
        });
        Object.assign(edgeState, {
            "attack-entry": "danger",
            telemetry: "complete",
            evidence: "complete",
            recommendation: "complete",
            approval: "complete",
            enforcement: "active",
        });
        delete edgeState.verification;
        delete edgeState.audit;
    } else if (truthState === "execution_failed") {
        nodeState.policy = "failed";
        nodeState.attacker = "danger";
        nodeState.web = "danger";
        nodeState.database = "pending";
        edgeState.enforcement = "interrupted";
        edgeState["attack-entry"] = "danger";
        delete edgeState.verification;
        delete edgeState.audit;
    } else if (truthState === "executed_not_verified") {
        nodeState.attacker = "danger";
        nodeState.web = "pending";
        nodeState.database = "pending";
        edgeState["attack-entry"] = "danger";
        delete edgeState.verification;
    } else if (truthState === "verification_failed") {
        nodeState.attacker = "danger";
        nodeState.web = "danger";
        nodeState.database = "pending";
        nodeState.policy = "complete";
        nodeState.audit = "pending";
        edgeState["attack-entry"] = "danger";
        edgeState.verification = "interrupted";
        delete edgeState.audit;
    }

    els.topologyNodes.forEach((node) => {
        node.classList.remove(
            "is-active",
            "is-danger",
            "is-complete",
            "is-pending",
            "is-failed",
            "is-blocked",
        );
        const nextState = nodeState[node.dataset.node];
        if (nextState) {
            node.classList.add(`is-${nextState}`);
        }
    });
    els.topologyEdges.forEach((edge) => {
        edge.classList.remove(
            "is-active",
            "is-danger",
            "is-complete",
            "is-interrupted",
            "is-muted",
        );
        const nextState = edgeState[edge.dataset.edge];
        if (nextState) {
            edge.classList.add(`is-${nextState}`);
        } else if (state.currentStage > 0) {
            edge.classList.add("is-muted");
        }
    });

    els.topologyStatus.className = "topology-status";
    if (["execution_failed", "verification_failed"].includes(truthState)) {
        els.topologyStatus.classList.add("is-danger");
    } else if (["rejected", "expired", "pending_approval", "executing", "executed_not_verified"].includes(truthState)) {
        els.topologyStatus.classList.add("is-pending");
    } else if (["verified_not_closed", "completed"].includes(truthState)) {
        els.topologyStatus.classList.add("is-complete");
    } else if (state.currentStage > 0 && state.currentStage < 6) {
        els.topologyStatus.classList.add("is-danger");
    }
    els.topologyStatus.querySelector("strong").textContent =
        truthCopy.topology || STAGE_COPY[state.currentStage]?.topology || STAGE_COPY[0].topology;
}

function renderControlOutcome(state) {
    const truthState = resolveTruthState(state);
    const [label, detail, className] = TRUTH_STATE_COPY[truthState].control;
    els.approvalState.className = `control-state ${className}`;
    els.approvalState.textContent = label;
    els.approvalDetail.textContent = detail;

    const executionCopy = {
        "not-executed": "未执行",
        pending: "待执行",
        executing: "执行中",
        executed: "已执行",
        rejected: "未执行",
        expired: "未执行",
        failed: "执行失败",
    };
    const verificationCopy = {
        "not-verified": "未验证",
        pending: "待验证",
        passed: "攻击失效",
        failed: "验证失败",
    };
    els.executionState.textContent = executionCopy[state.execution] || "未执行";
    els.verificationState.textContent = verificationCopy[state.verification] || "未验证";
    els.auditId.textContent = state.auditId || "待生成";

    const provenance = [];
    if (state.decisionSource) {
        provenance.push(["审批", state.decisionSource]);
    }
    if (state.executionSource) {
        provenance.push([
            "执行",
            `${state.executionSource}${state.executionReceiptId ? `（${state.executionReceiptId}）` : ""}`,
        ]);
    }
    if (state.verificationSource) {
        provenance.push([
            "复测",
            `${state.verificationSource}${state.verificationReceiptId ? `（${state.verificationReceiptId}）` : ""}`,
        ]);
    }
    if (state.auditSource) {
        provenance.push(["审计", state.auditSource]);
    }
    const sourceBoundary = state.mode === "live"
        ? "本地实时，非真实 XDR"
        : "官方样例回放，非真实 EAT 签名链";
    els.receiptProvenanceSummary.textContent = provenance.length
        ? `${sourceBoundary}，${provenance.length} 类状态来源`
        : `${sourceBoundary}，尚无回执`;
    els.receiptProvenanceList.replaceChildren();
    const rows = provenance.length
        ? provenance
        : [["当前", "尚未产生审批、执行或复测回执。"]];
    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        const term = document.createElement("dt");
        const detail = document.createElement("dd");
        term.textContent = label;
        detail.textContent = value;
        row.append(term, detail);
        els.receiptProvenanceList.append(row);
    });
}

const ACTION_TYPE_META = Object.freeze({
    thought: { icon: "💭", label: "思考" },
    tool: { icon: "🔧", label: "工具" },
    rag: { icon: "📚", label: "证据" },
    cot: { icon: "🧠", label: "推理" },
    hitl: { icon: "👤", label: "审批" },
    verify: { icon: "✅", label: "复测" },
});

function renderAgentActions(actions) {
    if (!els.agentActionList) return;
    els.agentActionList.replaceChildren();
    if (!Array.isArray(actions) || !actions.length) {
        const empty = document.createElement("li");
        empty.className = "action-item is-empty";
        empty.textContent = "等待智能体动作…";
        els.agentActionList.append(empty);
        return;
    }
    actions.forEach((action) => {
        const type = action.type || "thought";
        const meta = ACTION_TYPE_META[type] || ACTION_TYPE_META.thought;
        const item = document.createElement("li");
        item.className = `action-item is-${type}`;

        const icon = document.createElement("span");
        icon.className = "action-icon";
        icon.textContent = meta.icon;

        const body = document.createElement("div");
        body.className = "action-body";
        const name = document.createElement("strong");
        name.className = "action-name";
        name.textContent = action.name || meta.label;
        const detail = document.createElement("span");
        detail.className = "action-detail";
        detail.textContent = action.detail || "";

        body.append(name, detail);
        item.append(icon, body);
        els.agentActionList.append(item);
    });
}

function renderCase(state) {
    const truthState = resolveTruthState(state);
    const truthCopy = TRUTH_STATE_COPY[truthState];
    const stageCopy = STAGE_COPY[state.currentStage] || STAGE_COPY[0];
    els.topSource.textContent = state.source;
    els.caseSource.textContent = state.source;
    els.caseTitle.textContent = state.title;
    els.caseSummary.textContent = truthCopy.summary || state.summary || stageCopy.summary;
    els.caseId.textContent = state.caseId;
    els.caseStage.textContent = PROGRESS_LABELS[state.currentStage] || CASE_STAGES[state.currentStage]?.label || "等待开始";
    els.caseElapsed.textContent = formatElapsed(state.elapsedSec);
    if (els.caseRisk) {
        const allowedRiskClasses = ["risk-high", "risk-medium", "risk-low", "risk-pending"];
        const riskClass = allowedRiskClasses.includes(state.riskClass) ? state.riskClass : "risk-high";
        els.caseRisk.textContent = state.riskLabel || state.risk || "高风险";
        els.caseRisk.className = `risk-label ${riskClass}`;
    }
    els.summaryTitle.textContent = truthCopy.title || state.summaryTitle || stageCopy.title;
    els.summaryText.textContent = truthCopy.detail || state.summaryText || stageCopy.detail;
    els.aiConfidence.textContent = truthCopy.confidence || stageCopy.confidence;
    const detailRoute = STAGE_DETAIL_ROUTES[state.currentStage] || STAGE_DETAIL_ROUTES[0];
    els.stageDetailLink.textContent = detailRoute.label;
    els.stageDetailLink.dataset.routeJump = detailRoute.route;

    const display = STATUS_COPY[CASE_TRUTH_STATES[truthState].status] || STATUS_COPY.ready;
    setStateLabel(els.overallState, display.className, display.label);

    els.timelineSteps.forEach((step, index) => {
        step.classList.remove("is-current", "is-complete", "is-rejected", "is-failed");
        const stepLabel = step.querySelector("strong");
        if (stepLabel && PROGRESS_LABELS[index]) {
            stepLabel.textContent = PROGRESS_LABELS[index];
        }
        if (truthState === "completed" || index < state.currentStage) {
            step.classList.add("is-complete");
        } else if (
            index === state.currentStage
            && ["rejected", "expired"].includes(truthState)
        ) {
            step.classList.add("is-rejected");
        } else if (
            index === state.currentStage
            && ["execution_failed", "verification_failed"].includes(truthState)
        ) {
            step.classList.add("is-failed");
        } else if (index === state.currentStage) {
            step.classList.add("is-current");
        }
    });

    const evidence = truthCopy.evidence || stageCopy.evidence;
    evidence.forEach(([copy, evidenceState], index) => {
        const item = els.keyEvidenceItems[index];
        item.classList.remove("is-active", "is-complete");
        if (evidenceState === "active" || evidenceState === "complete") {
            item.classList.add(`is-${evidenceState}`);
        }
        item.querySelector("strong").textContent = copy;
    });
    const completedEvidence = evidence.filter(([, itemState]) => itemState === "complete").length;
    els.evidenceCount.textContent = `${completedEvidence} / ${evidence.length}`;

    const terminal = Boolean(truthCopy.terminal);
    const awaitExternal = Boolean(truthCopy.awaitExternal);
    els.startReplay.disabled = state.mode !== "replay" || terminal || awaitExternal;
    els.startReplay.textContent = truthState === "pending_approval"
        ? "进行人工审批"
        : state.mode === "xdr"
            ? "XDR 实时监测（无需手动开始）"
            : state.currentStage === 0
                ? "开始演示"
                : "下一步";
    els.demoPrev.disabled = state.mode !== "replay" || state.currentStage === 0;
    els.resumeFurthest.hidden = state.mode !== "replay"
        || state.currentStage >= state.furthestStage;
    els.demoPlay.disabled = state.mode !== "replay"
        || truthState === "pending_approval"
        || awaitExternal
        || terminal;
    els.demoPlay.classList.toggle("is-playing", state.autoplay);
    els.demoPlay.setAttribute("aria-pressed", String(state.autoplay));
    els.demoPlay.textContent = state.autoplay ? "暂停播放" : "自动播放";

    const sourceOptions = [...els.modeNotice.querySelectorAll(".source-option")];
    sourceOptions.forEach((option) => option.classList.remove("is-active"));
    const explainer = els.modeNotice.querySelector(".source-explainer");
    if (state.mode === "live") {
        sourceOptions[0]?.classList.add("is-active");
        els.agentStatus.textContent = "已连接本地实时状态";
        explainer.textContent = "当前显示本地网关真实状态，处置结论只来自服务端返回。";
    } else if (state.mode === "xdr") {
        // 复用「XDR 连接」选项，若无则回落到样例选项（CSS 中 mode-notice 目前两个选项，后续加第三个亦可）
        (sourceOptions[2] || sourceOptions[1])?.classList.add("is-active");
        const provider = state.provider || "已配置 XDR 平台";
        const polledAt = state.xdrPolledAt ? `最近刷新：${state.xdrPolledAt}` : "首次加载中…";
        els.agentStatus.textContent = `XDR 实时接入 · ${provider}`;
        explainer.textContent = `当前直接连接本地/远程 ${provider} 拉取最新告警，每 5 秒自动刷新；${polledAt}。`;
    } else {
        sourceOptions[1]?.classList.add("is-active");
        els.agentStatus.textContent = truthState === "completed"
            ? "样例闭环已完成"
            : "样例回放已就绪";
        explainer.textContent = "当前使用脱敏夹具，不代表真实 XDR 生产数据。";
    }

    renderTopology(state);
    renderControlOutcome(state);
    renderAuditEvents(state.auditEvents);
    renderAgentActions(stageCopy.actions || []);
    els.hitlCaseStage.textContent = PROGRESS_LABELS[state.currentStage] || CASE_STAGES[state.currentStage]?.label || "等待同步";
    els.hitlExecutionState.textContent = els.executionState.textContent;
}

function renderAuditEvents(events) {
    els.auditEventList.replaceChildren();
    if (!events.length) {
        const item = document.createElement("li");
        const time = document.createElement("time");
        const copy = document.createElement("div");
        const title = document.createElement("strong");
        const detail = document.createElement("p");
        time.textContent = "等待运行";
        title.textContent = "尚无审计事件";
        detail.textContent = "连接真实运行或完成一次案件回放后再查看。";
        copy.append(title, detail);
        item.append(time, copy);
        els.auditEventList.append(item);
        return;
    }

    events.forEach((event) => {
        const item = document.createElement("li");
        const time = document.createElement("time");
        const copy = document.createElement("div");
        const title = document.createElement("strong");
        const detail = document.createElement("p");
        time.dateTime = event.time;
        time.textContent = formatTime(event.time);
        title.textContent = event.title;
        detail.textContent = event.detail;
        copy.append(title, detail);
        item.append(time, copy);
        els.auditEventList.append(item);
    });

    els.auditOverviewTitle.textContent = "本地回放事件已记录";
    els.auditOverviewText.textContent = "这些事件用于演示操作过程，不属于真实 EAT 签名链。真实会话会单独显示验证状态。";
}

function requestApproval(context = {}) {
    const live = context.mode === "live";
    approvalReturnFocus = document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    els.approvalActionText.textContent = context.action || "限时封禁 SQL 注入来源 IP";
    els.approvalTargetText.textContent = live
        ? context.target || "以实时审批请求为准"
        : "203.0.113.24（脱敏保留地址）";
    els.approvalImpactText.textContent = context.impact
        || (live ? "执行前请核对安全平台中的实际影响范围" : "仅拦截该来源对教学商城的访问");
    els.approvalRollbackText.textContent = context.rollback
        || (live ? "按照原工具动作或安全平台策略进行回滚" : "15 分钟后自动解除，也可立即撤销策略");
    els.approveAction.textContent = live ? "批准实时动作" : "批准样例处置";
    els.approvalConfirm.checked = false;
    els.approveAction.disabled = true;
    els.approvalDialog.returnValue = "";
    els.approvalDialog.showModal();
    window.requestAnimationFrame(() => els.approvalConfirm.focus());
    return new Promise((resolve) => {
        els.approvalDialog.addEventListener("close", () => {
            const decision = ["approve", "reject"].includes(els.approvalDialog.returnValue)
                ? els.approvalDialog.returnValue
                : "cancel";
            if (approvalReturnFocus?.isConnected) {
                approvalReturnFocus.focus({ preventScroll: true });
            }
            approvalReturnFocus = null;
            resolve(decision);
        }, { once: true });
    });
}

const DEFAULT_STAGE_AUDIT_COPY = Object.freeze([
    ["样例基线已就绪", "官方样例回放已标注，尚未执行安全动作。"],
    ["检测到 SQL 注入", "XDR 规则命中脱敏请求载荷，创建样例安全事件。"],
    ["完成证据关联", "请求、响应、资产和数据库审计片段进入同一证据上下文。"],
    ["形成处置建议", "AI 建议限时封禁源 IP，未执行高风险动作。"],
    ["进入 HITL 审批", "处置路径暂停，等待操作员明确决策。"],
    ["操作员批准处置", "批准范围锁定为脱敏源 IP 和 15 分钟临时策略。"],
    ["样例执行回执成功", "本地样例执行器返回策略已生效，处置结果标记为 executed。"],
    ["复测确认攻击失效", "同一攻击请求返回 403，数据库未收到对应查询。"],
    ["生成闭环摘要", "样例审计摘要已生成，真实 EAT 签名链需单独验证。"],
]);

let STAGE_AUDIT_COPY = DEFAULT_STAGE_AUDIT_COPY.map((item) => [...item]);

// ===== 场景动态化：注入智能体生成的场景数据 =====
function applyScenarioStageCopy(stages) {
    if (!Array.isArray(stages) || stages.length !== CASE_STAGES.length) {
        console.warn("[Scenario] stages length mismatch, expected", CASE_STAGES.length, "got", stages?.length);
        return;
    }
    STAGE_COPY = stages.map((s) => ({
        status: s.status || "ready",
        summary: s.summary || "",
        title: s.title || "",
        detail: s.detail || "",
        confidence: s.confidence || "",
        topology: s.topology || "",
        evidence: Array.isArray(s.evidence) ? s.evidence.map((e) => [...e]) : [],
        progressLabel: s.progressLabel || "",
        actions: Array.isArray(s.actions) ? s.actions.map((a) => ({ ...a })) : [],
    }));
    PROGRESS_LABELS = stages.map((s, i) => s.progressLabel || CASE_STAGES[i]?.label || "");
}

function applyScenarioTruthStates(overrides) {
    if (!overrides || typeof overrides !== "object") return;
    TRUTH_STATE_COPY = JSON.parse(JSON.stringify(DEFAULT_TRUTH_STATE_COPY));
    Object.keys(overrides).forEach((key) => {
        if (TRUTH_STATE_COPY[key]) {
            TRUTH_STATE_COPY[key] = { ...TRUTH_STATE_COPY[key], ...overrides[key] };
        }
    });
}

function applyScenarioStageAudit(audit) {
    if (!Array.isArray(audit) || audit.length !== CASE_STAGES.length) return;
    STAGE_AUDIT_COPY = audit.map((item) => [item[0] || "", item[1] || ""]);
}

function applyScenarioReceipts(result) {
    SAMPLE_RECEIPTS = {
        execution: {
            id: result?.executionReceiptId || `FIXTURE-EXEC-${Date.now()}`,
            status: "executed",
            source: "场景执行回执",
        },
        verification: {
            id: result?.verificationReceiptId || `FIXTURE-VERIFY-${Date.now()}`,
            status: "passed",
            source: "场景复测回执",
        },
        audit: {
            id: result?.auditId || `EAT-${Date.now()}`,
            source: "场景审计摘要，非真实 EAT 签名链",
        },
    };
}

const DEFAULT_TOPOLOGY_TITLE = "SQL 注入攻击与处置证据拓扑";
const DEFAULT_TOPOLOGY_DESC =
    "展示攻击源、Web 应用、数据库、XDR、AI 智能体、HITL 审批、封禁策略和审计证据之间的状态路径。";
const DEFAULT_TOPOLOGY_LABELS = Object.freeze({
    nodes: Object.freeze({
        attacker: { label: "攻击源 IP", value: "203.0.113.24" },
        web: { label: "教学商城 Web", value: "/api/orders" },
        database: { label: "订单数据库", value: "核心资产" },
        xdr: { label: "检测 / XDR", value: "规则 + 流量证据" },
        ai: { label: "AI 安全智能体", value: "证据约束研判" },
        hitl: { label: "HITL 审批", value: "保留人类控制权" },
        policy: { label: "临时封禁策略", value: "15 分钟，可回滚" },
        audit: { label: "审计证据", value: "EAT 决策回执" },
    }),
    edges: Object.freeze({
        "attack-entry": "恶意请求",
        "asset-path": "查询链路",
        "telemetry": "遥测",
        "evidence": "证据",
        "recommendation": "建议",
        "approval": "批准",
        "enforcement": "限时封禁",
        "verification": "复测",
        "audit": "回执",
    }),
});

function applyTopologyNodeLabels(labels) {
    const nodes = labels?.nodes || {};
    const edges = labels?.edges || {};
    els.topologyNodes.forEach((node) => {
        const spec = nodes[node.dataset.node];
        if (!spec) return;
        const labelEl = node.querySelector(".node-label");
        const valueEl = node.querySelector(".node-value");
        if (labelEl && spec.label != null) labelEl.textContent = spec.label;
        if (valueEl && spec.value != null) valueEl.textContent = spec.value;
    });
    els.topologyEdges.forEach((edge) => {
        const text = edges[edge.dataset.edge];
        if (!text) return;
        const textEl = edge.querySelector("text");
        if (textEl) textEl.textContent = text;
    });
}

function applyScenarioTopologyLabels(caseMeta) {
    const titleEl = document.getElementById("topology-svg-title");
    const descEl = document.getElementById("topology-svg-desc");
    if (titleEl) titleEl.textContent = caseMeta?.topologyTitle || DEFAULT_TOPOLOGY_TITLE;
    if (descEl) descEl.textContent = caseMeta?.topologyDesc || DEFAULT_TOPOLOGY_DESC;
    applyTopologyNodeLabels(caseMeta?.topologyLabels || DEFAULT_TOPOLOGY_LABELS);
}

function resetScenarioCopy() {
    STAGE_COPY = DEFAULT_STAGE_COPY.map((stage) => ({
        ...stage,
        evidence: stage.evidence.map((e) => [...e]),
        actions: (stage.actions || []).map((a) => ({ ...a })),
    }));
    PROGRESS_LABELS = CASE_STAGES.map((s) => s.label);
    TRUTH_STATE_COPY = JSON.parse(JSON.stringify(DEFAULT_TRUTH_STATE_COPY));
    STAGE_AUDIT_COPY = DEFAULT_STAGE_AUDIT_COPY.map((item) => [...item]);
    SAMPLE_RECEIPTS = {
        execution: { ...DEFAULT_SAMPLE_RECEIPTS.execution },
        verification: { ...DEFAULT_SAMPLE_RECEIPTS.verification },
        audit: { ...DEFAULT_SAMPLE_RECEIPTS.audit },
    };
    applyScenarioTopologyLabels(null);
}

function applyScenarioResult(result) {
    if (!result || result.status !== "success") {
        throw new Error(result?.message || "智能体返回格式异常");
    }
    applyScenarioStageCopy(result.stages);
    applyScenarioTruthStates(result.truthStates);
    applyScenarioStageAudit(result.stageAudit);
    applyScenarioReceipts(result);
    applyScenarioTopologyLabels(result.case);
    caseStore.loadScenario(result);
    document.querySelector(".judge-stage")?.classList.add("is-ready");
}

function clearAutoplayTimer() {
    window.clearTimeout(autoplayTimer);
    autoplayTimer = null;
}

function clearElapsedTimer() {
    window.clearInterval(elapsedTimer);
    elapsedTimer = null;
}

/** 停止 XDR 实时告警轮询 */
function stopXdrPolling() {
    if (xdrPollTimer) {
        window.clearInterval(xdrPollTimer);
        xdrPollTimer = null;
    }
}

/**
 * 从后端拉一次 XDR 告警列表，然后更新当前研判页面展示。
 * 失败时仅以错误状态呈现（不影响 UI 其它操作）。
 */
async function fetchXdrOnce() {
    try {
        const result = await api.xdrAlerts({ limit: 12, time_range: "24h" });
        xdrLastPolledAt = new Date().toLocaleString();
        if (!result || result.status !== "success") {
            const msg = result?.message || "XDR 平台返回错误";
            caseStore.patch({
                mode: "xdr",
                provider: result?.provider || caseStore.state.provider || "",
                source: "XDR 平台接入失败",
                title: "无法获取 XDR 实时告警",
                summary: msg,
                summaryText: `${msg}。请前往「系统设置 → XDR 集成」确认连接信息已填写完整。`,
                riskClass: "risk-pending",
                riskLabel: "连接异常",
                risk: "pending",
                currentStage: 0,
                xdrPolledAt: xdrLastPolledAt,
                xdrAlerts: [],
            });
            return;
        }
        const alerts = Array.isArray(result.alerts) ? result.alerts : [];
        const provider = result.provider || caseStore.state.provider || "XDR";
        // 基于告警计算风险等级 / 汇总文案
        let riskClass = "risk-low";
        let riskLabel = "低风险";
        const severities = new Set(alerts.map((a) => String(a.severity || "").toLowerCase()));
        if (severities.has("critical") || severities.has("严重") || severities.has("high") || severities.has("高")) {
            riskClass = "risk-high";
            riskLabel = "高风险";
        } else if (severities.has("medium") || severities.has("中") || severities.has("warning") || severities.has("warn")) {
            riskClass = "risk-medium";
            riskLabel = "中风险";
        }
        const topTitles = alerts
            .slice(0, 5)
            .map((a, i) => `${i + 1}. [${a.severity || "-"}] ${a.title || "（无标题告警）"} @ ${a.timestamp || ""}`)
            .join("\n");
        const summary = alerts.length
            ? `检测到 ${alerts.length} 条来自 ${provider} 的最新告警。`
            : `过去 24 小时 ${provider} 暂无告警。`;
        // 进入 detect 阶段（第 2 步事件检测），自动触发 AI 分析阶段
        const currentStage = alerts.length ? 2 : 1;
        const title = alerts.length
            ? `XDR 实时监测 · ${alerts.length} 条告警`
            : `XDR 实时监测 · 无告警`;
        caseStore.patch({
            mode: "xdr",
            provider,
            source: `实时接入 ${provider}`,
            caseId: `XDR-${Date.now().toString().slice(-8)}`,
            title,
            summary,
            summaryText: topTitles || `${provider} 过去 24 小时暂无新增告警。`,
            riskClass,
            riskLabel,
            risk: riskLabel,
            currentStage,
            furthestStage: Math.max(caseStore.state.furthestStage || 0, currentStage),
            xdrPolledAt: xdrLastPolledAt,
            xdrAlerts: alerts,
        });
    } catch (error) {
        xdrLastPolledAt = new Date().toLocaleString();
        caseStore.patch({
            mode: "xdr",
            source: "XDR 平台接入失败",
            title: "XDR 实时监测请求异常",
            summary: error?.message || "请求失败",
            summaryText: `${error?.message || "未知错误"}。请检查后端服务是否启动、Indexer 地址是否可达。`,
            riskClass: "risk-pending",
            riskLabel: "请求异常",
            risk: "pending",
            currentStage: 0,
            xdrPolledAt: xdrLastPolledAt,
            xdrAlerts: [],
        });
    }
}

/** 启动 XDR 实时告警轮询（首次立即拉一次，之后每 5s 拉一次） */
function startXdrPolling() {
    stopXdrPolling();
    // 立即拉一次，保证用户切过来立刻有数据
    fetchXdrOnce();
    xdrPollTimer = window.setInterval(fetchXdrOnce, 10 * 1000);
}

function syncElapsed() {
    const state = caseStore.state;
    if (state.mode !== "replay" || !state.startedAt || state.completedAt) {
        clearElapsedTimer();
        return;
    }
    const startedAt = Date.parse(state.startedAt);
    if (Number.isNaN(startedAt)) return;
    const elapsedSec = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    if (elapsedSec !== state.elapsedSec) {
        caseStore.patch({ elapsedSec });
    }
}

function startElapsedTimer() {
    if (elapsedTimer || caseStore.state.completedAt || !caseStore.state.startedAt) return;
    elapsedTimer = window.setInterval(syncElapsed, 1000);
}

function ensureReplayStarted() {
    if (caseStore.state.mode !== "replay") return;
    if (!caseStore.state.startedAt) {
        caseStore.patch({
            startedAt: new Date().toISOString(),
            completedAt: "",
        });
    }
    startElapsedTimer();
}

function finishReplayClock() {
    clearElapsedTimer();
    const state = caseStore.state;
    if (!state.startedAt || state.completedAt) return;
    const finishedAt = new Date().toISOString();
    const startedAt = Date.parse(state.startedAt);
    caseStore.patch({
        completedAt: finishedAt,
        elapsedSec: Number.isNaN(startedAt)
            ? state.elapsedSec
            : Math.max(state.elapsedSec, Math.floor((Date.now() - startedAt) / 1000)),
    });
}

function stopAutoplay() {
    clearAutoplayTimer();
    if (caseStore.state.autoplay) {
        caseStore.patch({ autoplay: false });
    }
}

function stageOutcomePatch(stageIndex) {
    if (stageIndex < 5) {
        return {
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
        };
    }
    if (stageIndex === 5) {
        return {
            decision: "approved",
            execution: "not-executed",
            verification: "not-verified",
            auditId: "",
            decisionSource: "操作员对官方样例的明确授权",
            executionSource: "",
            verificationSource: "",
            auditSource: "",
            executionReceiptId: "",
            verificationReceiptId: "",
        };
    }
    if (stageIndex === 6) {
        return {
            decision: "approved",
            execution: SAMPLE_RECEIPTS.execution.status,
            verification: "not-verified",
            auditId: "",
            decisionSource: "操作员对官方样例的明确授权",
            executionSource: SAMPLE_RECEIPTS.execution.source,
            verificationSource: "",
            auditSource: "",
            executionReceiptId: SAMPLE_RECEIPTS.execution.id,
            verificationReceiptId: "",
        };
    }
    if (stageIndex === 7) {
        return {
            decision: "approved",
            execution: SAMPLE_RECEIPTS.execution.status,
            verification: SAMPLE_RECEIPTS.verification.status,
            auditId: "",
            decisionSource: "操作员对官方样例的明确授权",
            executionSource: SAMPLE_RECEIPTS.execution.source,
            verificationSource: SAMPLE_RECEIPTS.verification.source,
            auditSource: "",
            executionReceiptId: SAMPLE_RECEIPTS.execution.id,
            verificationReceiptId: SAMPLE_RECEIPTS.verification.id,
        };
    }
    return {
        decision: "approved",
        execution: SAMPLE_RECEIPTS.execution.status,
        verification: SAMPLE_RECEIPTS.verification.status,
        auditId: SAMPLE_RECEIPTS.audit.id,
        decisionSource: "操作员对官方样例的明确授权",
        executionSource: SAMPLE_RECEIPTS.execution.source,
        verificationSource: SAMPLE_RECEIPTS.verification.source,
        auditSource: SAMPLE_RECEIPTS.audit.source,
        executionReceiptId: SAMPLE_RECEIPTS.execution.id,
        verificationReceiptId: SAMPLE_RECEIPTS.verification.id,
    };
}

function applyReplayStage(stageIndex, {
    recordAudit = true,
    elapsedOverride = null,
    notify = false,
} = {}) {
    const boundedStage = Math.max(0, Math.min(stageIndex, CASE_STAGES.length - 1));
    const stageCopy = STAGE_COPY[boundedStage];
    const previousFurthest = caseStore.state.furthestStage;
    const startedAt = boundedStage > 0
        ? caseStore.state.startedAt || new Date().toISOString()
        : "";
    const elapsedSec = Number.isInteger(elapsedOverride)
        ? Math.max(0, elapsedOverride)
        : caseStore.state.elapsedSec;
    const completedAt = boundedStage === CASE_STAGES.length - 1
        ? caseStore.state.completedAt || new Date().toISOString()
        : "";
    const truthState = REPLAY_TRUTH_STATES[boundedStage];
    setCaseTruthState(truthState, {
        mode: "replay",
        source: caseStore.state.scenarioSource || "智能体生成回放",
        furthestStage: Math.max(previousFurthest, boundedStage),
        rejectedStage: null,
        elapsedSec,
        startedAt,
        completedAt,
        summary: stageCopy.summary,
        summaryTitle: stageCopy.title,
        summaryText: stageCopy.detail,
        ...stageOutcomePatch(boundedStage),
    }, { notify });
    if (recordAudit && boundedStage > previousFurthest) {
        const [title, detail] = STAGE_AUDIT_COPY[boundedStage];
        caseStore.addAudit({ title, detail });
    }
    if (boundedStage > 0 && boundedStage < CASE_STAGES.length - 1) {
        startElapsedTimer();
    } else if (boundedStage === CASE_STAGES.length - 1) {
        clearElapsedTimer();
    }
    announce(`${CASE_STAGES[boundedStage].label}。${stageCopy.title}`);
}

function scheduleAutoplay() {
    clearAutoplayTimer();
    if (!caseStore.state.autoplay) return;
    const truthState = resolveTruthState(caseStore.state);
    if (
        truthState === "pending_approval"
        || TRUTH_STATE_COPY[truthState].awaitExternal
        || TRUTH_STATE_COPY[truthState].terminal
    ) {
        stopAutoplay();
        return;
    }
    const currentStage = caseStore.state.currentStage;
    const nextStage = Math.min(currentStage + 1, CASE_STAGES.length - 1);
    const segmentSeconds = Math.max(
        1,
        DEMO_STAGE_TARGET_SECONDS[nextStage] - DEMO_STAGE_TARGET_SECONDS[currentStage],
    );
    autoplayTimer = window.setTimeout(() => {
        advanceReplay({ manual: false });
    }, segmentSeconds * 1000 * DEMO_TIME_SCALE);
}

async function requestReplayDecision(token) {
    stopAutoplay();
    const decision = await requestApproval();
    if (token !== replayToken) return;

    if (decision === "cancel") {
        announce("审批对话框已关闭，样例仍在等待人工决定");
        showToast("未提交审批决定，处置仍暂停在 HITL");
        return;
    }

    if (decision === "reject") {
        setCaseTruthState("rejected", {
            rejectedStage: 4,
            decisionSource: "操作员对官方样例的明确拒绝",
            executionSource: "",
            verificationSource: "",
            auditSource: "仅记录样例拒绝事件，非真实 EAT 签名链",
            executionReceiptId: "",
            verificationReceiptId: "",
        }, { notify: true });
        caseStore.addAudit({
            title: "操作员拒绝处置",
            detail: "样例决策为 rejected，没有下发临时封禁策略。",
        });
        announce("处置请求已拒绝，没有执行封禁动作");
        finishReplayClock();
        return;
    }

    applyReplayStage(5, { notify: true });
}

async function advanceReplay({ manual = true } = {}) {
    if (caseStore.state.mode === "live") {
        showToast("实时模式只展示服务端状态，请先读取本地实时任务");
        return;
    }
    if (manual) {
        stopAutoplay();
    }
    const truthState = resolveTruthState(caseStore.state);
    if (TRUTH_STATE_COPY[truthState].terminal) {
        return;
    }

    const token = replayToken;
    if (truthState === "pending_approval") {
        await requestReplayDecision(token);
        return;
    }

    const nextStage = Math.min(
        caseStore.state.currentStage + 1,
        CASE_STAGES.length - 1,
    );
    applyReplayStage(nextStage, {
        notify: nextStage === CASE_STAGES.length - 1,
    });
    if (nextStage === 4) {
        await requestReplayDecision(token);
        return;
    }
    if (nextStage === CASE_STAGES.length - 1) {
        stopAutoplay();
        return;
    }
    scheduleAutoplay();
}

function previousReplayStage() {
    stopAutoplay();
    if (caseStore.state.mode === "live" || caseStore.state.currentStage === 0) return;
    applyReplayStage(caseStore.state.currentStage - 1, { recordAudit: false });
    showToast("正在回看样例状态，不代表撤销已经展示的动作");
}

function toggleAutoplay() {
    if (caseStore.state.autoplay) {
        stopAutoplay();
        announce("自动播放已暂停");
        return;
    }
    const truthState = resolveTruthState(caseStore.state);
    if (
        caseStore.state.mode === "live"
        || truthState === "pending_approval"
        || TRUTH_STATE_COPY[truthState].awaitExternal
        || TRUTH_STATE_COPY[truthState].terminal
    ) {
        return;
    }
    caseStore.patch({ autoplay: true });
    ensureReplayStarted();
    announce("自动播放已开始，遇到人工审批会自动暂停");
    scheduleAutoplay();
}

function resetCase() {
    replayToken += 1;
    stopAutoplay();
    clearElapsedTimer();
    if (els.approvalDialog.open) {
        els.approvalDialog.close("cancel");
    }
    resetScenarioCopy();
    caseStore.reset();
    document.querySelector(".judge-stage")?.classList.remove("is-ready");
    showToast("已重置，请输入新的安全场景");
}

let _zoomRoot = null;
let _zoomRestoreInfo = null;

function toggleZoom() {
    const stage = document.querySelector(".judge-stage");
    if (!stage) return;
    const isZoomed = stage.classList.contains("is-zoomed");
    if (isZoomed) {
        exitZoom();
    } else {
        enterZoom();
    }
}

function enterZoom() {
    const stage = document.querySelector(".judge-stage");
    if (!stage) return;

    _zoomRestoreInfo = {
        parent: stage.parentNode,
        nextSibling: stage.nextSibling,
        hadIsReady: stage.classList.contains("is-ready"),
    };

    const portal = document.createElement("div");
    portal.className = "zoom-portal";
    document.body.appendChild(portal);

    stage.classList.add("is-zoomed");
    portal.appendChild(stage);

    const closeBtn = document.createElement("button");
    closeBtn.className = "zoom-close-btn";
    closeBtn.innerHTML = "&times;";
    closeBtn.setAttribute("aria-label", "关闭放大窗口");
    closeBtn.addEventListener("click", exitZoom);
    portal.appendChild(closeBtn);

    document.body.style.overflow = "hidden";
    _zoomRoot = portal;

    if (els.toggleZoom) {
        els.toggleZoom.textContent = "🔍 恢复大小";
        els.toggleZoom.setAttribute("aria-pressed", "true");
    }

    document.addEventListener("keydown", _handleZoomEscKey);
}

function exitZoom() {
    const portal = _zoomRoot;
    const restore = _zoomRestoreInfo;
    if (!portal || !restore) return;

    const stage = portal.querySelector(".judge-stage");
    if (!stage) return;

    stage.classList.remove("is-zoomed");

    if (restore.hadIsReady) stage.classList.add("is-ready");

    if (restore.nextSibling) {
        restore.parent.insertBefore(stage, restore.nextSibling);
    } else {
        restore.parent.appendChild(stage);
    }

    portal.remove();
    document.body.style.overflow = "";
    _zoomRoot = null;
    _zoomRestoreInfo = null;

    if (els.toggleZoom) {
        els.toggleZoom.textContent = "🔍 放大窗口";
        els.toggleZoom.setAttribute("aria-pressed", "false");
    }

    document.removeEventListener("keydown", _handleZoomEscKey);
}

function _handleZoomEscKey(e) {
    if (e.key === "Escape") {
        e.preventDefault();
        exitZoom();
    }
}

async function handleScenarioSubmit() {
    const message = els.scenarioInput?.value?.trim();
    if (!message) {
        showToast("请输入安全场景描述", "error");
        els.scenarioInput?.focus();
        return;
    }
    if (!api?.isOnline) {
        showToast("本地服务未连接，无法生成场景", "error");
        return;
    }

    const submitBtn = els.scenarioSubmit;
    const statusEl = els.scenarioStatus;
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = "分析中";
    if (statusEl) {
        statusEl.textContent = "智能体正在生成 9 阶段案件...";
        statusEl.className = "scenario-status is-loading";
    }

    try {
        const result = await api.scenario(message);
        applyScenarioResult(result);
        if (statusEl) {
            statusEl.textContent = "";
            statusEl.className = "scenario-status is-success";
        }
        showToast("场景已生成，点击「开始演示」查看流程", "info");
        if (els.startReplay) {
            els.startReplay.disabled = false;
            els.startReplay.textContent = "开始演示";
            els.startReplay.focus();
        }
    } catch (error) {
        const msg = error?.payload?.message || error?.message || "生成失败";
        if (statusEl) {
            statusEl.textContent = `生成失败：${msg}`;
            statusEl.className = "scenario-status is-error";
        }
        showToast(`场景生成失败：${msg}`, "error");
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

function handleScenarioPreset(presetKey) {
    const presets = {
        sqli: "Web 应用订单接口检测到 SQL 注入攻击，攻击载荷为 ' OR 1=1 --，攻击源 IP 203.0.113.24",
        webshell: "Web 应用上传接口检测到 PHP WebShell 写入，文件 shell.php 包含 eval($_POST[cmd])",
        apt: "内网检测到 APT 横向移动，发现 Pass-the-Hash 攻击和持久化后门，攻击源 10.0.1.55",
        credential: "凌晨检测到 lsass 进程异常访问，mimikatz 尝试读取凭据，攻击源 10.0.2.88",
        xss: "评论区检测到存储型 XSS 攻击，Payload 为 <script>document.cookie</script>，攻击源 IP 192.0.2.66，可能窃取用户会话",
        ransomware: "文件服务器检测到大规模文件加密行为，扩展名被批量修改为 .locked，勒索说明文件 README.txt 已落地，疑似 WannaCry 变种",
        ddos: "Web 服务在 5 分钟内收到超过 50 万次请求，来自全球 2000+ 不同 IP，CPU 使用率达 95%，服务响应超时",
        phishing: "邮件网关检测到伪造发件人的钓鱼邮件，附件包含恶意宏文档 invoice.xlsm，收件人覆盖财务部门全体成员",
    };
    const text = presets[presetKey];
    if (text && els.scenarioInput) {
        els.scenarioInput.value = text;
        els.scenarioInput.focus();
    }
}

function toggleScenarioLibrary() {
    const toggle = els.scenarioLibraryToggle;
    const content = document.querySelector("#scenario-library-content");
    if (!toggle || !content) return;
    const isExpanded = toggle.getAttribute("aria-expanded") === "true";
    if (isExpanded) {
        content.hidden = true;
        toggle.setAttribute("aria-expanded", "false");
    } else {
        content.hidden = false;
        toggle.setAttribute("aria-expanded", "true");
    }
}

const PRESET_TEMPLATE_KEYS = {
    sqli: "sqli",
    webshell: "webshell",
    apt: "apt",
    credential: "credential_theft",
    xss: "xss",
    ransomware: "ransomware",
    ddos: "ddos",
    phishing: "phishing",
};

async function handleScenarioCard(scenarioKey) {
    handleScenarioPreset(scenarioKey);
    const content = document.querySelector("#scenario-library-content");
    if (content) content.hidden = true;
    if (els.scenarioLibraryToggle) {
        els.scenarioLibraryToggle.setAttribute("aria-expanded", "false");
    }

    const templateKey = PRESET_TEMPLATE_KEYS[scenarioKey];
    if (templateKey) {
        await loadPresetScenario(templateKey);
    } else {
        if (typeof handleScenarioSubmit === "function") {
            setTimeout(() => handleScenarioSubmit(), 200);
        }
    }
}

async function loadPresetScenario(templateKey) {
    const submitBtn = els.scenarioSubmit;
    const statusEl = els.scenarioStatus;
    const originalText = submitBtn ? submitBtn.textContent : "";
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "加载中";
    }
    if (statusEl) {
        statusEl.textContent = "正在加载预设场景...";
        statusEl.className = "scenario-status is-loading";
    }

    try {
        const response = await fetch("/agent/scenario/preset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ preset_key: templateKey }),
        });
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData?.message || errData?.error || `HTTP ${response.status}`);
        }
        const result = await response.json();
        applyScenarioResult(result);
        if (statusEl) {
            statusEl.textContent = "预设场景已加载，可以开始演示";
            statusEl.className = "scenario-status is-success";
        }
        showToast("预设场景已加载，点击「开始演示」查看流程", "info");
        if (els.startReplay) {
            els.startReplay.disabled = false;
            els.startReplay.textContent = "开始演示";
            els.startReplay.focus();
        }
    } catch (error) {
        const msg = error?.payload?.message || error?.message || "加载失败";
        if (statusEl) {
            statusEl.textContent = `加载失败：${msg}`;
            statusEl.className = "scenario-status is-error";
        }
        showToast(`预设场景加载失败：${msg}`, "error");
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    }
}

function resumeFurthestStage() {
    stopAutoplay();
    if (
        caseStore.state.mode === "live"
        || caseStore.state.currentStage >= caseStore.state.furthestStage
    ) {
        return;
    }
    applyReplayStage(caseStore.state.furthestStage, { recordAudit: false });
    showToast("已回到本次演示的最新样例阶段");
}

function renderHealth(data) {
    els.connectionButton.classList.remove("is-offline");
    els.connectionButton.classList.add("is-online");
    els.connectionLabel.textContent = "本地服务正常";
    setStateLabel(els.gatewayState, "state-ready", "已连接");
    setStateLabel(els.sympasState, "state-ready", "已配置");
    els.gatewayUrl.textContent = api.baseUrl;
    els.gatewaySkills.textContent = `${data.skills ?? 0} 项`;
    els.gatewayRag.textContent = `${data.rag_collection_chunks ?? 0} 块`;
    els.sympasUrl.textContent = data.sympas_url || "已由本地网关管理";
    els.metricApprovals.textContent = String(data.pending_approvals ?? 0);
    els.metricAudits.textContent = String(data.audit_sessions ?? 0);
}

function renderHealthError(error) {
    els.connectionButton.classList.remove("is-online");
    els.connectionButton.classList.add("is-offline");
    els.connectionLabel.textContent = "本地服务不可用";
    setStateLabel(els.gatewayState, "state-failed", "连接失败");
    setStateLabel(els.sympasState, "state-pending", "状态未知");
    els.gatewaySkills.textContent = "不可用";
    els.gatewayRag.textContent = "不可用";
    els.sympasUrl.textContent = error.message;
}

function makeCell(text, className = "") {
    const cell = document.createElement("td");
    cell.textContent = text;
    if (className) {
        cell.className = className;
    }
    return cell;
}

function renderRuns(data, { promoteLive = false } = {}) {
    const runs = Array.isArray(data?.runs) ? data.runs : [];
    els.metricRuns.textContent = String(runs.length);
    els.runsBody.replaceChildren();

    if (!runs.length) {
        const row = document.createElement("tr");
        row.className = "empty-row";
        const cell = makeCell("尚无真实运行。评审演示可使用官方样本回放。");
        cell.colSpan = 5;
        row.append(cell);
        els.runsBody.append(row);
        els.historyLatest.textContent = "暂无真实运行";
        els.historyLatestDetail.textContent = "连接本地网关后，这里会显示最新任务状态。";
        if (promoteLive) {
            setCaseTruthState("initial", {
                mode: "live",
                source: "本地实时",
                caseId: "LIVE-NO-RUN",
                furthestStage: 0,
                auditId: "",
                decisionSource: "",
                executionSource: "",
                verificationSource: "",
                auditSource: "",
                executionReceiptId: "",
                verificationReceiptId: "",
                summary: "本地网关当前没有真实智能体运行，页面不会生成处置或复测结果。",
                summaryTitle: "等待真实任务",
                summaryText: "可以启动真实任务，或切回明确标注的官方样例回放。",
                auditEvents: [],
            });
        }
        return;
    }

    const latest = runs[0];
    els.historyLatest.textContent = `${statusText(latest.status)} · ${latest.run_id}`;
    els.historyLatestDetail.textContent = `创建于 ${formatTime(latest.created_at)}，来源为本地智能体网关。`;

    runs.slice(0, 12).forEach((run) => {
        const row = document.createElement("tr");
        const result = run.error
            ? `错误：${run.error}`
            : run.status === "completed"
                ? "结果已生成"
                : "等待结果";
        row.append(
            makeCell(run.run_id || "未知", "run-id"),
            makeCell("本地网关"),
            makeCell(statusText(run.status)),
            makeCell(formatTime(run.created_at)),
            makeCell(result),
        );
        els.runsBody.append(row);
    });

    if (latest.status) {
        const executionStatus = latest.execution_status
            || latest.result?.execution_status
            || latest.result?.action_result?.status
            || "";
        const verificationStatus = latest.verification_status
            || latest.result?.verification_status
            || latest.result?.verification?.status
            || "";
        const executionSucceeded = ["executed", "success", "succeeded"].includes(executionStatus);
        const verificationPassed = ["passed", "success", "verified"].includes(verificationStatus);
        const verificationFailed = ["failed", "error", "not_verified"].includes(verificationStatus);
        const rejected = latest.status === "rejected";
        const expired = latest.status === "expired";
        const executionFailed = latest.status === "failed"
            || ["failed", "error"].includes(executionStatus);
        const executing = latest.status === "executing";
        const approved = latest.status === "approved"
            || executionSucceeded
            || executing
            || executionFailed;
        const auditId = latest.result?.audit_id || latest.audit_id || "";
        const completedWithProof = latest.status === "completed"
            && executionSucceeded
            && verificationPassed
            && Boolean(auditId);
        const liveTruthState = rejected
            ? "rejected"
            : expired
                ? "expired"
                : executionFailed
                    ? "execution_failed"
                    : executing
                        ? "executing"
                        : completedWithProof
                            ? "completed"
                            : executionSucceeded && verificationFailed
                                ? "verification_failed"
                                : executionSucceeded && verificationPassed
                                    ? "verified_not_closed"
                                    : executionSucceeded
                                        ? "executed_not_verified"
                                        : approved
                                            ? "approved_not_executed"
                                            : "ai_assessed";
        const hasExecutionState = [
            "executing",
            "execution_failed",
            "executed_not_verified",
            "verification_failed",
            "verified_not_closed",
            "completed",
        ].includes(liveTruthState);
        const hasVerificationState = [
            "verification_failed",
            "verified_not_closed",
            "completed",
        ].includes(liveTruthState);
        const liveSummary = rejected
            ? "服务端返回 rejected，动作未执行。"
            : expired
                ? "服务端返回 expired，审批窗口结束且动作未执行。"
                : executionFailed
                    ? "服务端返回执行失败，攻击不视为已阻断。"
                    : executionSucceeded && verificationFailed
                        ? "动作已有执行回执，但服务端复测失败，事件不能闭环。"
                    : completedWithProof
                        ? "服务端同时返回执行成功、验证通过与审计关联，真实事件可以闭环。"
                        : executing
                            ? "服务端任务已进入 executing，不会显示为已过期。"
                            : executionSucceeded && verificationPassed
                                ? "执行和复测证据已经成立，仍在等待审计关联。"
                                : executionSucceeded
                                    ? "已收到执行回执，但缺少复测回执，不显示攻击失效。"
                                    : approved
                                        ? "审批已通过，但缺少执行回执，动作仍显示为未执行。"
                                        : "任务已返回，但尚未形成可执行的处置状态。";
        setCaseTruthState(liveTruthState, {
            mode: "live",
            source: "本地实时",
            caseId: latest.run_id || "LIVE-RUN",
            furthestStage: CASE_TRUTH_STATES[liveTruthState].currentStage,
            auditId: completedWithProof ? auditId : "",
            decisionSource: rejected || expired || approved
                ? "本地网关 HITL 状态"
                : "",
            executionSource: hasExecutionState && executionStatus
                ? "本地网关 execution_status"
                : "",
            verificationSource: hasVerificationState && verificationStatus
                ? "本地网关 verification_status"
                : "",
            auditSource: completedWithProof
                ? "本地网关返回的审计关联"
                : "",
            executionReceiptId: hasExecutionState
                ? latest.result?.execution_receipt_id
                    || latest.execution_receipt_id
                    || ""
                : "",
            verificationReceiptId: hasVerificationState
                ? latest.result?.verification_receipt_id
                    || latest.verification_receipt_id
                    || ""
                : "",
            summary: liveSummary,
            summaryTitle: completedWithProof
                ? "真实处置已验证并关联审计"
                : "真实状态已同步",
            summaryText: latest.error || liveSummary,
            auditEvents: [],
        });
    }
}

function approvalActionLabel(item) {
    const action = item?.action?.proposed_action
        || item?.action
        || item?.skill_name
        || "服务端未返回动作名称";
    if (typeof action === "string") return action;
    try {
        return JSON.stringify(action);
    } catch {
        return "服务端动作参数无法显示";
    }
}

function renderApprovalsError(error) {
    pendingLiveApproval = null;
    els.reviewLiveApproval.hidden = true;
    els.hitlReview.hidden = true;
    els.hitlSummaryTitle.textContent = "审批服务不可用";
    els.hitlSummaryText.textContent = `${error.message}。页面不会生成本地审批结果，可继续使用明确标注的官方样例回放。`;
    els.hitlList.replaceChildren();
    const state = document.createElement("div");
    state.className = "result-state";
    const title = document.createElement("strong");
    const detail = document.createElement("p");
    title.textContent = "无法读取服务端审批任务";
    detail.textContent = "请检查本地网关；不要把审批服务不可用解释为已批准或已执行。";
    state.append(title, detail);
    els.hitlList.append(state);
}

function renderApprovals(data) {
    const approvals = Array.isArray(data?.approvals) ? data.approvals : [];
    const pending = data?.summary?.pending
        ?? approvals.filter((item) => ["pending", "notified"].includes(item.status)).length;
    els.metricApprovals.textContent = String(pending);
    pendingLiveApproval = approvals.find(
        (item) => ["pending", "notified"].includes(item.status),
    ) || null;
    els.reviewLiveApproval.hidden = !pendingLiveApproval;
    els.hitlReview.hidden = !pendingLiveApproval;
    els.hitlPendingCount.textContent = String(pending);
    els.hitlSummaryTitle.textContent = pending
        ? `发现 ${pending} 项真实待审批任务`
        : "当前没有真实待审批任务";
    els.hitlSummaryText.textContent = pending
        ? "任务来自本地网关。操作员决定提交后，仍需等待执行与复测回执。"
        : caseStore.state.mode === "replay"
            ? "当前主演示为官方样例回放，样例授权不会写成服务端真实审批。"
            : "本地网关未返回等待中的审批任务，页面不会自行创建批准状态。";

    els.hitlList.replaceChildren();
    if (!approvals.length) {
        const state = document.createElement("div");
        state.className = "result-state";
        const title = document.createElement("strong");
        const detail = document.createElement("p");
        title.textContent = "审批队列为空";
        detail.textContent = "启动真实智能体任务并触发高风险动作后，待审批记录会出现在这里。";
        state.append(title, detail);
        els.hitlList.append(state);
    } else {
        approvals.slice(0, 20).forEach((item) => {
            const row = document.createElement("article");
            const identity = document.createElement("div");
            const kicker = document.createElement("span");
            const title = document.createElement("h3");
            const detail = document.createElement("p");
            const meta = document.createElement("div");
            const status = document.createElement("span");
            const time = document.createElement("time");
            const isPending = ["pending", "notified"].includes(item?.status);

            row.className = `hitl-item${isPending ? " is-current" : ""}`;
            row.setAttribute("role", "listitem");
            kicker.className = "summary-kicker";
            kicker.textContent = item?.id || item?.task_id || "审批任务";
            title.textContent = item?.skill_name || "受控安全动作";
            detail.textContent = approvalActionLabel(item);
            status.className = `service-state ${
                isPending
                    ? "state-pending"
                    : item?.status === "approved"
                        ? "state-completed"
                        : ["rejected", "expired"].includes(item?.status)
                            ? "state-failed"
                            : "state-ready"
            }`;
            status.textContent = statusText(item?.status);
            time.dateTime = item?.created_at || "";
            time.textContent = formatTime(item?.created_at);
            identity.append(kicker, title);
            meta.className = "hitl-item-meta";
            meta.append(status, time);
            row.append(identity, detail, meta);
            els.hitlList.append(row);
        });
    }

    if (pendingLiveApproval && caseStore.state.mode === "live") {
        setCaseTruthState("pending_approval", {
            furthestStage: Math.max(caseStore.state.furthestStage, 4),
            summary: "本地网关返回一项待审批动作，智能体已停在 HITL 节点。",
            summaryTitle: "发现实时审批请求",
            summaryText: approvalActionLabel(pendingLiveApproval),
            decisionSource: "本地网关 HITL 待审批状态",
            executionSource: "",
            verificationSource: "",
            auditSource: "",
            executionReceiptId: "",
            verificationReceiptId: "",
        });
    }
}

function renderAuditChain(data) {
    const frames = Array.isArray(data?.chain) ? data.chain : [];
    if (!frames.length) {
        return;
    }

    const events = frames.slice(-20).map((frame, index) => ({
        time: frame?.ts || frame?.timestamp || new Date().toISOString(),
        title: frame?.event_type || frame?.type || `审计节点 ${index + 1}`,
        detail: frame?.action
            || frame?.message
            || frame?.summary
            || "EAT 链式记录",
    }));
    renderAuditEvents(events);
    els.auditOverviewTitle.textContent = "已加载真实审计会话";
    els.auditOverviewText.textContent = "事件来自本地 EAT 数据库，可继续执行哈希链与签名验证。";
}

function renderAuditSessions(data) {
    const sessions = Array.isArray(data?.sessions) ? data.sessions : [];
    latestAuditSession = sessions[0]?.id || sessions[0] || "";
    els.metricAudits.textContent = String(data?.count ?? sessions.length);
    els.auditSessionCount.textContent = String(data?.count ?? sessions.length);
    if (sessions.length) {
        els.auditOverviewTitle.textContent = "发现可验证审计会话";
        els.auditOverviewText.textContent = "选择验证后将检查哈希链与签名状态。";
        els.auditChainState.textContent = "等待验证";
    } else if (!caseStore.state.auditEvents.length) {
        els.auditOverviewTitle.textContent = "暂无可验证会话";
        els.auditOverviewText.textContent = "运行智能体后，EAT 记录将在这里显示。回放事件会明确标记为本地演示。";
        els.auditChainState.textContent = "等待数据";
    }
}

async function syncServices({ notify = false, promoteLive = false } = {}) {
    setStateLabel(els.gatewayState, "state-checking", "检查中");
    setStateLabel(els.sympasState, "state-checking", "检查中");

    const results = await Promise.allSettled([
        api.health(),
        api.runs(),
        api.approvals(),
        api.auditSessions(),
    ]);

    const online = results[0].status === "fulfilled";

    if (online) {
        renderHealth(results[0].value);
    } else {
        renderHealthError(results[0].reason);
    }

    if (results[1].status === "fulfilled") {
        try {
            if (promoteLive) {
                renderRuns(results[1].value, { promoteLive: true });
            } else {
                const preserved = caseStore.state;
                renderRuns(results[1].value);
                caseStore.patch({
                    ...preserved,
                    auditEvents: preserved.auditEvents,
                });
            }
        } catch (e) {
            console.error("Failed to render runs:", e);
        }
    } else if (online) {
        console.warn("Runs fetch failed but health check passed");
    }

    if (results[2].status === "fulfilled") {
        try {
            renderApprovals(results[2].value);
        } catch (e) {
            console.error("Failed to render approvals:", e);
            renderApprovalsError(e);
        }
    } else {
        renderApprovalsError(results[2].reason);
    }

    if (results[3].status === "fulfilled") {
        try {
            renderAuditSessions(results[3].value);
            const sessions = results[3].value?.sessions || [];
            if (sessions.length) {
                const sessionId = sessions[0]?.id || sessions[0];
                if (sessionId) {
                    latestAuditSession = sessionId;
                    try {
                        const chain = await api.auditChain(sessionId);
                        renderAuditChain(chain);
                    } catch (error) {
                        els.auditChainState.textContent = "读取失败";
                    }
                }
            }
        } catch (e) {
            console.error("Failed to render audit sessions:", e);
        }
    }

    if (notify) {
        if (!online) {
            showToast("本地服务不可用，官方样本回放仍可使用", "error");
        } else if (promoteLive) {
            showToast("已连接本地网关并读取运行状态", "info");
        } else {
            showToast("服务状态已经更新", "info");
        }
    }

    return online;
}

function showRagLoading() {
    els.ragResult.className = "result-state is-loading";
    els.ragResult.replaceChildren();
    for (let index = 0; index < 3; index += 1) {
        const line = document.createElement("div");
        line.className = "skeleton-line";
        els.ragResult.append(line);
    }
    els.ragResultMeta.textContent = "正在检索本地知识库";
}

function renderRagResult(data) {
    els.ragResult.className = "result-state";
    els.ragResult.replaceChildren();

    const answer = String(data?.answer || "").trim();
    const evidence = Array.isArray(data?.evidence) ? data.evidence : [];
    if (!answer && !evidence.length) {
        const title = document.createElement("strong");
        const detail = document.createElement("p");
        title.textContent = "没有找到可支撑的证据";
        detail.textContent = "请补充案件上下文，或先向知识库导入经过核验的安全材料。";
        els.ragResult.append(title, detail);
        els.ragResultMeta.textContent = "检索完成，0 条引用";
        return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "rag-answer";
    const title = document.createElement("h3");
    const answerText = document.createElement("p");
    title.textContent = "证据约束回答";
    answerText.textContent = answer || "服务返回了证据，但没有生成回答。";
    wrapper.append(title, answerText);

    if (evidence.length) {
        const citations = document.createElement("ol");
        citations.className = "rag-citations";
        evidence.slice(0, 6).forEach((item, index) => {
            const citation = document.createElement("li");
            const source = item?.source || item?.metadata?.source || item?.title || "本地知识库";
            const excerpt = item?.content || item?.text || item?.document || "";
            citation.textContent = `[${index + 1}] ${source}${excerpt ? `：${String(excerpt).slice(0, 120)}` : ""}`;
            citations.append(citation);
        });
        wrapper.append(citations);
    }

    els.ragResult.append(wrapper);
    els.ragResultMeta.textContent = `检索完成，${evidence.length} 条引用`;
}

const EVIDENCE_SOURCE_CONTEXT = Object.freeze({
    request: {
        query: "SQL 注入 CWE-89 的检测、限时封禁与复测依据",
        boundary: "当前查看官方样例请求载荷。它用于演示证据关联，不代表真实 XDR 流量。",
    },
    asset: {
        query: "SQL 注入影响 Web 应用和数据库资产时需要核对哪些直接证据",
        boundary: "当前查看脱敏教学商城资产上下文。资产名称与地址均为演示夹具。",
    },
    knowledge: {
        query: "CWE-89 SQL 注入的证据要求、临时缓解与复测方法",
        boundary: "当前选择本地 RAG 知识检索。返回内容属于参考知识，不能替代案件直接证据。",
    },
});

function selectEvidenceSource(sourceKey, { focusQuery = false } = {}) {
    const context = EVIDENCE_SOURCE_CONTEXT[sourceKey];
    if (!context) return;
    els.sourceRows.forEach((row) => {
        const selected = row.dataset.sourceKey === sourceKey;
        row.classList.toggle("is-selected", selected);
        row.setAttribute("aria-pressed", String(selected));
    });
    els.ragQuery.value = context.query;
    els.sourceBoundary.textContent = context.boundary;
    if (focusQuery) {
        els.ragQuery.focus();
    }
}

function openStageDetail() {
    const stage = caseStore.state.currentStage;
    const target = STAGE_DETAIL_ROUTES[stage] || STAGE_DETAIL_ROUTES[0];
    if (target.route === "threat-analysis") {
        capabilityLab?.applyCaseContext("threat", {
            stage,
            description: stage >= 7
                ? "复测同一 SQL 注入请求返回 HTTP 403，数据库审计中对应查询次数为 0。请区分复测事实与模型判断。"
                : "教学商城 /api/orders 收到来源 203.0.113.24 的脱敏请求载荷 ' OR 1=1 --，响应时延增加 824 ms，XDR 规则命中 SQL 注入。",
        });
    } else if (target.route === "rag-evidence") {
        selectEvidenceSource(stage >= 3 ? "knowledge" : "request");
    }
    showRoute(target.route);
    if (target.route === "hitl-approval") {
        syncServices();
    }
}

async function runRagQuery(event) {
    event.preventDefault();
    const query = els.ragQuery.value.trim();
    if (!query) {
        els.ragQuery.focus();
        showToast("请输入需要检索的安全问题", "error");
        return;
    }

    showRagLoading();
    try {
        const result = await api.queryRag(query);
        renderRagResult(result);
        announce("知识检索已经完成");
    } catch (error) {
        els.ragResult.className = "result-state";
        els.ragResult.replaceChildren();
        const title = document.createElement("strong");
        const detail = document.createElement("p");
        title.textContent = "知识检索失败";
        detail.textContent = `${error.message}。案件回放仍可继续。`;
        els.ragResult.append(title, detail);
        els.ragResultMeta.textContent = "服务不可用";
        showToast(error.message, "error");
    }
}

async function verifyAudit() {
    if (!latestAuditSession) {
        els.auditChainState.textContent = "无真实会话";
        els.auditOverviewTitle.textContent = "没有可验证的真实 EAT 会话";
        els.auditOverviewText.textContent = caseStore.state.auditEvents.length
            ? "当前只有官方样例操作记录，它不是 EAT 签名链，不能显示为验证通过。"
            : "先运行一次真实智能体任务，再验证服务端返回的 EAT 会话。";
        showToast("当前没有可验证的真实 EAT 会话", "error");
        return;
    }
    els.verifyAudit.disabled = true;
    els.verifyAudit.textContent = "正在验证";
    try {
        const result = await api.verifyAudit(latestAuditSession);
        const valid = result?.valid === true
            || (Array.isArray(result?.results) && result.results.every((item) => item.valid));
        els.auditChainState.textContent = valid ? "验证通过" : "未通过";
        els.auditOverviewTitle.textContent = valid ? "审计链验证通过" : "审计链未通过验证";
        els.auditOverviewText.textContent = valid
            ? "当前会话的链式记录保持完整。"
            : result?.error || "未找到可验证数据，或链完整性检查失败。";
        showToast(valid ? "审计链验证通过" : "审计链未通过验证", valid ? "info" : "error");
    } catch (error) {
        els.auditChainState.textContent = "验证失败";
        showToast(error.message, "error");
    } finally {
        els.verifyAudit.disabled = false;
        els.verifyAudit.textContent = "验证审计链";
    }
}

async function reviewLiveApproval() {
    if (!pendingLiveApproval) {
        showToast("当前没有待审批动作", "error");
        return;
    }

    const decision = await requestApproval({
        mode: "live",
        action: pendingLiveApproval.action?.proposed_action
            || pendingLiveApproval.action
            || pendingLiveApproval.skill_name
            || "执行安全工具动作",
        target: pendingLiveApproval.target
            || (pendingLiveApproval.session_id
            ? `会话 ${pendingLiveApproval.session_id}`
            : `任务 ${pendingLiveApproval.id || pendingLiveApproval.task_id || "未知"}`),
        rollback: pendingLiveApproval.rollback_plan,
    });
    if (decision === "cancel") {
        showToast("未提交审批决定，真实任务仍保持服务端状态");
        return;
    }

    const approvalId = pendingLiveApproval.id || pendingLiveApproval.task_id;
    if (!approvalId) {
        showToast("服务端审批任务缺少可用编号", "error");
        return;
    }
    els.reviewLiveApproval.disabled = true;
    els.hitlReview.disabled = true;
    try {
        const tokenResult = await api.approvalToken(approvalId);
        const approvalToken = tokenResult?.approval_token;
        if (!approvalToken) {
            throw new Error("未能获取本机操作员审批令牌");
        }
        if (decision === "approve") {
            await api.approve(
                approvalId,
                approvalToken,
                "local_dashboard",
                "Operator confirmed the proposed action and rollback plan",
            );
            showToast("批准决定已提交，等待服务端执行状态回执");
        } else {
            await api.reject(
                approvalId,
                approvalToken,
                "local_dashboard",
                "Operator rejected the proposed action",
            );
            showToast("拒绝决定已提交，等待服务端确认未执行状态");
        }
        await syncServices({ promoteLive: true });
    } catch (error) {
        showToast(error.message, "error");
    } finally {
        els.reviewLiveApproval.disabled = false;
        els.hitlReview.disabled = false;
    }
}

function initializeTheme() {
    const saved = window.localStorage.getItem("cangsight-theme");
    const theme = saved === "dark" || saved === "light"
        ? saved
        : "dark";
    els.html.dataset.theme = theme;
    els.themeToggle.textContent = theme === "dark" ? "浅色模式" : "深色模式";
}

function toggleTheme() {
    const next = els.html.dataset.theme === "dark" ? "light" : "dark";
    els.html.dataset.theme = next;
    window.localStorage.setItem("cangsight-theme", next);
    els.themeToggle.textContent = next === "dark" ? "浅色模式" : "深色模式";
    announce(`已切换为${next === "dark" ? "深色" : "浅色"}模式`);
}

function initializeNavigation() {
    els.navLinks.forEach((link) => {
        link.addEventListener("click", (event) => {
            event.preventDefault();
            showRoute(link.dataset.route);
        });
    });

    els.caseDemoLinks.forEach((link) => {
        link.addEventListener("click", (event) => {
            event.preventDefault();
            showRoute("");
        });
    });

    els.interfaceButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const nextMode = button.dataset.interfaceTarget;
            if (nextMode === "judge") {
                showRoute("judge");
            } else {
                showRoute("workbench");
            }
        });
    });

    document.querySelectorAll("[data-route-jump]").forEach((button) => {
        const jump = () => showRoute(button.dataset.routeJump);
        button.addEventListener("click", jump);
        button.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                jump();
            }
        });
    });

    els.navToggle.addEventListener("click", () => {
        const open = els.sidebar.classList.toggle("is-open");
        els.navToggle.setAttribute("aria-expanded", String(open));
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && els.sidebar.classList.contains("is-open")) {
            els.sidebar.classList.remove("is-open");
            els.navToggle.setAttribute("aria-expanded", "false");
            els.navToggle.focus();
        }

        const interactiveTarget = event.target.closest(
            "input, textarea, select, button, a, dialog, [contenteditable='true']",
        );
        const judgeCaseActive = els.html.dataset.interfaceMode === "judge"
            && !document.querySelector("#view-current-case")?.hidden
            && !els.approvalDialog.open;
        if (!judgeCaseActive || interactiveTarget) return;
        if (event.key === "ArrowRight") {
            event.preventDefault();
            advanceReplay();
        } else if (event.key === "ArrowLeft") {
            event.preventDefault();
            previousReplayStage();
        } else if (event.code === "Space") {
            event.preventDefault();
            toggleAutoplay();
        }
    });

    const syncRouteFromLocation = (event) => {
        const routeName = window.location.hash.replace("#", "");
        showRoute(routeName, {
            updateHistory: false,
            focusMain: Boolean(event),
        });
    };

    window.addEventListener("popstate", syncRouteFromLocation);
    window.addEventListener("hashchange", syncRouteFromLocation);
    syncRouteFromLocation();
}

function bindEvents() {
    els.themeToggle.addEventListener("click", toggleTheme);
    els.startReplay.addEventListener("click", () => advanceReplay());
    els.demoPrev.addEventListener("click", previousReplayStage);
    els.resumeFurthest.addEventListener("click", resumeFurthestStage);
    els.demoPlay.addEventListener("click", toggleAutoplay);
    els.resetCase.addEventListener("click", resetCase);
    if (els.toggleZoom) {
        els.toggleZoom.addEventListener("click", toggleZoom);
    }
    if (els.scenarioSubmit) {
        els.scenarioSubmit.addEventListener("click", handleScenarioSubmit);
    }
    if (els.scenarioPresets?.length) {
        els.scenarioPresets.forEach((btn) => {
            btn.addEventListener("click", () => handleScenarioPreset(btn.dataset.preset));
        });
    }
    const libraryToggle = els.scenarioLibraryToggle;
    if (libraryToggle) {
        libraryToggle.addEventListener("click", toggleScenarioLibrary);
    }
    els.scenarioCards?.forEach((card) => {
        card.addEventListener("click", () => handleScenarioCard(card.dataset.scenario));
    });
    if (els.scenarioInput) {
        els.scenarioInput.addEventListener("keydown", (event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
                event.preventDefault();
                handleScenarioSubmit();
            }
        });
    }
    els.syncLive.addEventListener("click", () => syncServices({ notify: true, promoteLive: true }));
    els.reviewLiveApproval.addEventListener("click", reviewLiveApproval);
    els.hitlReview.addEventListener("click", reviewLiveApproval);
    els.hitlRefresh.addEventListener("click", () => syncServices({ notify: true }));
    els.stageDetailLink.addEventListener("click", openStageDetail);
    els.connectionButton.addEventListener("click", async () => {
        setStateLabel(els.gatewayState, "state-checking", "检查中");
        try {
            await api.checkServerConnection();
            showToast("本地服务连接正常", "info");
            await syncServices({ notify: false, promoteLive: true });
        } catch {
            showToast("本地服务不可用，已切换到离线模式", "error");
        }
        showRoute("settings");
    });
    els.refreshRuns.addEventListener("click", () => syncServices({ notify: true }));
    els.checkServices.addEventListener("click", () => syncServices({ notify: true }));
    els.refreshAudit.addEventListener("click", () => syncServices({ notify: true }));
    els.verifyAudit.addEventListener("click", verifyAudit);
    els.ragForm.addEventListener("submit", runRagQuery);
    els.sourceRows.forEach((row) => {
        row.addEventListener("click", () => selectEvidenceSource(
            row.dataset.sourceKey,
            { focusQuery: true },
        ));
    });

    els.approvalConfirm.addEventListener("change", () => {
        els.approveAction.disabled = !els.approvalConfirm.checked;
    });

    document.querySelectorAll('input[name="demo-mode"]').forEach((radio) => {
        radio.addEventListener("change", () => {
            if (!radio.checked) return;
            if (radio.value === "replay") {
                stopXdrPolling();
                resetCase();
                showRoute("judge");
            } else if (radio.value === "live") {
                stopXdrPolling();
                syncServices({ notify: true, promoteLive: true });
                showRoute("judge");
            } else if (radio.value === "xdr") {
                // 切到 XDR 实时接入：先重置，再启动轮询
                stopXdrPolling();
                caseStore.patch({
                    mode: "xdr",
                    source: "正在连接 XDR 平台…",
                    title: "XDR 实时监测启动中",
                    summary: "首次拉取最新告警中…",
                    summaryText: "自动轮询每 5 秒一次；若配置不完整或不可达，将在卡片中显示错误提示。",
                    riskClass: "risk-pending",
                    riskLabel: "连接中",
                    risk: "pending",
                    currentStage: 0,
                    furthestStage: 0,
                    provider: "",
                    xdrPolledAt: "",
                    xdrAlerts: [],
                });
                showRoute("judge");
                startXdrPolling();
            }
        });
    });
}

function initializeReplayStageFromQuery() {
    const rawStage = new URLSearchParams(window.location.search).get("replay-stage");
    if (rawStage === null) return;
    const requestedStage = Number.parseInt(rawStage, 10);
    if (
        Number.isInteger(requestedStage)
        && requestedStage >= 0
        && requestedStage < CASE_STAGES.length
    ) {
        applyReplayStage(requestedStage, {
            recordAudit: false,
            elapsedOverride: DEMO_STAGE_TARGET_SECONDS[requestedStage],
        });
    }
}

initializeTheme();
els.html.dataset.demoDuration = String(DEMO_DURATION_SECONDS);
els.html.dataset.demoTimeScale = String(DEMO_TIME_SCALE);
setInterfaceMode("home", { announceChange: false });
capabilityLab = initCapabilityLab({
    showToast,
    announce,
    onSelectLab: (labName) => {
        const routeName = LAB_ROUTES[labName] || "chat";
        showRoute(routeName, { labOverride: labName, syncLab: false });
    },
});
initializeNavigation();
bindEvents();
caseStore.subscribe(renderCase);
initializeReplayStageFromQuery();
if (caseStore.state.startedAt && !caseStore.state.completedAt) {
    startElapsedTimer();
}

api.on("connectionChange", ({ available }) => {
    if (available) {
        showToast("本地服务已连接", "info");
        syncServices({ notify: false, promoteLive: true });
    } else {
        showToast("本地服务连接断开，已切换离线模式", "error");
    }
});

api.startHealthCheck(30000);

initModelSettings({ showToast, announce });
initXdrSettings({ showToast, announce });
initAttackChain({ showToast, announce });

syncServices().then(() => {
    if (!api.isOnline) {
        showToast("本地服务未启动，部分功能将受限", "error");
    }
}).catch(() => {
    showToast("初始连接检查失败，已启用离线模式", "error");
});

