/**
 * 自主闭环 · 攻击链时间线
 * 用户输入告警 → LLM 动态生成 OODA 攻击链 → 同格式展示推流
 * CoT 推流 → ReAct 循环 → HITL 审批 → EAT 审计链
 */

import { api } from "./api-client.js";

let playTimer = null;
let currentStep = 0;
let isPlaying = false;
let scenarioData = null;
let loadingTimer = null;

const SEVERITY_MAP = {
    low: { cls: "severity-low", label: "低" },
    medium: { cls: "severity-medium", label: "中等" },
    high: { cls: "severity-high", label: "高危" },
    critical: { cls: "severity-critical", label: "严重" },
};

function truncate(text, max = 160) {
    if (!text) return "";
    return text.length > max ? text.slice(0, max) + "…" : text;
}

function extractTitle(text) {
    if (!text) return "未知节点";
    const firstLine = text.split(/[。\n；;]/)[0];
    return truncate(firstLine, 40);
}

function classifySeverity(cycleNum, totalCycles) {
    if (cycleNum >= totalCycles) return "critical";
    if (cycleNum >= Math.ceil(totalCycles * 0.7)) return "high";
    if (cycleNum >= Math.ceil(totalCycles * 0.4)) return "medium";
    return "low";
}

function extractEvidence(cycle) {
    const parts = [];
    if (cycle.observe) parts.push("obs=" + truncate(cycle.observe, 50));
    if (cycle.act) parts.push("act=" + truncate(cycle.act, 50));
    return parts.join(" ");
}

function buildScenario(cycles) {
    const nodes = cycles.map((cycle, idx) => {
        const num = cycle.cycle_number || idx + 1;
        return {
            id: idx + 1,
            title: extractTitle(cycle.observe) || `轮次 ${num}`,
            severity: classifySeverity(num, cycles.length),
            desc: truncate(cycle.orient, 140),
            evidence: extractEvidence(cycle),
            thinking: truncate(cycle.observe, 120),
            acting: truncate(cycle.decide, 120),
            observing: truncate(cycle.act, 120),
        };
    });

    const react = [];
    for (const cycle of cycles) {
        if (cycle.observe) react.push({ type: "thinking", text: truncate(cycle.observe, 100) });
        if (cycle.orient) react.push({ type: "thinking", text: truncate(cycle.orient, 100) });
        if (cycle.decide) react.push({ type: "acting", text: truncate(cycle.decide, 100) });
        if (cycle.act) react.push({ type: "observing", text: truncate(cycle.act, 100) });
    }

    const lastCycle = cycles[cycles.length - 1] || {};
    const hitl = {
        title: truncate(lastCycle.decide, 60) || "高危处置动作",
        detail: truncate(lastCycle.act, 120) || "需执行高危操作",
        reason: truncate(lastCycle.orient, 120) || "综合研判需立即处置",
    };

    const eat = [];
    for (const cycle of cycles) {
        const num = cycle.cycle_number || 1;
        eat.push({
            stage: `reasoning-r${num}`,
            hash: generateHash(`r-${num}-${cycle.orient || ""}`),
            desc: truncate(`研判结论：${cycle.orient || "分析完成"}`, 80),
        });
        eat.push({
            stage: `decision-r${num}`,
            hash: generateHash(`d-${num}-${cycle.decide || ""}`),
            desc: truncate(`决策：${cycle.decide || "执行处置"}`, 80),
        });
        if (cycle.act) {
            eat.push({
                stage: `execution-r${num}`,
                hash: generateHash(`e-${num}-${cycle.act}`),
                desc: truncate(`执行：${cycle.act}`, 80),
            });
        }
        if (cycle.reflexion) {
            eat.push({
                stage: `reflexion-r${num}`,
                hash: generateHash(`f-${num}-${cycle.reflexion}`),
                desc: truncate(`反思：${cycle.reflexion}`, 80),
            });
        }
    }

    return { nodes, react, hitl, eat };
}

function generateHash(seed) {
    let h = 0;
    for (let i = 0; i < seed.length; i++) {
        h = ((h << 5) - h + seed.charCodeAt(i)) | 0;
    }
    const hex = Math.abs(h).toString(16).padStart(8, "0");
    return `${hex.slice(0, 4)}…${hex.slice(4)}`;
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
}

function renderTimeline() {
    const scenario = scenarioData;
    if (!scenario) return;
    const list = document.getElementById("attack-timeline-list");
    if (!list) return;
    list.replaceChildren();

    for (const node of scenario.nodes) {
        const sev = SEVERITY_MAP[node.severity] || SEVERITY_MAP.medium;
        const li = document.createElement("li");
        li.className = "attack-node";
        li.dataset.node = node.id;
        li.dataset.severity = node.severity;

        li.innerHTML = `
            <div class="attack-node-dot"></div>
            <div class="attack-node-content">
                <div class="attack-node-header">
                    <span class="attack-node-badge">节点 ${node.id}</span>
                    <span class="attack-node-severity ${sev.cls}">${sev.label}</span>
                </div>
                <h3>${escapeHtml(node.title)}</h3>
                <p class="attack-node-desc">${escapeHtml(node.desc)}</p>
                <div class="attack-node-evidence">
                    <span class="evidence-tag">证据</span>
                    <code>${escapeHtml(node.evidence)}</code>
                </div>
            </div>
        `;
        list.append(li);
    }

    document.getElementById("timeline-progress").textContent = `0 / ${scenario.nodes.length}`;
}

function initAttackChain() {
    const submitBtn = document.getElementById("alert-submit");
    const input = document.getElementById("alert-input");
    const dropdownToggle = document.getElementById("alert-dropdown-toggle");
    const dropdownMenu = document.getElementById("alert-dropdown-menu");
    const playBtn = document.getElementById("attack-chain-play");
    const resetBtn = document.getElementById("attack-chain-reset");

    if (!submitBtn) return;

    submitBtn.addEventListener("click", () => generateAttackChain());

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            generateAttackChain();
        }
    });

    if (dropdownToggle && dropdownMenu) {
        dropdownToggle.addEventListener("click", () => {
            dropdownMenu.hidden = !dropdownMenu.hidden;
        });
        dropdownMenu.querySelectorAll("li").forEach((item) => {
            item.addEventListener("click", () => {
                input.value = item.dataset.alert;
                dropdownMenu.hidden = true;
                generateAttackChain();
            });
        });
        document.addEventListener("click", (e) => {
            if (!dropdownToggle.contains(e.target) && !dropdownMenu.contains(e.target)) {
                dropdownMenu.hidden = true;
            }
        });
    }

    if (playBtn) {
        playBtn.addEventListener("click", () => {
            if (isPlaying) {
                stopPlayback();
            } else {
                startPlayback();
            }
        });
    }

    if (resetBtn) {
        resetBtn.addEventListener("click", resetAll);
    }

    resetAll();
}

async function generateAttackChain() {
    const input = document.getElementById("alert-input");
    const submitBtn = document.getElementById("alert-submit");
    const statusEl = document.getElementById("alert-status");
    const alertText = input.value.trim();

    if (!alertText) {
        input.focus();
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "⏳ LLM 分析中…";

    const startTime = Date.now();
    const phases = [
        "Observe：分析告警特征…",
        "Orient：研判威胁类型…",
        "Decide：制定处置决策…",
        "Act：生成执行动作…",
        "Reflexion：策略修正…",
    ];
    let phaseIdx = 0;

    if (statusEl) statusEl.textContent = "正在调用 OODA API，由 LLM 生成攻击链…";

    loadingTimer = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        if (statusEl) {
            statusEl.textContent = `${phases[phaseIdx % phases.length]}（${elapsed}秒）`;
        }
        phaseIdx++;
    }, 3000);

    try {
        const data = await api.runOoda(alertText);
        const cycles = Array.isArray(data?.cycles) ? data.cycles : [];

        if (!cycles.length) {
            if (statusEl) statusEl.textContent = "OODA 服务未返回结果";
            return;
        }

        scenarioData = buildScenario(cycles);
        renderTimeline();
        resetAll();

        if (statusEl) statusEl.textContent = `已生成 ${cycles.length} 轮 OODA 攻击链`;
    } catch (err) {
        if (statusEl) statusEl.textContent = `生成失败：${err.message}`;
    } finally {
        if (loadingTimer) {
            clearInterval(loadingTimer);
            loadingTimer = null;
        }
        submitBtn.disabled = false;
        submitBtn.textContent = "生成攻击链";
    }
}

export { initAttackChain };

function startPlayback() {
    if (!scenarioData) return;
    isPlaying = true;
    const playBtn = document.getElementById("attack-chain-play");
    playBtn.textContent = "⏸ 暂停";

    if (currentStep >= scenarioData.nodes.length) {
        resetAll();
    }
    playNextNode();
}

function stopPlayback() {
    isPlaying = false;
    const playBtn = document.getElementById("attack-chain-play");
    playBtn.textContent = "▶ 自动推流";
    if (playTimer) {
        clearTimeout(playTimer);
        playTimer = null;
    }
}

function resetAll() {
    stopPlayback();
    currentStep = 0;

    document.querySelectorAll(".attack-node").forEach((node) => {
        node.classList.remove("is-active", "is-complete");
    });

    const nodeCount = scenarioData ? scenarioData.nodes.length : 0;
    document.getElementById("timeline-progress").textContent = `0 / ${nodeCount}`;

    const eventList = document.getElementById("decision-event-list");
    if (eventList) eventList.replaceChildren();

    document.querySelectorAll(".loop-node").forEach((n) => n.classList.remove("is-active"));

    const hitlPending = document.getElementById("hitl-pending");
    const hitlIdle = document.getElementById("hitl-idle");
    if (hitlPending) hitlPending.hidden = true;
    if (hitlIdle) {
        hitlIdle.hidden = false;
        hitlIdle.innerHTML = '<p>等待决策循环触发高危动作审批…</p><p class="hitl-hint">当智能体判定需要执行高危操作时，将暂停等待人工审批。</p>';
    }

    const eatBody = document.getElementById("eat-card-body");
    if (eatBody) {
        eatBody.innerHTML = '<div class="eat-empty"><p>尚未生成审计链事件</p><p class="eat-hint">批准高危动作后，执行结果将以密码学哈希链形式记录。</p></div>';
    }
}

function playNextNode() {
    const scenario = scenarioData;
    if (!scenario) return;

    if (currentStep >= scenario.nodes.length) {
        stopPlayback();
        triggerHITL();
        return;
    }

    const node = scenario.nodes[currentStep];
    const nodeEl = document.querySelector(`.attack-node[data-node="${node.id}"]`);
    if (nodeEl) {
        nodeEl.classList.add("is-active");
    }

    document.getElementById("timeline-progress").textContent = `${currentStep + 1} / ${scenario.nodes.length}`;

    const reactStart = currentStep * 2;
    for (let i = reactStart; i < reactStart + 2 && i < scenario.react.length; i++) {
        addReActEvent(scenario.react[i]);
        highlightLoopNode(scenario.react[i].type);
    }

    playTimer = setTimeout(() => {
        if (nodeEl) {
            nodeEl.classList.remove("is-active");
            nodeEl.classList.add("is-complete");
        }
        currentStep++;
        if (isPlaying) {
            playTimer = setTimeout(playNextNode, 600);
        }
    }, 2200);
}

function addReActEvent(event) {
    const list = document.getElementById("decision-event-list");
    if (!list) return;

    const li = document.createElement("li");
    li.className = `decision-event decision-${event.type}`;

    const time = new Date().toLocaleTimeString("zh-CN", { hour12: false });
    li.innerHTML = `
        <span class="event-type">${event.type === "thinking" ? "💭" : event.type === "acting" ? "⚡" : "👁"}</span>
        <span class="event-text">${escapeHtml(event.text)}</span>
        <time>${time}</time>
    `;
    list.append(li);
}

function highlightLoopNode(type) {
    document.querySelectorAll(".loop-node").forEach((n) => n.classList.remove("is-active"));
    const map = { thinking: "loop-thinking", acting: "loop-acting", observing: "loop-observing" };
    const id = map[type];
    if (id) {
        const node = document.getElementById(id);
        if (node) {
            node.classList.add("is-active");
            setTimeout(() => node.classList.remove("is-active"), 1500);
        }
    }
}

function triggerHITL() {
    const scenario = scenarioData;
    if (!scenario) return;
    const hitl = scenario.hitl;
    const hitlPending = document.getElementById("hitl-pending");
    const hitlIdle = document.getElementById("hitl-idle");
    if (hitlPending) hitlPending.hidden = false;
    if (hitlIdle) hitlIdle.hidden = true;

    const titleEl = document.getElementById("hitl-action-title");
    const detailEl = document.getElementById("hitl-action-detail");
    const reasonEl = document.getElementById("hitl-action-reason");
    if (titleEl) titleEl.textContent = hitl.title;
    if (detailEl) detailEl.textContent = hitl.detail;
    if (reasonEl) reasonEl.textContent = hitl.reason;

    const approveBtn = document.getElementById("hitl-approve");
    const rejectBtn = document.getElementById("hitl-reject");

    if (approveBtn) {
        approveBtn.onclick = () => {
            if (hitlPending) hitlPending.hidden = true;
            if (hitlIdle) {
                hitlIdle.hidden = false;
                hitlIdle.innerHTML = '<p class="hitl-approved">✓ 已批准执行</p><p class="hitl-hint">处置指令已下发，等待执行回执…</p>';
            }
            generateEAT();
        };
    }

    if (rejectBtn) {
        rejectBtn.onclick = () => {
            if (hitlPending) hitlPending.hidden = true;
            if (hitlIdle) {
                hitlIdle.hidden = false;
                hitlIdle.innerHTML = '<p class="hitl-rejected">✗ 已拒绝执行</p><p class="hitl-hint">拒绝后攻击链暂停，需人工介入分析。</p>';
            }
        };
    }
}

function generateEAT() {
    const scenario = scenarioData;
    if (!scenario) return;
    const eatBody = document.getElementById("eat-card-body");
    if (!eatBody) return;

    eatBody.innerHTML = "";
    const ol = document.createElement("ol");
    ol.className = "eat-event-list";

    scenario.eat.forEach((evt, idx) => {
        setTimeout(() => {
            const li = document.createElement("li");
            li.className = "eat-event";
            li.innerHTML = `
                <span class="eat-stage">${escapeHtml(evt.stage)}</span>
                <div class="eat-content">
                    <p>${escapeHtml(evt.desc)}</p>
                    <code class="eat-hash">hash: ${escapeHtml(evt.hash)}</code>
                </div>
                <span class="eat-status">✓</span>
            `;
            ol.append(li);
            eatBody.innerHTML = "";
            eatBody.append(ol);
        }, idx * 800);
    });
}
