import { api } from "./api-client.js";
import { createGraphViewer } from "./graph-render.js";
import { highlightFragment, langFromFilename } from "./code-highlight.js";

const TERMINAL_RUN_STATES = new Set([
    "completed",
    "failed",
    "cancelled",
    "rejected",
    "expired",
]);
const MAX_CODE_BYTES = 1024 * 1024;

function query(selector) {
    return document.querySelector(selector);
}

function queryAll(selector) {
    return [...document.querySelectorAll(selector)];
}

function textValue(value, fallback = "未返回数据") {
    if (value === null || value === undefined || value === "") {
        return fallback;
    }
    if (typeof value === "string") {
        return value;
    }
    try {
        return JSON.stringify(value, null, 2);
    } catch {
        return String(value);
    }
}

function compactJson(value, limit = 6000) {
    const text = textValue(value);
    return text.length > limit ? `${text.slice(0, limit)}\n内容已截断` : text;
}

function setState(element, stateClass, text) {
    element.classList.remove(
        "state-ready",
        "state-running",
        "state-pending",
        "state-completed",
        "state-checking",
        "state-failed",
    );
    element.classList.add(stateClass);
    element.textContent = text;
}

function createResultState(titleText, detailText, className = "") {
    const state = document.createElement("div");
    state.className = `result-state${className ? ` ${className}` : ""}`;
    const title = document.createElement("strong");
    const detail = document.createElement("p");
    title.textContent = titleText;
    detail.textContent = detailText;
    state.append(title, detail);
    return state;
}

function createLoadingState(label) {
    const state = document.createElement("div");
    state.className = "result-state is-loading";
    state.setAttribute("role", "status");
    state.setAttribute("aria-live", "polite");
    const title = document.createElement("strong");
    title.textContent = label;
    state.append(title);
    for (let index = 0; index < 3; index += 1) {
        const line = document.createElement("div");
        line.className = "skeleton-line";
        state.append(line);
    }
    return state;
}

function appendMessage(log, role, text, meta = "") {
    const message = document.createElement("article");
    message.className = `chat-message ${role}`;
    
    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    const avatarIcon = document.createElement("span");
    
    if (role === "user") {
        avatarIcon.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/></svg>';
    } else {
        avatarIcon.innerHTML = '<svg viewBox="0 0 64 64" width="32" height="32"><defs><linearGradient id="bgA" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0d2228"/><stop offset="1" stop-color="#1a3b40"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="14" ry="14" fill="url(#bgA)"/><rect x="37" y="6" width="15" height="12" rx="2" ry="2" fill="none" stroke="#f5a623" stroke-width="2"/><line x1="40" y1="11" x2="49" y2="11" stroke="#f5a623" stroke-width="1.5" stroke-linecap="round"/><line x1="40" y1="14" x2="48" y2="14" stroke="#f5a623" stroke-width="1.5" stroke-linecap="round"/><rect x="4" y="19" width="23" height="13" rx="6.5" ry="6.5" fill="none" stroke="#22c55e" stroke-width="2.5"/><rect x="20" y="29" width="23" height="13" rx="6.5" ry="6.5" fill="none" stroke="#22c55e" stroke-width="2.5"/><rect x="37" y="19" width="23" height="13" rx="6.5" ry="6.5" fill="none" stroke="#22c55e" stroke-width="2.5"/><circle cx="26" cy="25.5" r="3.8" fill="#22c55e"/><circle cx="38" cy="25.5" r="3.8" fill="#22c55e"/><path d="M21 36 L30 45 L45 28" stroke="#f5a623" stroke-width="4.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    }
    avatar.append(avatarIcon);
    
    const content = document.createElement("div");
    content.className = "message-content";
    
    const header = document.createElement("div");
    header.className = "message-meta";
    const sender = document.createElement("strong");
    const context = document.createElement("span");
    const body = document.createElement("p");
    sender.textContent = role === "user" ? "操作员" : "CangSight";
    context.textContent = meta || (role === "user" ? "当前会话" : "智能体回答");
    body.textContent = text;
    header.append(sender, context);
    content.append(header, body);
    
    message.append(avatar, content);
    log.append(message);
    log.scrollTop = log.scrollHeight;
    return { message, body };
}

function severityScore(item) {
    const raw = item?.severity_score ?? item?.severity ?? 0;
    const parsed = Number.parseFloat(raw);
    return Number.isFinite(parsed) ? parsed : 0;
}

function severityLabel(score) {
    if (score >= 9) return "严重";
    if (score >= 7) return "高危";
    if (score >= 4) return "中危";
    return "低危";
}

function wait(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function initCapabilityLab({ showToast, announce, onSelectLab }) {
    const labSwitches = queryAll("[data-lab]");
    const labPanels = queryAll("[data-lab-panel]");
    const chatLog = query("#chat-log");
    const chatForm = query("#chat-form");
    const chatInput = query("#chat-input");
    const chatType = query("#chat-type");
    const chatSubmit = query("#chat-submit");
    const chatToolResults = query("#chat-tool-results");

    const threatForm = query("#threat-form");
    const threatDescription = query("#threat-description");
    const threatType = query("#threat-type");
    const threatTimeRange = query("#threat-time-range");
    const threatSubmit = query("#threat-submit");
    const threatState = query("#threat-state");
    const threatRunId = query("#threat-run-id");
    const threatResult = query("#threat-result-content");

    const codeForm = query("#code-form");
    const codeFilename = query("#code-filename");
    const codeFile = query("#code-file");
    const codeFileLabel = query("#code-file-label");
    const codeContent = query("#code-content");
    const codeSubmit = query("#code-submit");
    const codeState = query("#code-state");
    const codeRisk = query("#code-risk");
    const codeFindings = query("#code-findings");
    const codeSliceToggle = query("#code-slice");
    const codeSliceDirection = query("#code-slice-direction");
    const codeGraphToggle = query("#code-graph");
    const codeHighlight = query("#code-highlight");
    const codeHighlightCode = codeHighlight ? codeHighlight.querySelector("code") : null;
    const codeGutter = query("#code-gutter");
    const scanCritical = query("#scan-critical");
    const scanHigh = query("#scan-high");
    const scanMedium = query("#scan-medium");
    const scanLow = query("#scan-low");

    const cweForm = query("#cwe-form");
    const cweQuery = query("#cwe-query");
    const cweState = query("#cwe-state");
    const cweCount = query("#cwe-count") || { textContent: "" };
    const cweList = query("#cwe-list");
    const cweDetail = query("#cwe-detail");

    const ctfForm = query("#ctf-form");
    const ctfChallenge = query("#ctf-challenge");
    const ctfAuthorized = query("#ctf-authorized");
    const ctfSubmit = query("#ctf-submit");
    const ctfState = query("#ctf-state");
    const ctfResult = query("#ctf-result-content");

    const oodaForm = query("#ooda-form");
    const oodaObjective = query("#ooda-objective");
    const oodaRun = query("#ooda-run");
    const oodaStep = query("#ooda-step");
    const oodaReset = query("#ooda-reset");
    const oodaState = query("#ooda-state");
    const oodaCycleCount = query("#ooda-cycle-count");
    const oodaReflexion = query("#ooda-reflexion");

    let cweLoaded = false;
    let analysisToken = 0;
    let oodaCycles = 0;

    function selectLab(name) {
        labSwitches.forEach((button) => {
            const active = button.dataset.lab === name;
            button.classList.toggle("is-active", active);
            button.setAttribute("aria-pressed", String(active));
        });
        labPanels.forEach((panel) => {
            const active = panel.dataset.labPanel === name;
            panel.hidden = !active;
            panel.classList.toggle("is-active", active);
        });
        if (name === "cwe" && !cweLoaded) {
            loadCwe();
        }
    }

    function applyCaseContext(name, context = {}) {
        if (name === "threat") {
            threatDescription.value = context.description || threatDescription.value;
            threatType.value = "comprehensive";
            threatTimeRange.value = "1h";
        } else if (name === "chat") {
            chatInput.value = context.description || chatInput.value;
            chatType.value = "security_event";
        } else if (name === "cwe") {
            cweQuery.value = context.query || "CWE-89";
        } else if (name === "ooda") {
            oodaObjective.value = context.objective
                || "对 SQL 注入事件进行证据研判、HITL 授权、限时处置与复测闭环";
        }
    }

    labSwitches.forEach((button) => {
        button.addEventListener("click", () => {
            const name = button.dataset.lab;
            selectLab(name);
            onSelectLab?.(name);
        });
    });

    function createToolCallSection(labelText, codeText) {
        const section = document.createElement("div");
        section.className = "tool-call-section";
        const label = document.createElement("span");
        label.className = "tool-call-label";
        label.textContent = labelText;
        const code = document.createElement("pre");
        code.className = "tool-call-code";
        code.textContent = codeText;
        section.append(label, code);
        return section;
    }

    // 工具调用历史：每个调用一个折叠块。
    // 入参里可能是整段源码，返回里可能是 20KB 原始 MCP 响应，所以折叠时只给
    // 序号、工具名、状态和参数名；展开后才给完整内容，靠限高滚动，不做截断。
    function renderToolResults(toolResults, toolCalls) {
        chatToolResults.replaceChildren();
        const title = document.createElement("strong");
        title.textContent = "工具调用";
        chatToolResults.append(title);

        if (!Array.isArray(toolResults) || !toolResults.length) {
            const copy = document.createElement("p");
            copy.textContent = "本轮没有调用工具，回答由当前模型直接生成。";
            chatToolResults.append(copy);
            return;
        }

        const calls = Array.isArray(toolCalls) ? toolCalls : [];
        const list = document.createElement("ol");
        list.className = "tool-result-list";

        toolResults.forEach((tool, index) => {
            // tool_calls 与 tool_results 是同一顺序 push 的，按下标配对参数
            const call = calls[index] || {};
            const name = tool?.tool_name || call?.name || `工具 ${index + 1}`;
            const ok = tool?.status === "success";
            const args = call?.args;
            const argKeys = args && typeof args === "object" && !Array.isArray(args)
                ? Object.keys(args)
                : [];

            const item = document.createElement("li");
            const details = document.createElement("details");
            details.className = "tool-call";

            const summary = document.createElement("summary");
            const order = document.createElement("span");
            order.className = "tool-call-order";
            order.textContent = String(index + 1);
            const nameEl = document.createElement("span");
            nameEl.className = "tool-call-name";
            nameEl.textContent = name;
            const stateEl = document.createElement("span");
            stateEl.className = `tool-call-state ${ok ? "is-ok" : "is-bad"}`;
            stateEl.textContent = ok ? "成功" : "失败";
            const hint = document.createElement("span");
            hint.className = "tool-call-hint";
            hint.textContent = argKeys.length ? argKeys.join(" · ") : "无参数";
            summary.append(order, nameEl, stateEl, hint);

            const body = document.createElement("div");
            body.className = "tool-call-body";
            if (argKeys.length) {
                body.append(createToolCallSection("调用参数", textValue(args)));
            }
            if (!ok && tool?.error) {
                body.append(createToolCallSection("错误", String(tool.error)));
            }
            body.append(createToolCallSection("返回结果", textValue(tool?.result)));

            details.append(summary, body);
            item.append(details);
            list.append(item);
        });

        chatToolResults.append(list);
    }

    chatForm.addEventListener("submit", (event) => {
        event.preventDefault();
        const message = chatInput.value.trim();
        if (!message) {
            chatInput.focus();
            showToast("请输入需要分析的安全问题", "error");
            return;
        }

        appendMessage(chatLog, "user", message);
        const pending = appendMessage(chatLog, "assistant", "正在分析请求并调用相关工具...", "处理中");
        chatInput.value = "";
        chatSubmit.disabled = true;
        chatSubmit.textContent = "分析中";

        let streamedText = "";
        let toolsRendered = false;

        const finish = () => {
            chatSubmit.disabled = false;
            chatSubmit.textContent = "发送分析";
        };

        const fail = (errorMessage) => {
            pending.message.classList.add("error");
            pending.body.textContent = `分析失败：${errorMessage}`;
            pending.message.querySelector(".message-meta span").textContent = "请求失败";
            showToast(errorMessage, "error");
            finish();
        };

        api.agentChatStream(message, chatType.value, {
            onMeta(meta) {
                const statusText = [];
                if (meta?.provider && meta?.model) {
                    statusText.push(`${meta.provider} / ${meta.model}`);
                }
                if (meta?.has_tool_calls) {
                    statusText.push("调用工具分析中");
                    pending.body.textContent = "正在调用安全分析工具...";
                }
                if (statusText.length) {
                    pending.message.querySelector(".message-meta span").textContent =
                        statusText.join(" | ");
                }
            },
            onTools(data) {
                toolsRendered = true;
                renderToolResults(data?.tool_results, data?.tool_calls);
                pending.body.textContent = "工具执行完成，正在生成分析报告...";
                pending.message.querySelector(".message-meta span").textContent = "生成报告中";
            },
            onDelta(data) {
                streamedText += data?.text || "";
                pending.body.textContent = streamedText;
            },
            onDone(data) {
                if (!streamedText) {
                    pending.body.textContent = data?.answer
                        || "分析已完成，但智能体未能生成文字回答。您可以重试或换一种方式描述问题。";
                }
                if (!toolsRendered) {
                    renderToolResults(data?.tool_results, data?.tool_calls);
                }

                const statusText = [];
                if (data?.provider && data?.model) {
                    statusText.push(`${data.provider} / ${data.model}`);
                }
                if (data?.tool_rounds) {
                    statusText.push(`${data.tool_rounds} 轮工具`);
                }
                if (data?.tool_calls?.length) {
                    statusText.push(`${data.tool_calls.length} 次工具调用`);
                }
                if (data?.tool_results?.length) {
                    const successCount = data.tool_results.filter(t => t.status === "success").length;
                    statusText.push(`${successCount}/${data.tool_results.length} 成功`);
                }
                pending.message.querySelector(".message-meta span").textContent =
                    statusText.length ? statusText.join(" | ") : "分析完成";
                announce("安全对话分析完成");
                finish();
            },
            onError(data) {
                fail(data?.message || "分析失败");
            },
        }).catch((error) => {
            let errorMessage = error.message;
            if (error.payload?.message) {
                errorMessage = error.payload.message;
            } else if (error.payload?.error) {
                errorMessage = error.payload.error;
            }
            fail(errorMessage);
        });
    });

    async function pollRun(runId, token) {
        const started = Date.now();
        while (Date.now() - started < 90000) {
            if (token !== analysisToken) {
                throw new Error("分析任务已被新的请求替代");
            }
            const run = await api.run(runId);
            const runState = run.status === "queued"
                ? "排队中"
                : run.status === "running"
                    ? "分析中"
                    : run.status === "rejected"
                        ? "已拒绝"
                        : run.status === "expired"
                            ? "已过期"
                            : run.status;
            setState(
                threatState,
                ["failed", "cancelled", "rejected", "expired"].includes(run.status)
                    ? "state-failed"
                    : "state-running",
                runState,
            );
            if (TERMINAL_RUN_STATES.has(run.status)) {
                return run;
            }
            await wait(1100);
        }
        throw new Error("分析运行超过 90 秒，请到审计日志查看后续状态");
    }

    function renderThreatResult(run) {
        threatResult.className = "result-state";
        threatResult.replaceChildren();
        if (run.status !== "completed") {
            const terminalCopy = {
                rejected: "分析请求已拒绝",
                expired: "分析请求已过期",
                failed: "分析执行失败",
                cancelled: "分析已取消",
            };
            threatResult.append(createResultState(
                terminalCopy[run.status] || "分析未完成",
                run.error || `运行状态为 ${run.status}`,
            ));
            return;
        }

        const result = run.result || {};
        const output = document.createElement("div");
        output.className = "analysis-output";
        const title = document.createElement("h4");
        const conclusion = document.createElement("p");
        const raw = document.createElement("pre");
        raw.className = "raw-result";
        title.textContent = "智能体研判";
        conclusion.textContent = result.conclusion
            || result.enhanced_conclusion
            || result.summary
            || "运行已经完成，请查看原始结果。";
        raw.textContent = compactJson(result);
        output.append(title, conclusion, raw);
        threatResult.append(output);
    }

    threatForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const description = threatDescription.value.trim();
        if (!description) {
            threatDescription.focus();
            showToast("请先输入安全事件描述", "error");
            return;
        }

        const token = ++analysisToken;
        threatSubmit.disabled = true;
        threatSubmit.textContent = "正在创建";
        setState(threatState, "state-running", "正在创建");
        threatResult.replaceChildren(createLoadingState("正在创建智能体运行"));

        try {
            const created = await api.createRun({
                team_profile: "cangsight_agent",
                run_id: `analysis-${Date.now()}`,
                payload: {
                    action: "react",
                    security_event: {
                        description,
                        analysis_type: threatType.value,
                        time_range: threatTimeRange.value,
                        source: "capability_lab",
                    },
                },
            });
            threatRunId.textContent = created.run_id;
            threatSubmit.textContent = "分析中";
            const run = await pollRun(created.run_id, token);
            renderThreatResult(run);
            setState(
                threatState,
                run.status === "completed" ? "state-completed" : "state-failed",
                run.status === "completed" ? "分析完成" : "分析失败",
            );
            announce(`威胁分析${run.status === "completed" ? "完成" : "失败"}`);
        } catch (error) {
            setState(threatState, "state-failed", "分析失败");
            threatResult.replaceChildren(createResultState("分析失败", error.message));
            showToast(error.message, "error");
        } finally {
            threatSubmit.disabled = false;
            threatSubmit.textContent = "创建分析任务";
        }
    });

    // ---- 代码高亮 ----
    // 叠层方案：上层 textarea 负责编辑（文字透明、只留光标），
    // 下层 pre 负责显示彩色文字。两边共享同一套字体与内边距，靠下面两个
    // 同步函数保证滚动位置一致，否则一滚动就错位。
    let highlightTimer = null;

    function syncHighlightScroll() {
        if (!codeHighlight || !codeContent) return;
        codeHighlight.scrollTop = codeContent.scrollTop;
        codeHighlight.scrollLeft = codeContent.scrollLeft;
        // 行号只跟随垂直滚动；水平方向固定不动
        if (codeGutter) codeGutter.scrollTop = codeContent.scrollTop;
    }

    function renderGutter() {
        if (!codeGutter || !codeContent) return;
        const text = codeContent.value;
        // 空内容时也留一行，否则行号列会整个塌掉
        const count = text ? text.split("\n").length : 1;
        const numbers = [];
        for (let i = 1; i <= count; i += 1) numbers.push(i);
        codeGutter.textContent = numbers.join("\n");
        // 行号列宽按位数走。用 px 而不是 ch：ch 取决于元素自身字号，
        // 而 wrapper 的字号和行号列的等宽字号不一致，算出来会偏窄。
        const digits = String(count).length;
        const wrap = codeContent.closest(".code-editor-wrap");
        if (wrap) {
            wrap.style.setProperty(
                "--gutter-w", `${Math.max(32, digits * 8 + 20)}px`,
            );
        }
        codeGutter.scrollTop = codeContent.scrollTop;
    }

    function renderHighlight() {
        if (!codeHighlightCode) return;
        const filename = codeFilename.value.trim() || "sample.cj";
        codeHighlightCode.replaceChildren(
            highlightFragment(codeContent.value, langFromFilename(filename)),
        );
        renderGutter();
        syncHighlightScroll();
    }

    function scheduleHighlight() {
        if (highlightTimer) window.clearTimeout(highlightTimer);
        highlightTimer = window.setTimeout(renderHighlight, 120);
    }

    if (codeContent && codeHighlightCode) {
        codeContent.addEventListener("input", scheduleHighlight);
        codeContent.addEventListener("scroll", syncHighlightScroll, { passive: true });
        // 改文件名会改变推断出的语言，关键字表跟着换
        codeFilename.addEventListener("input", scheduleHighlight);
        renderHighlight();
    }

    codeFile.addEventListener("change", async () => {
        const file = codeFile.files?.[0];
        if (!file) return;
        if (file.size > MAX_CODE_BYTES) {
            codeFile.value = "";
            showToast("文件超过 1 MB，请缩小后再扫描", "error");
            return;
        }
        try {
            codeContent.value = await file.text();
            codeFilename.value = file.name;
            codeFileLabel.textContent = `${file.name}，${Math.max(1, Math.round(file.size / 1024))} KB`;
            // 程序化赋值不会触发 input 事件，得手动重绘高亮
            renderHighlight();
            announce("本地代码文件已经读取");
        } catch {
            showToast("无法读取所选文件", "error");
        }
    });

    function setScanCounts(ranking) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        ranking.forEach((item) => {
            const score = severityScore(item);
            if (score >= 9) counts.critical += 1;
            else if (score >= 7) counts.high += 1;
            else if (score >= 4) counts.medium += 1;
            else counts.low += 1;
        });
        scanCritical.textContent = String(counts.critical);
        scanHigh.textContent = String(counts.high);
        scanMedium.textContent = String(counts.medium);
        scanLow.textContent = String(counts.low);
    }

    // 上一次渲染出来的图查看器，重绘前必须 destroy，否则 ResizeObserver 会泄漏
    let activeGraphViewer = null;

    function destroyGraphViewer() {
        if (!activeGraphViewer) return;
        activeGraphViewer.destroy();
        activeGraphViewer = null;
    }

    // 工具三态：pass 有结果 / empty 跑了但空 / reject 工具失败。
    // empty 与 reject 都不能读成“安全”，文案上必须区分开。
    const STAGE_NAME = {
        code_scan: "规则扫描",
        slice: "变量切片",
        graph: "依赖图",
    };
    const STAGE_STATE = {
        pass: "有结果",
        empty: "无结果",
        reject: "失败",
        skipped: "未执行",
    };
    const SKIP_REASON = {
        not_requested: "未请求",
        no_slice: "后端未切出变量",
        no_graph: "后端未生成图",
        backend_500: "后端生成失败，该语法可能不被支持",
        forbidden: "服务端拒绝（HTTP 403），稍后重试或检查服务端状态",
        unauthorized: "鉴权失败（HTTP 401），检查 SYMPAS_MCP_TOKEN",
        timeout: "调用超时",
        unreachable: "连不上服务端，检查 SYMPAS_MCP_URL 与网络",
        tool_error: "工具调用失败",
    };

    function describeRisk(data) {
        const risk = data?.composite_risk;
        if (risk && typeof risk === "object") {
            const overall = Number(risk.overall);
            const label = String(risk.label || "").toUpperCase();
            if (!Number.isFinite(overall) && !label) return "未返回综合风险";
            const score = Number.isFinite(overall) ? overall : "—";
            return label ? `综合风险 ${score} / ${label}` : `综合风险 ${score}`;
        }
        if (risk === undefined || risk === null) return "未返回综合风险";
        return `综合风险 ${textValue(risk)}`;
    }

    function createSection(className, titleText) {
        const section = document.createElement("div");
        section.className = className;
        const title = document.createElement("h4");
        title.textContent = titleText;
        section.append(title);
        return section;
    }

    function appendMutedRow(section, text) {
        const row = document.createElement("div");
        row.className = "slice-row";
        row.textContent = text;
        section.append(row);
    }

    function renderSliceBlock(slice) {
        if (!slice) return null;
        // 标题跟着实际方向走：前向说的是"影响哪些行"，别和后向混为一谈
        const isForward = slice.direction === "Fwd";
        const section = createSection(
            "slice-result",
            isForward ? "变量前向切片" : "变量后向切片",
        );

        if (slice.status === "skipped") {
            appendMutedRow(section, "本次未执行切片（勾选「变量切片」后重新扫描）");
            return section;
        }
        if (slice.status !== "pass") {
            appendMutedRow(
                section,
                `切片未产出：${SKIP_REASON[slice.reason] || slice.reason || slice.message || "未知原因"}`,
            );
            return section;
        }

        const vars = Array.isArray(slice.vars) ? slice.vars : [];
        if (!vars.length) {
            appendMutedRow(section, "切片已执行，但没有可展示的变量依赖");
            return section;
        }

        vars.slice(0, 30).forEach((item) => {
            const lines = Array.isArray(item.lines) ? item.lines : [];
            const shown = lines.slice(0, 20).join(", ");
            const more = lines.length > 20 ? ` …共 ${lines.length} 行` : "";
            const scope = item.func ? `${item.var} @${item.func}` : String(item.var);
            appendMutedRow(
                section,
                `${scope} · ${item.file || "当前文件"} · ${item.line_count ?? lines.length} 行`
                + `（${item.span?.[0] ?? "?"}–${item.span?.[1] ?? "?"}）：${shown}${more}`,
            );
        });
        if (vars.length > 30) {
            appendMutedRow(section, `另有 ${vars.length - 30} 个变量未展示`);
        }
        if (slice.engine) {
            appendMutedRow(section, `分析引擎：${slice.engine}`);
        }
        return section;
    }

    function renderGraphBlock(graph) {
        if (!graph) return null;
        const section = createSection("slice-result", "依赖图");

        if (graph.status === "skipped") {
            appendMutedRow(section, "本次未生成图（勾选「依赖图」后重新扫描）");
            return section;
        }
        if (graph.status !== "pass") {
            appendMutedRow(
                section,
                `图未产出：${SKIP_REASON[graph.reason] || graph.reason || graph.message || "未知原因"}`,
            );
            return section;
        }

        const graphs = Array.isArray(graph.graphs) ? graph.graphs : [];
        if (!graphs.length) {
            appendMutedRow(section, "后端返回的成功状态里没有图数据");
            return section;
        }

        const summary = document.createElement("div");
        summary.className = "code-meta";
        summary.textContent = graphs
            .map((item) => `${item.graph_type} ${item.node_count ?? "?"}n/${item.edge_count ?? "?"}e`)
            .join(" · ");
        section.append(summary);

        // 默认看 Sdg（系统依赖图）：仓颉代码的跨函数数据流与调用关系在 Sdg 上
        // 最直观，Cfg 只是单函数的控制流。图里没有 Sdg 时退回第一张。
        const viewer = createGraphViewer({ graphs, activeType: "Sdg", height: "460px" });
        activeGraphViewer = viewer;
        section.append(viewer.element);
        return section;
    }

    function renderStageBlock(stages) {
        if (!Array.isArray(stages) || !stages.length) return null;
        const section = createSection("stage-list", "分析阶段");

        stages.forEach((stage) => {
            const row = document.createElement("div");
            row.className = "stage-row";

            const name = document.createElement("span");
            name.className = "stage-name";
            name.textContent = STAGE_NAME[stage?.name] || stage?.name || "阶段";

            const state = document.createElement("span");
            const status = stage?.status || "empty";
            state.className = `stage-state is-${status}`;
            state.textContent = STAGE_STATE[status] || status;

            const note = document.createElement("span");
            note.className = "stage-note";
            const parts = [];
            if (stage?.note) parts.push(String(stage.note));
            if (stage?.ms != null) parts.push(`${stage.ms} ms`);
            note.textContent = parts.join(" · ");

            row.append(name, state, note);
            section.append(row);
        });
        return section;
    }

    function renderCodeResult(data) {
        const ranking = Array.isArray(data?.sbfl?.ranking) ? data.sbfl.ranking : [];
        const stages = Array.isArray(data?.stages) ? data.stages : [];
        setScanCounts(ranking);
        codeFindings.replaceChildren();
        destroyGraphViewer();

        codeRisk.textContent = describeRisk(data);

        // 分析对象：lang 回退成功时 file 与 effective_file 不同，必须让人看见换了后缀
        if (data?.effective_file || data?.lang) {
            const meta = document.createElement("div");
            meta.className = "code-meta";
            const parts = [];
            if (data?.effective_file) parts.push(`文件 ${data.effective_file}`);
            if (data?.lang) parts.push(`语言 ${data.lang}`);
            if (data?.file && data?.effective_file && data.file !== data.effective_file) {
                parts.push(`（原文件名 ${data.file}，已按内容回退）`);
            }
            meta.textContent = parts.join(" · ");
            codeFindings.append(meta);
        }

        // 1. 规则命中。没有命中不是提前结束：切片与图必须照常展示。
        if (ranking.length) {
            // 高危排前面，免得要滚到底才看到真正要紧的
            const ordered = [...ranking].sort(
                (a, b) => severityScore(b) - severityScore(a),
            );
            const shown = ordered.slice(0, 50);

            const listHead = document.createElement("div");
            listHead.className = "finding-list-head";
            listHead.textContent = `规则命中 ${ranking.length} 条${
                ranking.length > shown.length ? `（按严重度排序，显示前 ${shown.length}）` : ""
            }`;

            const list = document.createElement("div");
            list.className = "finding-items";

            shown.forEach((finding) => {
                const item = document.createElement("article");
                item.className = "finding-item";
                const body = document.createElement("div");
                const title = document.createElement("h4");
                const detail = document.createElement("p");
                const level = document.createElement("span");
                const score = severityScore(finding);
                title.textContent = `${finding.cwe || "CWE 未分类"}：${finding.name || "安全发现"}`;
                detail.textContent = finding.line
                    ? `位置：第 ${finding.line} 行`
                    : "位置：分析器未返回具体行号";
                level.className = "finding-severity";
                level.textContent = `${severityLabel(score)} ${score || ""}`.trim();
                body.append(title, detail);

                // 数据来源与涉及变量：只对 injection / memory-safety / info-leak
                // 这类与数据流有关的规则才有值（后端按 category 过滤过）
                const originKind = finding.origin?.origin;
                const originLabels = {
                    "param-direct": "形参直达",
                    "param-via": "经变量传入",
                    internal: "仅内部赋值",
                };
                const originLabel = originLabels[originKind];
                if (originLabel) {
                    detail.append(" · ");
                    const badge = document.createElement("span");
                    badge.className = `origin-badge origin-${originKind}`;
                    badge.textContent = originLabel;
                    badge.title = finding.origin?.detail || "";
                    detail.append(badge);
                }

                // 涉及的变量 + 它们在哪定义。直接给出"第几行的什么变量"，
                // 比一个抽象的"来源"标签更值得看。
                const defs = finding.origin?.var_defs || [];
                if (defs.length) {
                    const varNode = document.createElement("span");
                    varNode.className = "finding-vars";
                    varNode.textContent = `变量 ${
                        defs
                            .map((d) => (d.kind === "param"
                                ? `${d.var}（形参）`
                                : `${d.var}（第 ${d.line ?? "?"} 行）`))
                            .join("、")
                    }`;
                    detail.append(" · ", varNode);
                }
                // 切片若覆盖到该变量，补一行"依赖哪些行"
                const slices = finding.origin?.slices || [];
                if (slices.length) {
                    const picked = slices[0];
                    const lines = picked.lines || [];
                    const sliceNode = document.createElement("span");
                    sliceNode.className = "finding-slice";
                    sliceNode.textContent = ` · ${picked.var} 依赖 ${picked.line_count} 行：${
                        lines.slice(0, 8).join(", ")
                    }${lines.length > 8 ? " …" : ""}`;
                    sliceNode.title = lines.join(", ");
                    detail.append(sliceNode);
                }

                item.append(body, level);
                list.append(item);
            });

            codeFindings.append(listHead, list);
        } else {
            const scanStage = stages.find((stage) => stage?.name === "code_scan");
            let titleText = "规则未命中";
            let detailText = "规则扫描已完成，未命中已知规则。仍建议结合人工复核。";
            if (scanStage?.status === "reject") {
                titleText = "规则扫描失败";
                detailText = data?.recommendation
                    || "规则引擎不可用，本次结果不能作为安全判断依据。";
            } else if (data?.lang === "cangjie") {
                // 接入项目规则集后，仓颉不再是"规则集不覆盖"，而是"扫了但没命中"
                const ruleInfo = data?.rule_source?.type === "project"
                    ? `已用项目内置的 ${data.rule_source.rule_count} 条仓颉规则扫描`
                    : "规则引擎未覆盖仓颉（项目规则集未加载）";
                titleText = data?.rule_source?.type === "project"
                    ? "未命中仓颉规则"
                    : "规则引擎未覆盖仓颉";
                detailText = `${ruleInfo}，未命中已知模式。这只代表「没扫到」，不代表「没有风险」。请以变量切片与依赖图复核。`;
            }
            codeFindings.append(createResultState(titleText, detailText));
        }

        // 2. 变量切片
        const sliceBlock = renderSliceBlock(data?.slice);
        if (sliceBlock) codeFindings.append(sliceBlock);

        // 3. 依赖图
        const graphBlock = renderGraphBlock(data?.graph);
        if (graphBlock) codeFindings.append(graphBlock);

        // 4. 阶段耗时与状态
        const stageBlock = renderStageBlock(stages);
        if (stageBlock) codeFindings.append(stageBlock);

        // 5. 建议
        if (data?.recommendation) {
            const recommendation = document.createElement("div");
            recommendation.className = "recommendation";
            recommendation.textContent = `建议：${textValue(data.recommendation)}`;
            codeFindings.append(recommendation);
        }
    }

    codeForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const content = codeContent.value;
        const filename = codeFilename.value.trim() || "sample.py";
        if (!content.trim()) {
            codeContent.focus();
            showToast("请上传文件或粘贴代码", "error");
            return;
        }
        if (new Blob([content]).size > MAX_CODE_BYTES) {
            showToast("代码内容超过 1 MB，请缩小后再扫描", "error");
            return;
        }

        codeSubmit.disabled = true;
        codeSubmit.textContent = "扫描中";
        setState(codeState, "state-running", "扫描中");
        codeFindings.replaceChildren(createLoadingState(
            codeGraphToggle?.checked
                ? "正在执行规则扫描、变量切片与依赖图生成"
                : "正在执行规则扫描与变量切片",
        ));
        destroyGraphViewer();

        try {
            const data = await api.analyzeCode(content, filename, {
                includeSlice: codeSliceToggle ? codeSliceToggle.checked : true,
                sliceDirection: codeSliceDirection ? codeSliceDirection.value : "Bwd",
                includeGraph: codeGraphToggle ? codeGraphToggle.checked : false,
            });
            renderCodeResult(data);
            setState(codeState, "state-completed", "扫描完成");
            announce("代码扫描完成");
        } catch (error) {
            setState(codeState, "state-failed", "扫描失败");
            codeFindings.replaceChildren(createResultState("扫描失败", error.message));
            showToast(error.message, "error");
        } finally {
            codeSubmit.disabled = false;
            codeSubmit.textContent = "开始扫描";
        }
    });

    async function showCweDetail(cweId, sourceButton) {
        cweList.querySelectorAll(".cwe-row").forEach((button) => {
            button.classList.toggle("is-selected", button === sourceButton);
        });
        cweDetail.replaceChildren(createLoadingState("正在读取 CWE 详情"));
        try {
            const item = await api.cweDetail(cweId);
            cweDetail.replaceChildren();
            const kicker = document.createElement("span");
            const title = document.createElement("h3");
            const description = document.createElement("p");
            const details = document.createElement("dl");
            const score = severityScore(item);
            kicker.className = "summary-kicker";
            kicker.textContent = `${cweId} / ${severityLabel(score)}`;
            title.textContent = item?.name || item?.cwe_name || cweId;
            description.textContent = item?.description || "暂无描述";

            const riskGroup = document.createElement("div");
            const riskTerm = document.createElement("dt");
            const riskValue = document.createElement("dd");
            riskTerm.textContent = "严重度";
            riskValue.textContent = score ? `${severityLabel(score)}，${score}/10` : "知识库未提供评分";
            riskGroup.append(riskTerm, riskValue);

            const mitigationGroup = document.createElement("div");
            const mitigationTerm = document.createElement("dt");
            const mitigationValue = document.createElement("dd");
            mitigationTerm.textContent = "修复建议";
            mitigationValue.textContent = item?.mitigation || "暂无修复建议";
            mitigationGroup.append(mitigationTerm, mitigationValue);

            details.append(riskGroup, mitigationGroup);
            cweDetail.append(kicker, title, description, details);
        } catch (error) {
            cweDetail.replaceChildren(createResultState("无法读取条目", error.message));
        }
    }

    function renderCweList(items) {
        cweList.replaceChildren();
        cweCount.textContent = `${items.length} 条`;
        if (!items.length) {
            cweList.append(createResultState("没有匹配条目", "请更换关键词或使用 CWE 编号。"));
            return;
        }

        items.forEach((item) => {
            const id = item?.cwe_id || item?.id || "CWE-UNKNOWN";
            const row = document.createElement("button");
            const idText = document.createElement("span");
            const name = document.createElement("strong");
            const level = document.createElement("span");
            row.className = "cwe-row";
            row.type = "button";
            idText.textContent = id;
            name.textContent = item?.name || item?.cwe_name || "未命名漏洞";
            level.className = "cwe-level";
            level.textContent = severityLabel(severityScore(item));
            row.append(idText, name, level);
            row.addEventListener("click", () => showCweDetail(id, row));
            cweList.append(row);
        });
    }

    async function loadCwe(pattern = "") {
        setState(cweState, "state-checking", "加载中");
        cweList.replaceChildren(createLoadingState("正在读取本地 CWE 知识库"));
        try {
            const data = await api.cweSearch(pattern);
            const items = Array.isArray(data) ? data : [];
            renderCweList(items);
            setState(cweState, "state-ready", "已加载");
            cweLoaded = true;
            if (items.length) {
                const first = cweList.querySelector(".cwe-row");
                first?.click();
            }
        } catch (error) {
            setState(cweState, "state-failed", "加载失败");
            cweList.replaceChildren(createResultState("知识库加载失败", error.message));
            showToast(error.message, "error");
        }
    }

    cweForm.addEventListener("submit", (event) => {
        event.preventDefault();
        loadCwe(cweQuery.value.trim());
    });

    ctfAuthorized.addEventListener("change", () => {
        ctfSubmit.disabled = !ctfAuthorized.checked;
        setState(
            ctfState,
            ctfAuthorized.checked ? "state-ready" : "state-pending",
            ctfAuthorized.checked ? "授权已确认" : "需要授权确认",
        );
    });

    ctfForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const challenge = ctfChallenge.value.trim();
        if (!ctfAuthorized.checked) {
            ctfAuthorized.focus();
            showToast("请先确认目标已经获得授权", "error");
            return;
        }
        if (!challenge) {
            ctfChallenge.focus();
            showToast("请输入 CTF 题目或授权靶场描述", "error");
            return;
        }

        ctfSubmit.disabled = true;
        ctfSubmit.textContent = "分析中";
        setState(ctfState, "state-running", "分析中");

        const isUrl = /^https?:\/\//i.test(challenge);
        ctfResult.className = "result-state";
        ctfResult.replaceChildren();
        const timeline = document.createElement("div");
        timeline.className = "ctf-timeline";
        const header = document.createElement("h4");
        header.textContent = isUrl ? "CTF 自主攻击时间线" : "CTF 题目分析";
        timeline.append(header);
        const stepsContainer = document.createElement("div");
        stepsContainer.className = "ctf-steps";
        timeline.append(stepsContainer);
        ctfResult.append(timeline);

        const token = Symbol("ctf");

        function addStep(icon, label, detail) {
            const step = document.createElement("div");
            step.className = "ctf-step";
            const iconEl = document.createElement("span");
            iconEl.className = "ctf-step-icon";
            iconEl.textContent = icon;
            const labelEl = document.createElement("span");
            labelEl.className = "ctf-step-label";
            labelEl.textContent = label;
            step.append(iconEl, labelEl);
            if (detail) {
                const detailEl = document.createElement("div");
                detailEl.className = "ctf-step-detail";
                detailEl.textContent = detail;
                step.append(detailEl);
            }
            stepsContainer.append(step);
            stepsContainer.scrollTop = stepsContainer.scrollHeight;
        }

        function addFlagBadge(flags) {
            if (!flags || flags.length === 0) return;
            const badge = document.createElement("div");
            badge.className = "ctf-flag-found";
            badge.textContent = `🏆 Flag: ${flags.join(", ")}`;
            stepsContainer.append(badge);
        }

        try {
            const created = await api.createRun({
                team_profile: "ctf_agent",
                run_id: `ctf-${Date.now()}`,
                payload: isUrl
                    ? { target_url: challenge }
                    : { challenge_description: challenge },
            });

            const runId = created.run_id;
            addStep("🚀", "任务已创建", `Run ID: ${runId}`);

            const evtSource = new EventSource(`/agents/runs/${encodeURIComponent(runId)}/events`);
            let completed = false;

            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    evtSource.close();
                    reject(new Error("CTF 分析超过 120 秒"));
                }, 120000);

                evtSource.addEventListener("connected", () => {
                    addStep("📡", "已连接到事件流");
                });

                evtSource.addEventListener("ctf_mission_started", (e) => {
                    const d = JSON.parse(e.data);
                    addStep("🎯", "任务启动", `目标: ${d.target_url || challenge}`);
                });

                evtSource.addEventListener("phase_start", (e) => {
                    const d = JSON.parse(e.data);
                    addStep("📍", `阶段: ${d.phase}`, d.description || "");
                });

                evtSource.addEventListener("tool_call", (e) => {
                    const d = JSON.parse(e.data);
                    const toolName = d.tool || "";
                    const action = d.action || "";
                    const icons = {
                        port_scan: "🔍", dir_brute: "📂", http_request: "🌐",
                        sql_inject: "💉", xss_test: "⚡", upload_test: "📤",
                        exploit_sqli: "🔨", find_flag: "🚩", sensitive_files: "🔑",
                        lfi_rfi_test: "📄", command_inject: "💻", ssrf_test: "🔄",
                        vkb_retrieve: "📚", cwe_classifier: "🏷️", sbfl_rank: "📊",
                        uafr_report: "📋",
                    };
                    addStep(icons[toolName] || "🔧", `${toolName}: ${action}`);
                });

                evtSource.addEventListener("llm_decision", (e) => {
                    const d = JSON.parse(e.data);
                    addStep("🧠", `LLM决策 #${d.step}`, `${d.action || "等待"} - ${d.reasoning || ""}`);
                });

                evtSource.addEventListener("vulnerability_found", (e) => {
                    const d = JSON.parse(e.data);
                    addStep("⚠️", `发现漏洞: ${d.type}`, d.url || "");
                });

                evtSource.addEventListener("flag_found", (e) => {
                    const d = JSON.parse(e.data);
                    addFlagBadge(d.flags);
                });

                evtSource.addEventListener("ctf_mission_completed", (e) => {
                    const d = JSON.parse(e.data);
                    completed = true;
                    clearTimeout(timeout);
                    evtSource.close();
                    addStep("✅", "任务完成", `阶段: ${d.phase || "completed"}, Flag: ${(d.flags_found || []).length}个`);
                    resolve(d);
                });

                evtSource.addEventListener("run_failed", (e) => {
                    const d = JSON.parse(e.data);
                    clearTimeout(timeout);
                    evtSource.close();
                    reject(new Error(d.error || "CTF 任务执行失败"));
                });

                evtSource.addEventListener("run_completed", (e) => {
                    clearTimeout(timeout);
                    evtSource.close();
                    if (!completed) {
                        resolve({});
                    }
                });

                evtSource.onerror = () => {
                    clearTimeout(timeout);
                    evtSource.close();
                    if (!completed) {
                        reject(new Error("事件流连接中断"));
                    }
                };
            });

            const run = await api.run(runId);
            if (run.result) {
                const result = typeof run.result === "string" ? JSON.parse(run.result) : run.result;
                if (result.vulnerabilities && result.vulnerabilities.length > 0) {
                    addStep("📊", `发现 ${result.vulnerabilities.length} 个漏洞`);
                }
                if (result.flags_found && result.flags_found.length > 0) {
                    addFlagBadge(result.flags_found);
                }
                if (result.tool_execution_trace) {
                    addStep("📋", `工具调用总计: ${result.tool_execution_trace.length} 次`);
                }
            }

            setState(ctfState, "state-completed", "分析完成");
            announce("CTF 分析完成");
        } catch (error) {
            ctfResult.append(createResultState("CTF 分析失败", error.message));
            setState(ctfState, "state-failed", "分析失败");
            showToast(error.message, "error");
        } finally {
            ctfSubmit.disabled = !ctfAuthorized.checked;
            ctfSubmit.textContent = "开始 CTF 分析";
        }
    });

    function resetOoda() {
        oodaCycles = 0;
        oodaCycleCount.textContent = "0";
        oodaReflexion.textContent = "完成循环后显示策略修正与下一轮建议。";
        ["observe", "orient", "decide", "act"].forEach((stage) => {
            const panel = query(`[data-ooda-stage="${stage}"]`);
            panel.classList.remove("is-running", "is-complete");
            query(`#ooda-${stage}`).textContent = "等待执行";
        });
        setState(oodaState, "state-ready", "等待目标");
    }

    function renderOodaCycle(cycle) {
        ["observe", "orient", "decide", "act"].forEach((stage) => {
            const panel = query(`[data-ooda-stage="${stage}"]`);
            panel.classList.remove("is-running");
            panel.classList.add("is-complete");
            query(`#ooda-${stage}`).textContent = textValue(cycle?.[stage], "本轮没有返回该阶段内容");
        });
        oodaReflexion.textContent = textValue(
            cycle?.reflexion,
            "本轮没有返回反思内容。",
        );
    }

    async function executeOoda(mode) {
        const objective = oodaObjective.value.trim();
        if (!objective) {
            oodaObjective.focus();
            showToast("请输入 OODA 任务目标", "error");
            return;
        }

        oodaRun.disabled = true;
        oodaStep.disabled = true;
        setState(oodaState, "state-running", mode === "step" ? "单步执行中" : "循环执行中");
        queryAll("[data-ooda-stage]").forEach((panel) => {
            panel.classList.remove("is-complete");
            panel.classList.add("is-running");
        });

        try {
            const data = mode === "step"
                ? await api.stepOoda(objective)
                : await api.runOoda(objective);
            const cycles = Array.isArray(data?.cycles) ? data.cycles : [];
            if (!cycles.length) {
                throw new Error("OODA 服务没有返回循环结果");
            }
            renderOodaCycle(cycles[cycles.length - 1]);
            oodaCycles += mode === "step" ? 1 : cycles.length;
            oodaCycleCount.textContent = String(oodaCycles);
            setState(oodaState, "state-completed", "执行完成");
            announce("OODA 决策循环执行完成");
        } catch (error) {
            queryAll("[data-ooda-stage]").forEach((panel) => {
                panel.classList.remove("is-running");
            });
            setState(oodaState, "state-failed", "执行失败");
            oodaReflexion.textContent = error.message;
            showToast(error.message, "error");
        } finally {
            oodaRun.disabled = false;
            oodaStep.disabled = false;
        }
    }

    oodaForm.addEventListener("submit", (event) => {
        event.preventDefault();
        executeOoda("full");
    });
    oodaStep.addEventListener("click", () => executeOoda("step"));
    oodaReset.addEventListener("click", resetOoda);

    return { selectLab, applyCaseContext };
}

