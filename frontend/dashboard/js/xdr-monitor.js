/**
 * XDR 实时监测台 —— 独立路由页 #xdr-monitor
 *
 * 职责：
 * 1. 进入页面时检查 XDR 配置是否完整（调 /integrations/xdr/config 看 can_enable_xdr）
 *    - 未配置 → 显示「尚未连接，请前往设置配置」占位卡片
 *    - 已配置 → 显示监测面板并自动启动 5s 轮询
 * 2. 每轮：拉告警 → 触发研判 → 拉取统一队列（/integrations/xdr/alerts/unified）→ 展示到统一列表
 *    每捕获一个告警立即研判并显示在界面，研判未完成时显示 loading spinner
 * 3. 统一列表最多保留 100 条告警+研判配对，超过时自动淘汰队末（最旧）的记录
 * 4. 停止监测：调用 /integrations/xdr/stop 设置后端停止事件，清空队列
 * 5. 高危/严重告警的研判卡片上显示「封禁 IP」按钮，点击走 /integrations/xdr/respond（HITL 人审）
 */
import { api } from "./api-client.js";

const POLL_INTERVAL_MS = 5 * 1000;
const UNIFIED_LIMIT = 100;

const state = {
    polling: false,
    timer: null,
    /** AbortController：停止监测时 abort 正在进行的 HTTP 请求 */
    abortController: null,
    lastPolledAt: "",
    configured: false,
    provider: "",
    analyzing: false,
    /** 真实连通性状态："unknown" | "ok" | "failed" */
    connectivity: "unknown",
    /** Wazuh Manager 版本（连通后填充，用于 UI 显示） */
    managerVersion: "",
    /** 连通失败时的错误信息 */
    connectivityError: "",
    /** 轮询连续失败计数（超过阈值触发断连提示） */
    failCount: 0,
    /** 连通性检测中（避免并发） */
    checking: false,
    /** 停止按钮 loading 状态（防止重复点击） */
    stopping: false,
    /** 停止请求是否已确认（true 时，tick/下一轮会立即退出） */
    stopRequested: false,
    /** 正在运行的 tick 序号（用来识别「过期」的 tick，防止重复执行） */
    tickSeq: 0,
    /** 上一次 stop 的时间戳（防抖，防止双击） */
    lastStopAt: 0,
};

const dom = {};

function cacheDom() {
    const ids = [
        "xdr-empty-state", "xdr-monitor-grid",
        "xdr-poll-status", "xdr-poll-meta",
        "xdr-unified-list",
        "xdr-monitor-refresh", "xdr-monitor-toggle",
    ];
    ids.forEach((id) => { dom[id] = document.getElementById(id); });
}

function setPollStatus(label, stateClass) {
    if (!dom["xdr-poll-status"]) return;
    dom["xdr-poll-status"].textContent = label;
    dom["xdr-poll-status"].className = `xdr-poll-status ${stateClass}`;
}

function showEmpty() {
    if (dom["xdr-empty-state"]) dom["xdr-empty-state"].hidden = false;
    if (dom["xdr-monitor-grid"]) dom["xdr-monitor-grid"].hidden = true;
}

/** 显示"尚未配置"占位卡片 */
function showNotConfigured() {
    const card = dom["xdr-empty-state"]?.querySelector(".xdr-empty-card");
    if (card) {
        card.querySelector("h3").textContent = "尚未连接 XDR 平台";
        card.querySelector("p").textContent = "当前没有配置 XDR 连接信息。请前往系统设置配置 Wazuh 或通用 REST 厂商，保存后回到本页。";
        const btn = card.querySelector("button");
        if (btn) btn.textContent = "前往设置配置";
    }
    showEmpty();
}

/** 显示"已配置但 Wazuh 不可达"占位卡片 */
function showConnectivityFailed() {
    stopPolling(false);
    const card = dom["xdr-empty-state"]?.querySelector(".xdr-empty-card");
    if (card) {
        card.querySelector("h3").textContent = `${state.provider} 当前不可达`;
        const errMsg = state.connectivityError || "连接被拒绝或超时";
        card.querySelector("p").textContent = `配置已保存，但无法连通 ${state.provider} 服务（${errMsg}）。请确认 Wazuh Manager 和 Indexer 服务已启动，然后点击下方按钮重试。`;
        const btn = card.querySelector("button");
        if (btn) {
            btn.removeAttribute("data-route-jump");
            btn.textContent = "重新检测连通性";
            const fresh = btn.cloneNode(true);
            btn.replaceWith(fresh);
            fresh.addEventListener("click", async () => {
                fresh.disabled = true;
                fresh.textContent = "检测中…";
                const ok = await checkConnectivity();
                fresh.disabled = false;
                if (ok) {
                    showGrid();
                    startPolling();
                } else {
                    fresh.textContent = "重新检测连通性";
                    showConnectivityFailed();
                }
            });
        }
    }
    showEmpty();
}

function showGrid() {
    if (dom["xdr-empty-state"]) dom["xdr-empty-state"].hidden = true;
    if (dom["xdr-monitor-grid"]) dom["xdr-monitor-grid"].hidden = false;
}

function fmtTime() {
    return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

/** 渲染统一列表项（告警 + 研判配对） */
function renderUnifiedItem(item) {
    const alert = item.alert || {};
    const analysis = item.analysis || {};
    const status = item.status || "pending";

    const card = document.createElement("article");
    card.className = `xdr-unified-item xdr-sev-${alert.severity || "info"}`;

    // 左侧：告警信息
    const left = document.createElement("div");
    left.className = "xdr-unified-left";

    const sev = (alert.severity || "info").toUpperCase();
    const alertHeader = document.createElement("div");
    alertHeader.className = "xdr-unified-alert-header";
    alertHeader.innerHTML = `
        <span class="xdr-sev-tag xdr-sev-${alert.severity || "info"}">${escapeHtml(sev)}</span>
        <strong class="xdr-alert-title">${escapeHtml(alert.title || "(无标题告警)")}</strong>
    `;

    const alertMeta = document.createElement("div");
    alertMeta.className = "xdr-unified-alert-meta";
    alertMeta.textContent = `${escapeHtml(alert.source || "未知源")} · ${escapeHtml(alert.timestamp || "")}`;

    left.append(alertHeader, alertMeta);

    // 右侧：研判结果
    const right = document.createElement("div");
    right.className = "xdr-unified-right";

    if (status === "pending") {
        // 研判中状态
        const pending = document.createElement("div");
        pending.className = "xdr-unified-pending";
        pending.innerHTML = `
            <div class="xdr-loading-spinner"></div>
            <span>正在研判…</span>
        `;
        right.append(pending);
    } else if (status === "error") {
        // 研判失败
        const errorBox = document.createElement("div");
        errorBox.className = "xdr-unified-error";
        errorBox.innerHTML = `
            <span class="xdr-error-icon">⚠️</span>
            <span class="xdr-error-text">研判失败：${escapeHtml(analysis.reasoning || "未知错误")}</span>
        `;
        right.append(errorBox);
    } else {
        // 研判完成
        const level = analysis.threat_level || "未知";
        const levelClass = levelToClass(level);

        const analysisHeader = document.createElement("div");
        analysisHeader.className = `xdr-unified-analysis-header ${levelClass}`;
        const confidence = (analysis.confidence ?? 0).toFixed(2);
        analysisHeader.innerHTML = `
            <span class="xdr-threat-tag ${levelClass}">${escapeHtml(level)}</span>
            <span class="xdr-confidence">置信度 ${confidence}</span>
        `;

        const reasoning = document.createElement("div");
        reasoning.className = "xdr-unified-reasoning";
        reasoning.textContent = analysis.reasoning || "(无推理说明)";

        const tags = document.createElement("div");
        tags.className = "xdr-unified-tags";
        if (analysis.attack_technique) {
            tags.innerHTML += `<span class="xdr-tag">ATT&CK: ${escapeHtml(analysis.attack_technique)}</span>`;
        }
        if (analysis.cwe) {
            tags.innerHTML += `<span class="xdr-tag">CWE: ${escapeHtml(analysis.cwe)}</span>`;
        }
        const actionLabel = {
            monitor: "仅监测",
            alert: "告警",
            block_ip: "建议封禁 IP",
            isolate: "建议隔离主机",
        }[analysis.recommended_action] || analysis.recommended_action;
        if (actionLabel) {
            tags.innerHTML += `<span class="xdr-tag xdr-tag-action">建议: ${escapeHtml(actionLabel)}</span>`;
        }
        if (analysis.source === "rule") {
            tags.innerHTML += `<span class="xdr-tag xdr-tag-rule">规则研判</span>`;
        } else if (analysis.source === "llm") {
            tags.innerHTML += `<span class="xdr-tag xdr-tag-llm">LLM 研判</span>`;
        }

        right.append(analysisHeader, reasoning, tags);

        // 处置按钮（高危/严重 + 有目标 IP）
        if (
            (level === "高危" || level === "严重")
            && Array.isArray(analysis.target_ips)
            && analysis.target_ips.length > 0
        ) {
            const actions = document.createElement("div");
            actions.className = "xdr-unified-actions";
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "button button-danger button-sm";
            const action = analysis.recommended_action === "isolate" ? "isolate" : "block_ip";
            btn.textContent = action === "isolate" ? "隔离主机" : "封禁 IP";
            btn.addEventListener("click", () => respondToAlert(analysis, action, btn));
            actions.append(btn);
            right.append(actions);
        }
    }

    // 时间戳（研判完成时间）
    if (item.analyzed_at) {
        const ts = document.createElement("div");
        ts.className = "xdr-unified-timestamp";
        ts.textContent = escapeHtml(item.analyzed_at);
        right.append(ts);
    }

    card.append(left, right);
    return card;
}

function levelToClass(level) {
    if (level === "严重") return "threat-critical";
    if (level === "高危") return "threat-high";
    if (level === "中危") return "threat-medium";
    if (level === "低危") return "threat-low";
    if (level === "误报") return "threat-fp";
    return "threat-unknown";
}

function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

/** 检查 XDR 配置是否完整 */
async function checkConfig() {
    try {
        const cfg = await api.xdrConfig();
        if (cfg && cfg.can_enable_xdr) {
            state.configured = true;
            const PROVIDER_LABELS = {
                wazuh: "Wazuh",
                splunk: "Splunk ES",
                elastic: "Elastic Security",
                sentinel: "Microsoft Sentinel",
                qradar: "IBM QRadar",
                aliyun_sas: "阿里云安全中心",
                huawei_secmaster: "华为云 SecMaster",
            };
            state.provider = PROVIDER_LABELS[cfg.provider] || cfg.provider || "XDR";
            return true;
        }
        state.configured = false;
        return false;
    } catch {
        state.configured = false;
        return false;
    }
}

/** 真实连通性检测 */
async function checkConnectivity() {
    if (state.checking) return state.connectivity === "ok";
    state.checking = true;
    setPollStatus("检测连通性…", "state-checking");
    try {
        const result = await api.testXdr({});
        if (result && result.status === "success") {
            state.connectivity = "ok";
            state.connectivityError = "";
            const details = result.details || {};
            state.managerVersion = details.manager_version || "";
            setPollStatus(
                `已连接 ${state.provider}${state.managerVersion ? " " + state.managerVersion : ""}`,
                "state-ready"
            );
            return true;
        }
        state.connectivity = "failed";
        state.connectivityError = result?.message || "连接失败";
        setPollStatus("XDR 不可达", "state-failed");
        return false;
    } catch (err) {
        state.connectivity = "failed";
        const raw = err?.message || "请求异常";
        let brief = raw;
        if (raw.includes("由于目标计算机积极拒绝") || raw.includes("Connection refused")) {
            brief = "连接被拒绝（XDR 服务未启动）";
        } else if (raw.includes("timed out") || raw.includes("超时")) {
            brief = "连接超时（XDR 服务响应过慢或不可达）";
        } else if (raw.includes("Failed to establish")) {
            brief = "无法建立连接（网络不通或端口未开放）";
        } else if (raw.length > 80) {
            brief = raw.slice(0, 80) + "...";
        }
        state.connectivityError = brief;
        setPollStatus("XDR 不可达", "state-failed");
        return false;
    } finally {
        state.checking = false;
    }
}

/** 拉取统一队列并更新列表 */
async function fetchUnifiedQueue() {
    if (state.connectivity === "failed") return;
    if (state.stopRequested || !state.polling) return;
    try {
        const result = await api.xdrAlertsUnified(
            { limit: UNIFIED_LIMIT },
            { signal: state.abortController?.signal, retries: 0 }
        );
        // 请求可能在等待期间被 stop，若是则不更新 UI
        if (state.stopRequested || !state.polling) return;
        state.lastPolledAt = fmtTime();
        if (dom["xdr-poll-meta"]) {
            state.lastPolledAt = fmtTime();
            dom["xdr-poll-meta"].textContent = `最近刷新：${state.lastPolledAt}`;
        }

        if (!result || result.status !== "success") {
            state.failCount += 1;
            if (state.failCount >= 2) {
                setPollStatus("拉取失败，重检连通性…", "state-failed");
                state.connectivity = "unknown";
                checkConnectivity().then((ok) => {
                    if (!ok) showConnectivityFailed();
                });
            } else {
                setPollStatus("拉取失败", "state-failed");
            }
            return;
        }

        state.failCount = 0;
        const items = Array.isArray(result.items) ? result.items : [];
        if (dom["xdr-unified-list"]) {
            dom["xdr-unified-list"].replaceChildren();
            if (items.length === 0) {
                const empty = document.createElement("p");
                empty.className = "xdr-empty-text";
                empty.textContent = "暂无告警与研判记录。";
                dom["xdr-unified-list"].append(empty);
            } else {
                items.forEach((item) => dom["xdr-unified-list"].append(renderUnifiedItem(item)));
            }
        }
        const cached = result.total_cached || 0;
        setPollStatus(
            `已连接 ${state.provider}${state.managerVersion ? " " + state.managerVersion : ""} · ${items.length} 条记录（缓存 ${cached}/${UNIFIED_LIMIT}）`,
            "state-ready"
        );
    } catch (err) {
        if (err?.name === "AbortError" || /abort/i.test(err?.message || "")) return;
        state.failCount += 1;
        setPollStatus("请求异常", "state-failed");
        if (state.failCount >= 2) {
            state.connectivity = "unknown";
            checkConnectivity().then((ok) => {
                if (!ok) showConnectivityFailed();
            });
        }
    }
}

/** 触发研判（后端自动拉告警+研判+入队） */
async function triggerAnalyze() {
    if (state.analyzing) return;
    if (state.stopRequested || !state.polling) return;
    state.analyzing = true;
    try {
        await api.xdrAnalyze(
            { limit: 10, severity: "medium" },
            { signal: state.abortController?.signal, retries: 0 }
        );
    } catch (err) {
        if (err?.name === "AbortError" || /abort/i.test(err?.message || "")) return;
        console.error("[XDR Monitor] analyze failed", err);
    } finally {
        state.analyzing = false;
    }
}

/** 一轮完整轮询：触发研判 → 拉取统一队列 */
async function tick() {
    // 记录本轮序号、重置本地停止信号
    const mySeq = ++state.tickSeq;

    // 前置检查
    if (state.stopRequested || !state.polling) return;

    // 1. 触发研判
    await triggerAnalyze();
    if (state.stopRequested || !state.polling) return;

    // 2. 拉取统一队列
    await fetchUnifiedQueue();

    // 3. 若执行期间收到停止请求，则清理定时器，不再安排新轮次
    if (state.stopRequested) {
        state.polling = false;
        if (state.timer) {
            window.clearInterval(state.timer);
            state.timer = null;
        }
    }
}

function startPolling() {
    if (state.polling) return;
    state.polling = true;
    state.stopping = false;
    state.stopRequested = false;
    // 创建新的 AbortController 用于本轮的所有 HTTP 请求
    if (state.abortController) {
        state.abortController.abort();
    }
    state.abortController = new AbortController();
    // 清除后端 stop 事件（允许研判继续）
    api.xdrStart().catch(() => {});
    if (dom["xdr-monitor-toggle"]) {
        dom["xdr-monitor-toggle"].textContent = "停止监测";
        dom["xdr-monitor-toggle"].classList.add("is-active");
        dom["xdr-monitor-toggle"].disabled = false;
    }
    setPollStatus("启动中…", "state-checking");
    // 首次立即执行一轮
    tick();
    state.timer = window.setInterval(() => {
        // 若已请求停止，不启动新的 tick
        if (state.stopRequested || !state.polling) {
            if (state.timer) {
                window.clearInterval(state.timer);
                state.timer = null;
            }
            return;
        }
        tick();
    }, POLL_INTERVAL_MS);
}

async function stopPolling(callBackend = true, silent = false) {
    // 1. 防止重复点击（500ms 防抖 + 「正在停止」状态机）
    const now = Date.now();
    if (state.stopping && now - state.lastStopAt < 5000) return;
    state.stopping = true;
    state.lastStopAt = now;

    // 2. 设置停止请求标记（tick 会在每步之后检查）
    state.stopRequested = true;
    state.polling = false;

    // 3. 清定时器（确保不会再安排新的 tick）
    if (state.timer) {
        window.clearInterval(state.timer);
        state.timer = null;
    }

    // 4. abort 正在进行的 HTTP 请求
    if (state.abortController) {
        try { state.abortController.abort(); } catch {}
        state.abortController = null;
    }

    // 5. 同步禁用按钮防止误点
    if (!silent && dom["xdr-monitor-toggle"]) {
        dom["xdr-monitor-toggle"].textContent = "停止中…";
        dom["xdr-monitor-toggle"].disabled = true;
    }

    // 6. 调用后端 stop 接口（设置 threading.Event，清空队列）
    if (callBackend) {
        try {
            await Promise.race([
                api.xdrStop(),
                new Promise((resolve) => window.setTimeout(resolve, 3000)),
            ]);
        } catch (err) {
            console.warn("[XDR Monitor] xdrStop failed:", err);
        }
    }

    // 7. 更新 UI
    if (!silent && dom["xdr-monitor-toggle"]) {
        dom["xdr-monitor-toggle"].textContent = "启动监测";
        dom["xdr-monitor-toggle"].classList.remove("is-active");
        dom["xdr-monitor-toggle"].disabled = false;
    }
    if (!silent) {
        setPollStatus("已停止", "state-pending");
    }

    state.stopping = false;
}

/** 点击「封禁 IP」/「隔离主机」→ 调 respond → 后端走 HITL 人审 */
async function respondToAlert(analysis, action, btn) {
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = "提交人审中…";
    try {
        const result = await api.xdrRespond({
            alert_id: analysis.alert_id,
            action,
            target_ips: analysis.target_ips,
            reason: `研判结论: ${analysis.threat_level}（${analysis.attack_technique || "无ATT&CK"}）— ${analysis.reasoning || ""}`.slice(0, 200),
        });
        if (result && result.status === "success") {
            const res = result.result || {};
            const results = Array.isArray(res.results) ? res.results : [];
            const blocked = results.filter((r) => r.success).length;
            const rejected = results.filter((r) => r.status === "rejected").length;
            btn.textContent = rejected === results.length
                ? "人审已拒绝"
                : `已处置 ${blocked}/${results.length}`;
            btn.classList.add("is-done");
        } else {
            btn.textContent = "处置失败";
            btn.classList.add("is-failed");
        }
    } catch (err) {
        btn.textContent = "请求异常";
        btn.classList.add("is-failed");
        console.error("[XDR Monitor] respond failed", err);
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.textContent = original;
            btn.classList.remove("is-done", "is-failed");
        }, 4000);
    }
}

/** 进入页面时初始化 */
async function activate() {
    cacheDom();
    if (dom["xdr-monitor-refresh"]) {
        dom["xdr-monitor-refresh"].addEventListener("click", () => tick());
    }
    if (dom["xdr-monitor-toggle"]) {
        dom["xdr-monitor-toggle"].addEventListener("click", async () => {
            if (state.polling) {
                await stopPolling(true);
            } else {
                checkConnectivity().then((ok) => {
                    if (ok) {
                        showGrid();
                        startPolling();
                    } else {
                        showConnectivityFailed();
                    }
                });
            }
        });
    }

    // 1. 配置完整性检查
    const configured = await checkConfig();
    if (!configured) {
        showNotConfigured();
        setPollStatus("未配置", "state-pending");
        return;
    }

    // 2. 真实连通性检测
    setPollStatus("检测连通性…", "state-checking");
    const reachable = await checkConnectivity();
    if (!reachable) {
        showConnectivityFailed();
        return;
    }

    // 3. 连通 → 显示监测面板 + 启动轮询
    showGrid();
    startPolling();
}

/** 离开页面时清理 */
function deactivate() {
    stopPolling(false);  // 离开页面时不调后端 stop（保留队列数据）
}

// 监听 view 容器显隐
function setupVisibilityObserver() {
    const target = document.getElementById("view-xdr-monitor");
    if (!target) {
        window.addEventListener("DOMContentLoaded", setupVisibilityObserver, { once: true });
        return;
    }
    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            if (m.attributeName === "hidden") {
                if (!target.hidden) {
                    activate();
                } else {
                    deactivate();
                }
            }
        }
    });
    observer.observe(target, { attributes: true, attributeFilter: ["hidden"] });
    if (!target.hidden) activate();
}

setupVisibilityObserver();

export { activate, deactivate };
