const DEFAULT_TIMEOUT = 10000;
const MAX_RETRIES = 2;
const RETRY_DELAY = 1500;
const HEALTH_CHECK_INTERVAL = 30000;
const RECONNECT_DELAY = 5000;

function resolveBaseUrl() {
    if (window.location.protocol === "file:") {
        return "http://localhost:7800";
    }
    return window.location.origin;
}

export class ApiError extends Error {
    constructor(message, status = 0, payload = null) {
        super(message);
        this.name = "ApiError";
        this.status = status;
        this.payload = payload;
    }
}

export class ApiClient {
    constructor(baseUrl = resolveBaseUrl()) {
        this.baseUrl = baseUrl.replace(/\/$/, "");
        this._lastHealthCheck = 0;
        this._isServerAvailable = null;
        this._healthCheckTimer = null;
        this._listeners = new Set();
        this._consecutiveFailures = 0;
        this._maxConsecutiveFailures = 5;
        this._requestQueue = [];
        this._isProcessingQueue = false;
        this._lastSuccessfulRequest = 0;
        this._offlineMode = false;
    }

    on(event, callback) {
        if (event === "connectionChange") {
            const listener = { event, callback };
            this._listeners.add(listener);
            return () => this._listeners.delete(listener);
        }
        return () => {};
    }

    _emit(event, data) {
        this._listeners.forEach((listener) => {
            if (listener.event === event) {
                try {
                    listener.callback(data);
                } catch {}
            }
        });
    }

    _setConnectionState(available) {
        const changed = this._isServerAvailable !== available;
        this._isServerAvailable = available;
        if (changed) {
            this._offlineMode = !available;
            this._emit("connectionChange", { available, timestamp: Date.now() });
        }
        if (available) {
            this._consecutiveFailures = 0;
            this._lastSuccessfulRequest = Date.now();
            this._offlineMode = false;
        } else {
            this._consecutiveFailures++;
        }
    }

    async request(path, options = {}) {
        const maxRetries = options.retries ?? MAX_RETRIES;
        const timeout = options.timeout ?? DEFAULT_TIMEOUT;
        let lastError = null;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            if (attempt > 0) {
                const backoff = RETRY_DELAY * Math.pow(2, attempt - 1);
                await this._delay(backoff);
            }

            const controller = new AbortController();
            const timeoutId = window.setTimeout(() => controller.abort(), timeout);
            // 支持外部传入的 signal（用于用户主动取消请求）
            if (options.signal) {
                options.signal.addEventListener("abort", () => controller.abort());
            }

            const headers = new Headers(options.headers || {});
            if (options.body && !headers.has("Content-Type")) {
                headers.set("Content-Type", "application/json");
            }
            headers.set("Accept", "application/json");
            headers.set("X-Request-ID", `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);

            try {
                const url = `${this.baseUrl}${path}`;
                const response = await fetch(url, {
                    ...options,
                    headers,
                    signal: controller.signal,
                });

                window.clearTimeout(timeoutId);

                const contentType = response.headers.get("content-type") || "";
                let payload;
                try {
                    payload = contentType.includes("application/json")
                        ? await response.json()
                        : await response.text();
                } catch {
                    payload = await response.text();
                    if (!payload) {
                        payload = {};
                    }
                }

                if (!response.ok) {
                    const detail = (typeof payload === 'object' && payload !== null)
                        ? (payload.message || payload.error || payload.detail || response.statusText)
                        : (payload || response.statusText);
                    const error = new ApiError(detail || `请求失败 (${response.status})`, response.status, payload);
                    
                    if (response.status >= 500 && attempt < maxRetries) {
                        lastError = error;
                        continue;
                    }
                    
                    if (response.status === 429 && attempt < maxRetries) {
                        lastError = error;
                        continue;
                    }
                    
                    throw error;
                }

                this._setConnectionState(true);
                return payload;
            } catch (error) {
                window.clearTimeout(timeoutId);

                if (error.name === "AbortError") {
                    // 用户主动取消（外部 signal abort）→ 直接抛 AbortError，不重试、不当失败
                    if (options.signal?.aborted) {
                        throw error;
                    }
                    // 超时 abort → 当作超时处理
                    lastError = new ApiError("请求超时，请检查本地服务是否运行", 0);
                    if (attempt < maxRetries) {
                        continue;
                    }
                    this._setConnectionState(false);
                    throw lastError;
                }

                if (error instanceof ApiError) {
                    lastError = error;
                    if ((error.status >= 500 || error.status === 429) && attempt < maxRetries) {
                        continue;
                    }
                    if (error.status === 0) {
                        this._setConnectionState(false);
                    }
                    throw error;
                }

                lastError = new ApiError(
                    "网络连接失败，请检查本地服务是否启动",
                    0,
                    { cause: error.message }
                );
                if (attempt < maxRetries) {
                    continue;
                }
                this._setConnectionState(false);
                throw lastError;
            }
        }

        this._setConnectionState(false);
        throw lastError || new ApiError("请求失败，请稍后重试", 0);
    }

    async _delay(ms) {
        return new Promise(resolve => window.setTimeout(resolve, ms));
    }

    async checkServerConnection(force = false) {
        const now = Date.now();
        if (!force && now - this._lastHealthCheck < 5000 && this._isServerAvailable !== null) {
            return this._isServerAvailable;
        }

        this._lastHealthCheck = now;
        try {
            const result = await this.health();
            this._setConnectionState(true);
            return result;
        } catch (error) {
            this._setConnectionState(false);
            return false;
        }
    }

    startHealthCheck(interval = HEALTH_CHECK_INTERVAL) {
        if (this._healthCheckTimer) {
            return;
        }
        this._healthCheckTimer = window.setInterval(() => {
            this.checkServerConnection().catch(() => {});
        }, interval);
    }

    stopHealthCheck() {
        if (this._healthCheckTimer) {
            window.clearInterval(this._healthCheckTimer);
            this._healthCheckTimer = null;
        }
    }

    get isOnline() {
        return this._isServerAvailable === true;
    }

    get isOfflineMode() {
        return this._offlineMode;
    }

    get(path, options = {}) {
        return this.request(path, { ...options, method: "GET" });
    }

    post(path, payload, options = {}) {
        return this.request(path, {
            ...options,
            method: "POST",
            body: JSON.stringify(payload ?? {}),
        });
    }

    health() {
        return this.get("/health", { timeout: 5000 });
    }

    runs() {
        return this.get("/agents/runs");
    }

    createRun(payload) {
        return this.post("/agents/runs", payload);
    }

    run(runId) {
        return this.get(`/agents/runs/${encodeURIComponent(runId)}`);
    }

    cancelRun(runId) {
        return this.post(`/agents/runs/${encodeURIComponent(runId)}/cancel`, {});
    }

    agentChat(message, inputType = "", authorization = null) {
        const payload = {
            message,
            input_type: inputType,
        };
        if (authorization) {
            payload.authorization = authorization;
        }
        return this.post("/agent/chat", payload, { timeout: 60000, retries: 1 });
    }

    /**
     * 流式安全对话（SSE）。通过 onMeta/onTools/onDelta/onDone/onError 回调逐步接收结果。
     * @returns {Promise<void>} 流结束或出错时 resolve
     */
    async agentChatStream(message, inputType = "", handlers = {}, options = {}) {
        const url = `${this.baseUrl}/agent/chat/stream`;
        const controller = new AbortController();
        const timeoutId = window.setTimeout(() => controller.abort(), options.timeout ?? 90000);
        if (options.signal) {
            options.signal.addEventListener("abort", () => controller.abort());
        }

        try {
            const response = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                    "X-Request-ID": `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                },
                body: JSON.stringify({ message, input_type: inputType }),
                signal: controller.signal,
            });

            if (!response.ok || !response.body) {
                let detail = `请求失败 (${response.status})`;
                try {
                    const data = await response.json();
                    detail = data?.message || data?.error || detail;
                } catch {}
                throw new ApiError(detail, response.status, null);
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                let sep;
                while ((sep = buffer.indexOf("\n\n")) >= 0) {
                    const raw = buffer.slice(0, sep);
                    buffer = buffer.slice(sep + 2);
                    this._dispatchSse(raw, handlers);
                }
            }
            this._setConnectionState(true);
        } catch (error) {
            if (error.name === "AbortError") {
                if (options.signal?.aborted) throw error;
                throw new ApiError("请求超时，请检查本地服务是否运行", 0);
            }
            throw error;
        } finally {
            window.clearTimeout(timeoutId);
        }
    }

    _dispatchSse(raw, handlers) {
        let event = "message";
        let data = "";
        for (const line of raw.split("\n")) {
            if (line.startsWith("event:")) {
                event = line.slice(6).trim();
            } else if (line.startsWith("data:")) {
                data += line.slice(5).replace(/^ /, "");
            }
        }
        if (!data) return;
        let payload = data;
        try {
            payload = JSON.parse(data);
        } catch {}
        const handler = {
            meta: handlers.onMeta,
            tools: handlers.onTools,
            delta: handlers.onDelta,
            done: handlers.onDone,
            error: handlers.onError,
        }[event];
        if (handler) handler(payload);
    }

    scenario(message, inputType = "") {
        return this.post("/agent/scenario", {
            message,
            input_type: inputType,
        }, { timeout: 60000, retries: 1 });
    }

    scenarioPreset(presetKey) {
        return this.post("/agent/scenario/preset", {
            preset_key: presetKey,
        }, { timeout: 10000, retries: 1 });
    }

    analyzeCode(content, filename) {
        return this.post("/threat/analyze", {
            content,
            filename,
        }, { timeout: 30000 });
    }

    cweSearch(pattern = "") {
        const suffix = pattern ? `?pattern=${encodeURIComponent(pattern)}` : "";
        return this.get(`/cwe/search${suffix}`);
    }

    cweDetail(cweId) {
        return this.get(`/cwe/search?id=${encodeURIComponent(cweId)}`);
    }

    runOoda(objective) {
        return this.post("/agents/ooda", { objective }, { timeout: 120000 });
    }

    stepOoda(objective) {
        return this.post("/agents/ooda/step", {
            objective,
            cycle_count: 1,
        }, { timeout: 60000 });
    }

    llmConfig() {
        return this.get("/llm/config");
    }

    saveLlmConfig(config) {
        return this.post("/llm/config", config);
    }

    testLlm() {
        return this.post("/llm/test", {}, { timeout: 30000 });
    }

    xdrConfig() {
        return this.get("/integrations/xdr/config");
    }

    saveXdrConfig(config) {
        return this.post("/integrations/xdr/config", config);
    }

    testXdr(config) {
        // 连通性测试失败不重试（Wazuh 没开就是没开，重试只是浪费时间）
        return this.post("/integrations/xdr/test", config, { timeout: 15000, retries: 0 });
    }

    xdrAlerts(params = {}, options = {}) {
        const { limit = 20, severity = "", time_range = "" } = params;
        const qs = new URLSearchParams();
        qs.set("limit", String(limit));
        if (severity) qs.set("severity", severity);
        if (time_range) qs.set("time_range", time_range);
        return this.get(`/integrations/xdr/alerts?${qs.toString()}`, options);
    }

    xdrAlertDetail(alertId) {
        return this.get(`/integrations/xdr/alerts/${encodeURIComponent(alertId)}`);
    }

    /** 批量分析告警（不传 alerts 则后端自动从 Indexer 拉取 medium+ Top N） */
    xdrAnalyze(payload = {}, options = {}) {
        return this.post("/integrations/xdr/analyze", payload, { timeout: 60000, ...options });
    }

    /** 获取最近的分析结果列表 */
    xdrAnalyses(params = {}, options = {}) {
        const { limit = 50, threat_level = "" } = params;
        const qs = new URLSearchParams();
        qs.set("limit", String(limit));
        if (threat_level) qs.set("threat_level", threat_level);
        return this.get(`/integrations/xdr/analyses?${qs.toString()}`, options);
    }

    /** 对指定告警执行处置（走 HITL 人审 → Wazuh block_ip/isolate） */
    xdrRespond(payload) {
        return this.post("/integrations/xdr/respond", payload, { timeout: 120000 });
    }

    /** 获取统一告警+研判 FIFO 队列（最多 100 条，队首最新） */
    xdrAlertsUnified(params = {}, options = {}) {
        const { limit = 100 } = params;
        const qs = new URLSearchParams();
        qs.set("limit", String(limit));
        return this.get(`/integrations/xdr/alerts/unified?${qs.toString()}`, options);
    }

    /** 停止 XDR 监测 */
    xdrStop() {
        return this.post("/integrations/xdr/stop", {});
    }

    /** 启动/恢复 XDR 监测 */
    xdrStart() {
        return this.post("/integrations/xdr/start", {});
    }

    approvals() {
        return this.get("/gateway/hitl/approvals");
    }

    approval(taskId) {
        return this.get(`/gateway/hitl/approval/${encodeURIComponent(taskId)}`);
    }

    async approvalToken(taskId) {
        try {
            const result = await this.approval(taskId);
            if (result?.approval_token) {
                return { approval_token: result.approval_token, ...result };
            }
            return { approval_token: taskId, id: taskId };
        } catch {
            try {
                const result = await this.get("/gateway/hitl/approvals");
                const approvals = result?.approvals || [];
                const task = approvals.find(a => a.id === taskId || a.task_id === taskId);
                if (task?.approval_token) {
                    return { approval_token: task.approval_token, ...task };
                }
                return { approval_token: taskId, id: taskId };
            } catch {
                return { approval_token: taskId, id: taskId };
            }
        }
    }

    approve(taskId, approvalToken, operator = "local_dashboard", reason = "") {
        return this.post(`/gateway/hitl/approve/${encodeURIComponent(taskId)}`, {
            approval_token: approvalToken,
            operator,
            reason,
        });
    }

    reject(taskId, approvalToken, operator = "local_dashboard", reason = "") {
        return this.post(`/gateway/hitl/reject/${encodeURIComponent(taskId)}`, {
            approval_token: approvalToken,
            operator,
            reason,
        });
    }

    auditSessions() {
        return this.get("/audit/eat/chain");
    }

    auditChain(sessionId) {
        return this.get(`/audit/eat/chain/${encodeURIComponent(sessionId)}`);
    }

    verifyAudit(sessionId = "") {
        const suffix = sessionId ? `/${encodeURIComponent(sessionId)}` : "";
        return this.get(`/audit/eat/verify${suffix}`);
    }

    queryRag(query) {
        return this.post("/rag/query", {
            query,
            enforce_citations: true,
            top_k: 6,
        }, { timeout: 20000 });
    }
}

export const api = new ApiClient();
