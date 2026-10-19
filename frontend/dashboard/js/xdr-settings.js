/**
 * XDR 平台配置页逻辑（升级后）。
 *
 * 支持 7 个厂商（Wazuh 默认）：
 *  - Wazuh：深度集成（专用字段）
 *  - Splunk / Elastic / Sentinel / QRadar / 阿里云 / 华为云：通用 REST 客户端 + 预设模板
 *
 * 功能：
 *  - 卡片式平台选择 + 连接方式可视化徽章
 *  - 通用 REST 厂商选择时自动填充预设模板（端点/认证方式/JSON 路径）
 *  - 凭据保留掩码（********），修改后自动继承旧值
 *  - 顶部"服务状态"卡片同步
 *  - 配置持久化（后端 xdr_config.json）
 */

import { api } from "./api-client.js";

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

const PROVIDER_LABELS = {
    wazuh: "Wazuh",
    splunk: "Splunk ES",
    elastic: "Elastic Security",
    sentinel: "Microsoft Sentinel",
    qradar: "IBM QRadar",
    aliyun_sas: "阿里云安全中心",
    huawei_secmaster: "华为云 SecMaster",
};

const PROVIDER_METHOD_CHIPS = {
    wazuh: [
        { icon: "🎟️", text: "连接方式：JWT + Manager REST API", alt: false },
        { icon: "📊", text: "告警读取：Indexer (OpenSearch) 9200", alt: true },
    ],
    splunk: [
        { icon: "🎫", text: "连接方式：Bearer Token", alt: false },
        { icon: "🔍", text: "告警读取：搜索作业导出 API", alt: true },
    ],
    elastic: [
        { icon: "🔑", text: "连接方式：API Key Header", alt: false },
        { icon: "📡", text: "告警读取：检测引擎 _search API", alt: true },
    ],
    sentinel: [
        { icon: "🎟️", text: "连接方式：Azure AD OAuth2", alt: false },
        { icon: "☁️", text: "告警读取：Microsoft Graph API", alt: true },
    ],
    qradar: [
        { icon: "🔑", text: "连接方式：SEC Token Header", alt: false },
        { icon: "🚨", text: "告警读取：SIEM Offenses API", alt: true },
    ],
    aliyun_sas: [
        { icon: "🔏", text: "连接方式：AccessKey AK/SK HMAC-SHA1 签名", alt: false },
        { icon: "☁️", text: "告警读取：OpenAPI DescribeWarning", alt: true },
    ],
    huawei_secmaster: [
        { icon: "🔏", text: "连接方式：AK/SK HMAC-SHA256 签名", alt: false },
        { icon: "☁️", text: "告警读取：SecMaster 事件 API", alt: true },
    ],
};

// 通用 REST 厂商预设模板（与后端 generic_rest_client.VENDOR_PRESETS 一致）
// 选择平台时自动填充端点/认证方式/JSON 路径（仅当字段为空时才填，避免覆盖用户已填的）
const VENDOR_PRESETS = {
    splunk: { auth_type: "bearer_token", auth_header_name: "Authorization", alerts_endpoint: "/services/search/jobs/export", alerts_json_path: "results" },
    elastic: { auth_type: "api_key_header", auth_header_name: "Authorization", alerts_endpoint: "/api/detection_engine/search", alerts_json_path: "data.hits.hits" },
    sentinel: { auth_type: "bearer_token", auth_header_name: "Authorization", alerts_endpoint: "/api/alerts", alerts_json_path: "value" },
    qradar: { auth_type: "api_key_header", auth_header_name: "SEC", alerts_endpoint: "/api/siem/offenses", alerts_json_path: "" },
    aliyun_sas: { auth_type: "aliyun_sig", auth_header_name: "Authorization", alerts_endpoint: "/", alerts_json_path: "Alerts" },
    huawei_secmaster: { auth_type: "huawei_sig", auth_header_name: "Authorization", alerts_endpoint: "/v1/{project_id}/events", alerts_json_path: "events" },
};

// 所有通用 REST 厂商（共享字段组）
const GENERIC_REST_PROVIDERS = ["splunk", "elastic", "sentinel", "qradar", "aliyun_sas", "huawei_secmaster"];

export function initXdrSettings({ showToast, announce }) {
    const form = document.querySelector("#xdr-form");
    const formGrid = document.querySelector(".xdr-form-grid");
    const providerCards = document.querySelectorAll(".xdr-provider-card");
    const cardRadios = document.querySelectorAll('input[name="xdr-provider-card"]');
    const provider = document.querySelector("#xdr-provider"); // hidden select
    const baseUrl = document.querySelector("#xdr-base-url");
    const username = document.querySelector("#xdr-username");
    const password = document.querySelector("#xdr-password");
    const indexerUrl = document.querySelector("#xdr-indexer-url");
    const indexerUser = document.querySelector("#xdr-indexer-user");
    const indexerPassword = document.querySelector("#xdr-indexer-password");
    const timeoutInput = document.querySelector("#xdr-timeout");
    const verifySsl = document.querySelector("#xdr-verify-ssl");
    const save = document.querySelector("#xdr-save");
    const test = document.querySelector("#xdr-test");
    const state = document.querySelector("#xdr-state");
    const note = document.querySelector("#xdr-config-note");
    const subtitle = document.querySelector("#xdr-subtitle");
    const connHint = document.querySelector("#xdr-connection-hint");

    // 通用 REST 厂商字段
    const authType = document.querySelector("#xdr-auth-type");
    const authHeaderName = document.querySelector("#xdr-auth-header-name");
    const genericApiKey = document.querySelector("#xdr-generic-api-key");
    const genericUsername = document.querySelector("#xdr-generic-username");
    const genericPassword = document.querySelector("#xdr-generic-password");
    const alertsEndpoint = document.querySelector("#xdr-alerts-endpoint");
    const alertsJsonPath = document.querySelector("#xdr-alerts-json-path");
    const tenantId = document.querySelector("#xdr-tenant-id");
    const regionInput = document.querySelector("#xdr-region");

    // 顶部服务状态卡片联动
    const serviceRow = document.querySelector("#xdr-service-row");
    const serviceState = document.querySelector("#xdr-service-state");
    const serviceTitle = document.querySelector("#xdr-service-title");
    const serviceDesc = document.querySelector("#xdr-service-desc");
    const demoModeXdrRadio = document.querySelector('input[name="demo-mode"][value="xdr"]');

    const MASK = "********";

    /** 渲染连接方式徽章 */
    function renderConnectionChips(providerName) {
        const chips = PROVIDER_METHOD_CHIPS[providerName] || [];
        connHint.innerHTML = chips
            .map(
                (c) =>
                    `<span class="xdr-method-chip${c.alt ? " xdr-method-chip--passive" : ""}">${
                        c.icon
                    } ${c.text}</span>`,
            )
            .join("");
    }

    /** 切换 provider 可见性 + 卡片激活态 + 徽章 + 通用 REST 预设自动填充 */
    function setProvider(name, { autoFillPreset = true } = {}) {
        provider.value = name;
        formGrid.dataset.provider = name;
        providerCards.forEach((card) => {
            card.classList.toggle("is-active", card.dataset.provider === name);
            const radio = card.querySelector('input[type="radio"]');
            if (radio) radio.checked = card.dataset.provider === name;
        });
        renderConnectionChips(name);

        // 通用 REST 厂商：自动填充预设模板（仅当字段为空时才填，避免覆盖用户已填的）
        if (autoFillPreset && GENERIC_REST_PROVIDERS.includes(name)) {
            const preset = VENDOR_PRESETS[name];
            if (preset) {
                if (authType && !authType.value) authType.value = preset.auth_type;
                if (authHeaderName && !authHeaderName.value) authHeaderName.value = preset.auth_header_name;
                if (alertsEndpoint && !alertsEndpoint.value) alertsEndpoint.value = preset.alerts_endpoint;
                if (alertsJsonPath && alertsJsonPath.value === "") alertsJsonPath.value = preset.alerts_json_path;
            }
        }
        // 同步 auth_type 到 formGrid.dataset，触发 CSS 子字段显示
        if (authType) {
            formGrid.dataset.authType = authType.value;
        }
    }

    /** auth_type 下拉变化时同步 dataset，触发 CSS 显示对应子字段 */
    if (authType) {
        authType.addEventListener("change", () => {
            formGrid.dataset.authType = authType.value;
        });
    }

    /** 将配置状态同步到顶部"安全平台"服务卡 */
    function syncServiceStatus(cfg, savedOk = false, testOk = false) {
        if (!cfg || !cfg.provider) {
            serviceTitle.textContent = "XDR 平台";
            serviceDesc.textContent = "尚未配置。可选择 Wazuh 或通用 REST 厂商对接真实告警数据。";
            setState(serviceState, "state-pending", "未配置");
            if (demoModeXdrRadio) demoModeXdrRadio.disabled = true;
            return;
        }
        const label = PROVIDER_LABELS[cfg.provider] || cfg.provider;
        serviceTitle.textContent = `${label} 已接入`;
        let statusText = "已配置";
        let statusCls = "state-ready";
        if (testOk) {
            statusText = "已连接";
            statusCls = "state-completed";
            if (demoModeXdrRadio) {
                demoModeXdrRadio.disabled = false;
                const nextLabel = demoModeXdrRadio.nextElementSibling?.querySelector("small");
                if (nextLabel) {
                    nextLabel.textContent = `已连接 ${label}，可用于真实告警研判演示`;
                }
            }
        } else if (savedOk) {
            statusText = "已保存";
            statusCls = "state-ready";
        } else {
            statusText = "已读取";
            statusCls = "state-ready";
        }
        setState(serviceState, statusCls, statusText);

        const extra = [];
        if (cfg.base_url) extra.push(`地址：${cfg.base_url}`);
        if (cfg.provider_hint) extra.push(cfg.provider_hint);
        if (cfg.username) extra.push(`用户：${cfg.username}`);
        const detail = extra.length ? extra.join(" · ") : "凭据已保存至后端持久化文件";
        serviceDesc.textContent = `${label} · ${detail}`;
        subtitle.textContent = `当前接入平台：${label}。修改下方字段并点击"保存配置"即可更新，下次启动自动读取。`;
    }

    /** 读取并填充表单 */
    async function loadConfig() {
        setState(state, "state-checking", "正在读取");
        try {
            const data = (await api.xdrConfig()) || {};
            const p = data.provider || "wazuh";
            setProvider(p);

            baseUrl.value = data.base_url || "";
            timeoutInput.value = data.timeout || 30;
            verifySsl.checked = data.verify_ssl !== false;

            if (p === "wazuh") {
                username.value = data.username || "";
                password.value = data.password_set ? MASK : "";
                indexerUrl.value = data.indexer_url || "";
                indexerUser.value = data.indexer_user || "";
                indexerPassword.value = data.indexer_password_set
                    ? data.indexer_password_mask || MASK
                    : "";
                // 兼容：api_key 掩码
                if (data.api_key_set && !data.indexer_password_set) {
                    indexerPassword.value = data.api_key_mask || MASK;
                }
            } else if (GENERIC_REST_PROVIDERS.includes(p)) {
                // 通用 REST 厂商：回填通用字段
                // 先用预设模板兜底，再用后端返回值覆盖
                const preset = VENDOR_PRESETS[p] || {};
                if (authType) authType.value = data.auth_type || preset.auth_type || "";
                if (authHeaderName) authHeaderName.value = data.auth_header_name || preset.auth_header_name || "";
                if (alertsEndpoint) alertsEndpoint.value = data.alerts_endpoint || preset.alerts_endpoint || "";
                if (alertsJsonPath) alertsJsonPath.value = data.alerts_json_path ?? preset.alerts_json_path ?? "";
                if (tenantId) tenantId.value = data.tenant_id || "";
                if (regionInput) regionInput.value = data.region || "";
                // 凭据掩码
                if (genericApiKey) {
                    genericApiKey.value = data.api_key_set ? (data.api_key_mask || MASK) : "";
                }
                if (genericUsername) {
                    genericUsername.value = data.username || "";
                }
                if (genericPassword) {
                    genericPassword.value = data.password_set ? MASK : "";
                }
                // 同步 auth_type dataset 触发 CSS 子字段显示
                formGrid.dataset.authType = authType ? authType.value : "";
            }

            const isConfigured =
                data.api_key_set || data.username_set || data.indexer_password_set;
            if (isConfigured) {
                const label = PROVIDER_LABELS[p] || p;
                const hint = data.provider_hint || `${label} 配置已保存`;
                note.textContent = `${hint}；如需更新，请修改对应字段（密码留空或为 "${MASK}" 时保留原内容）。`;
                setState(state, "state-ready", "已配置");
                syncServiceStatus(data, false, false);
                // 配置齐全 → 直接解锁「真实 XDR」单选框（无需先点测试连接）
                if (data.can_enable_xdr && demoModeXdrRadio) {
                    demoModeXdrRadio.disabled = false;
                    const labelEl = demoModeXdrRadio.nextElementSibling;
                    const smallEl = labelEl ? labelEl.querySelector("small") : null;
                    if (smallEl) {
                        smallEl.textContent = `已配置 ${label}，可直接进入真实告警模式（自动轮询 Indexer 的最新 ${label} 告警）`;
                    }
                }
            } else {
                note.textContent = 'XDR 尚未配置，请填写上方平台连接信息后点击「保存配置」。';
                setState(state, "state-pending", "未配置");
                syncServiceStatus(null);
                if (demoModeXdrRadio) demoModeXdrRadio.disabled = true;
            }
        } catch (error) {
            note.textContent = error.message || "读取配置失败";
            setState(state, "state-failed", "读取失败");
            syncServiceStatus(null);
        }
    }

    /** 卡片点击 / radio 切换 */
    function bindCards() {
        providerCards.forEach((card) => {
            card.addEventListener("click", (e) => {
                // 避免点击 radio 触发两次
                if (e.target.tagName !== "INPUT") {
                    const radio = card.querySelector('input[type="radio"]');
                    if (radio) radio.checked = true;
                }
                const p = card.dataset.provider;
                if (p) setProvider(p);
            });
        });
        cardRadios.forEach((radio) => {
            radio.addEventListener("change", (e) => {
                if (e.target.checked) {
                    setProvider(e.target.value);
                }
            });
        });
    }

    /** 构造 payload */
    function buildPayload() {
        const payload = {
            provider: provider.value,
            base_url: baseUrl.value.trim(),
            timeout: parseInt(timeoutInput.value, 10) || 30,
            verify_ssl: !!verifySsl.checked,
        };
        if (provider.value === "wazuh") {
            if (username.value && username.value !== MASK) {
                payload.username = username.value.trim();
            }
            if (password.value && password.value !== MASK) {
                payload.password = password.value;
            }
            if (indexerUrl.value.trim()) {
                payload.indexer_url = indexerUrl.value.trim();
            }
            if (indexerUser.value.trim()) {
                payload.indexer_user = indexerUser.value.trim();
            }
            if (indexerPassword.value && indexerPassword.value !== MASK) {
                payload.indexer_password = indexerPassword.value;
            }
        } else if (GENERIC_REST_PROVIDERS.includes(provider.value)) {
            // 通用 REST 厂商：构造通用字段 payload
            payload.auth_type = authType ? authType.value : "";
            payload.auth_header_name = authHeaderName ? authHeaderName.value.trim() : "";
            payload.alerts_endpoint = alertsEndpoint ? alertsEndpoint.value.trim() : "";
            payload.alerts_json_path = alertsJsonPath ? alertsJsonPath.value : "";
            payload.tenant_id = tenantId ? tenantId.value.trim() : "";
            payload.token_url = "";  // 预留
            payload.region = regionInput ? regionInput.value.trim() : "";
            // 凭据：根据 auth_type 决定传 api_key 还是 username/password
            if (payload.auth_type === "basic_auth") {
                if (genericUsername.value && genericUsername.value !== MASK) {
                    payload.username = genericUsername.value.trim();
                }
                if (genericPassword.value && genericPassword.value !== MASK) {
                    payload.password = genericPassword.value;
                }
            } else {
                // bearer_token / api_key_header / aliyun_sig / huawei_sig
                // 阿里云/华为云的 AccessKey Secret 也走 password 字段（后端会处理）
                if (genericApiKey.value && genericApiKey.value !== MASK) {
                    payload.api_key = genericApiKey.value.trim();
                }
                // 阿里云/华为云的 Secret 字段（如果用户填了 genericPassword）
                if ((payload.auth_type === "aliyun_sig" || payload.auth_type === "huawei_sig")
                    && genericPassword.value && genericPassword.value !== MASK) {
                    payload.password = genericPassword.value;
                }
            }
        }
        return payload;
    }

    /** 保存 */
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        save.disabled = true;
        save.textContent = "保存中";
        setState(state, "state-running", "正在保存");

        const payload = buildPayload();
        try {
            const result = await api.saveXdrConfig(payload);
            note.textContent = result?.message || "XDR 配置已保存";
            setState(state, "state-completed", "保存成功");
            announce("XDR 配置已保存");
            showToast("XDR 平台配置已保存，下次启动自动加载。", "success");
            // 保存成功后重新从服务端读取，确保掩码 / 同步状态正确
            await loadConfig();
            // 将服务状态卡在 "已保存" 高亮
            const currentCfg = {
                provider: payload.provider,
                base_url: payload.base_url,
                username: payload.username,
                provider_hint: "已保存到本地持久化",
            };
            syncServiceStatus(currentCfg, true, false);
        } catch (error) {
            setState(state, "state-failed", "保存失败");
            note.textContent = error.message || "保存失败";
            showToast(note.textContent, "error");
        } finally {
            save.disabled = false;
            save.textContent = "保存配置";
        }
    });

    /** 测试连接 */
    test.addEventListener("click", async () => {
        test.disabled = true;
        test.textContent = "测试中";
        setState(state, "state-running", "正在测试");

        const payload = buildPayload();
        try {
            const result = await api.testXdr(payload);
            const latency = result.latency_ms ? `（${result.latency_ms}ms）` : "";
            note.textContent = `${result.message}${latency}`;
            setState(state, "state-completed", "连接成功");
            announce("XDR 连接测试成功");
            showToast("XDR 平台连接测试成功，可以切换到实时真实告警模式。");
            syncServiceStatus(
                {
                    provider: payload.provider,
                    base_url: payload.base_url,
                    username: payload.username,
                },
                true,
                true,
            );
        } catch (error) {
            const response = error.payload || {};
            note.textContent = response.message || error.message || "连接失败";
            setState(state, "state-failed", "连接失败");
            showToast(note.textContent, "error");
            syncServiceStatus(
                {
                    provider: payload.provider,
                    base_url: payload.base_url,
                },
                false,
                false,
            );
        } finally {
            test.disabled = false;
            test.textContent = "测试连接";
        }
    });

    bindCards();
    setProvider(provider.value || "wazuh");
    loadConfig();
}
