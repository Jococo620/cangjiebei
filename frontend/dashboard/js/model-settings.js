import { api } from "./api-client.js";

const PROVIDER_DEFAULTS = {
    openai: {
        model: "",
        baseUrl: "",
        generic: true,
    },
    deepseek: {
        model: "deepseek-chat",
        baseUrl: "https://api.deepseek.com",
    },
    tongyi: {
        model: "qwen-turbo",
        baseUrl: "https://dashscope.aliyuncs.com",
    },
    qwen: {
        model: "qwen-max",
        baseUrl: "https://dashscope.aliyuncs.com",
    },
};

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

export function initModelSettings({ showToast, announce }) {
    const form = document.querySelector("#model-form");
    const provider = document.querySelector("#model-provider");
    const model = document.querySelector("#model-name");
    const baseUrl = document.querySelector("#model-base-url");
    const apiKey = document.querySelector("#model-api-key");
    const save = document.querySelector("#model-save");
    const test = document.querySelector("#model-test");
    const state = document.querySelector("#model-state");
    const note = document.querySelector("#model-config-note");

    function ensureProviderOption(value) {
        if (!value || [...provider.options].some((option) => option.value === value)) {
            return;
        }
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        provider.append(option);
    }

    async function loadConfig() {
        setState(state, "state-checking", "正在读取");
        try {
            const data = await api.llmConfig();
            // 仅在用户显式配置过（已持久化或已设置 Key）时回填服务商；
            // 否则显示中性占位，避免默认突出某一厂商。
            const configured = Boolean(data?.persisted || data?.api_key_set);
            ensureProviderOption(data?.provider);
            provider.value = configured ? (data?.provider || "") : "";
            model.value = configured ? (data?.model || "") : "";
            baseUrl.value = configured ? (data?.base_url || "") : "";
            note.textContent = data?.api_key_set
                ? `API Key 已配置。配置${data.persisted ? "已保存到本地" : "仅在当前进程生效"}。`
                : "尚未配置模型。平台兼容 DeepSeek、通义千问、Qwen 及任意 OpenAI 格式模型，选择服务商并填入 API Key 后即可使用。";
            setState(
                state,
                data?.api_key_set ? "state-ready" : "state-pending",
                data?.api_key_set ? "已配置" : "未选择服务商",
            );
        } catch (error) {
            note.textContent = error.message;
            setState(state, "state-failed", "读取失败");
        }
    }

    provider.addEventListener("change", () => {
        const defaults = PROVIDER_DEFAULTS[provider.value];
        if (!defaults) {
            model.value = "";
            baseUrl.value = "";
            return;
        }
        model.value = defaults.model;
        baseUrl.value = defaults.baseUrl;
        if (defaults.generic) {
            note.textContent = "通用接口：请填写目标服务的 Base URL 与模型名，兼容 DeepSeek、Qwen、GLM、Moonshot、Kimi 等任意 OpenAI 格式模型。";
        }
    });

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!provider.value) {
            showToast("请先选择模型服务商", "error");
            provider.focus();
            return;
        }
        if (PROVIDER_DEFAULTS[provider.value]?.generic && !model.value.trim()) {
            showToast("通用接口请填写目标模型名称", "error");
            model.focus();
            return;
        }
        save.disabled = true;
        save.textContent = "保存中";
        setState(state, "state-running", "正在保存");
        try {
            const result = await api.saveLlmConfig({
                provider: provider.value,
                api_key: apiKey.value,
                model: model.value.trim(),
                base_url: baseUrl.value.trim(),
            });
            apiKey.value = "";
            note.textContent = result?.api_key_set
                ? "配置已保存到本地，API Key 不会在页面回显。"
                : "配置已保存，但仍未设置 API Key。";
            setState(
                state,
                result?.api_key_set ? "state-completed" : "state-pending",
                result?.api_key_set ? "保存成功" : "缺少 API Key",
            );
            announce("模型配置已经保存");
            showToast("模型配置已经保存到本地");
        } catch (error) {
            setState(state, "state-failed", "保存失败");
            note.textContent = error.message;
            showToast(error.message, "error");
        } finally {
            save.disabled = false;
            save.textContent = "保存配置";
        }
    });

    test.addEventListener("click", async () => {
        test.disabled = true;
        test.textContent = "测试中";
        setState(state, "state-running", "正在测试");
        try {
            const result = await api.testLlm();
            note.textContent = `${result.provider} / ${result.model}：${result.response || "连接成功"}`;
            setState(state, "state-completed", "连接成功");
            announce("模型连接测试成功");
            showToast("模型连接测试成功");
        } catch (error) {
            note.textContent = error.message;
            setState(state, "state-failed", "连接失败");
            showToast(error.message, "error");
        } finally {
            test.disabled = false;
            test.textContent = "测试连接";
        }
    });

    loadConfig();
}

