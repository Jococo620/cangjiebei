// 依赖图查看器：用 <img> 加载后端 graphviz 渲染好的 SVG，容器负责平移/缩放。
//
// 为什么用 <img> 而不是 fetch + innerHTML 内联 SVG：
//   1. SVG 由第三方 MCP 服务生成，内联进 DOM 等于把外来 XML 塞进同源文档，
//      里面若带 <script>/onload 就能直接执行；<img> 是隔离的文档上下文，脚本不执行。
//   2. 后端已经渲染好矢量图，前端不需要图布局算法。
// 代价：<img> 内部无法被 CSS 选中，也拿不到节点做点击交互——本项目只需要看图与缩放。

const PADDING = 24;
const MIN_SCALE_RATIO = 0.3;
const MAX_SCALE_RATIO = 10;
const MAX_FIT_SCALE = 1.2;

function clamp(value, low, high) {
    return Math.min(high, Math.max(low, value));
}

function graphTitle(graph) {
    const type = graph?.graph_type || "未命名";
    if (graph?.node_count == null && graph?.edge_count == null) return String(type);
    return `${type}：${graph.node_count ?? "?"} 节点 / ${graph.edge_count ?? "?"} 边`;
}

/**
 * 创建依赖图查看器。
 *
 * @param {Object} options
 * @param {Array} options.graphs  后端 graph.graphs，每项含 graph_type / svg_url
 * @param {string} [options.activeType]  初始显示哪张图，默认第一张
 * @param {string} [options.height]      视口高度，形如 "420px"
 * @returns {{ element: HTMLElement, select: Function, destroy: Function }}
 */
export function createGraphViewer({ graphs = [], activeType, height } = {}) {
    const usable = (Array.isArray(graphs) ? graphs : []).filter(
        (item) => item && item.svg_url,
    );

    const root = document.createElement("div");
    root.className = "graph-viewer";

    const toolbar = document.createElement("div");
    toolbar.className = "graph-toolbar";

    const typeGroup = document.createElement("div");
    typeGroup.className = "graph-types";
    typeGroup.setAttribute("role", "group");
    typeGroup.setAttribute("aria-label", "切换图类型");

    const actions = document.createElement("div");
    actions.className = "graph-actions";

    const viewport = document.createElement("div");
    viewport.className = "graph-viewport";
    viewport.tabIndex = 0;
    viewport.setAttribute("role", "application");
    viewport.setAttribute(
        "aria-label",
        "依赖图。拖动平移，滚轮缩放，双击复位，加号减号键缩放，数字 0 键复位。",
    );
    if (height) viewport.style.height = height;

    const canvas = document.createElement("img");
    canvas.className = "graph-canvas";
    canvas.alt = "";
    canvas.draggable = false;
    canvas.decoding = "async";
    canvas.style.visibility = "hidden";

    const status = document.createElement("div");
    status.className = "graph-status is-loading";
    status.textContent = "正在加载图";

    viewport.append(canvas, status);
    toolbar.append(typeGroup, actions);
    root.append(toolbar, viewport);

    let scale = 1;
    let translateX = 0;
    let translateY = 0;
    let fitScale = 1;
    let userAdjusted = false;
    let activeIndex = -1;
    let loaded = false;
    let disposed = false;

    function minScale() {
        return Math.max(0.02, fitScale * MIN_SCALE_RATIO);
    }

    function maxScale() {
        return Math.max(minScale() * 2, fitScale * MAX_SCALE_RATIO);
    }

    function paint() {
        // translate3d 走合成层，拖动时不触发重排
        canvas.style.transform =
            `translate3d(${translateX}px, ${translateY}px, 0) scale(${scale})`;
    }

    function fit() {
        const viewWidth = viewport.clientWidth;
        const viewHeight = viewport.clientHeight;
        const imageWidth = canvas.naturalWidth;
        const imageHeight = canvas.naturalHeight;
        if (!viewWidth || !viewHeight || !imageWidth || !imageHeight) return;

        const usableWidth = Math.max(1, viewWidth - PADDING * 2);
        const usableHeight = Math.max(1, viewHeight - PADDING * 2);
        fitScale = clamp(
            Math.min(usableWidth / imageWidth, usableHeight / imageHeight),
            0.02,
            MAX_FIT_SCALE,
        );
        scale = fitScale;
        translateX = (viewWidth - imageWidth * scale) / 2;
        translateY = (viewHeight - imageHeight * scale) / 2;
        userAdjusted = false;
        paint();
    }

    function zoomAt(clientX, clientY, factor) {
        const rect = viewport.getBoundingClientRect();
        const originX = clientX - rect.left;
        const originY = clientY - rect.top;
        const next = clamp(scale * factor, minScale(), maxScale());
        if (next === scale) return;
        // 以光标为不动点缩放：光标下的那个像素点缩放前后保持贴合
        const ratio = next / scale;
        translateX = originX - (originX - translateX) * ratio;
        translateY = originY - (originY - translateY) * ratio;
        scale = next;
        userAdjusted = true;
        paint();
    }

    function zoomCenter(factor) {
        const rect = viewport.getBoundingClientRect();
        zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, factor);
    }

    function showMessage(text, isError) {
        status.textContent = text;
        status.classList.remove("is-loading");
        status.classList.toggle("is-error", Boolean(isError));
        status.hidden = false;
    }

    function select(index) {
        if (index < 0 || index >= usable.length || index === activeIndex) return;
        activeIndex = index;
        loaded = false;
        canvas.style.visibility = "hidden";
        showMessage("正在加载图");
        canvas.alt = `${usable[index].graph_type || "依赖"} 图`;
        canvas.src = usable[index].svg_url;

        [...typeGroup.children].forEach((button, position) => {
            const isActive = position === index;
            button.classList.toggle("is-active", isActive);
            button.setAttribute("aria-pressed", String(isActive));
        });

        openLink.href = usable[index].svg_url;
    }

    canvas.addEventListener("load", () => {
        if (disposed) return;
        loaded = true;
        canvas.style.visibility = "";
        status.hidden = true;
        fit();
    });

    canvas.addEventListener("error", () => {
        if (disposed) return;
        loaded = false;
        canvas.style.visibility = "hidden";
        showMessage("图加载失败：后端可能未生成该类型的图，或产物链接已过期。", true);
    });

    // ---- 类型切换 ----
    usable.forEach((graph, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "graph-type";
        button.textContent = graph.graph_type || `图 ${index + 1}`;
        button.title = graphTitle(graph);
        button.setAttribute("aria-pressed", "false");
        button.addEventListener("click", () => select(index));
        typeGroup.append(button);
    });

    // ---- 缩放按钮与外部链接 ----
    function addAction(label, title, handler) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "graph-action";
        button.textContent = label;
        button.title = title;
        button.setAttribute("aria-label", title);
        button.addEventListener("click", handler);
        actions.append(button);
    }

    addAction("+", "放大", () => zoomCenter(1.25));
    addAction("−", "缩小", () => zoomCenter(0.8));
    addAction("适应", "适应窗口（双击图也可）", () => {
        if (loaded) fit();
    });

    const openLink = document.createElement("a");
    openLink.className = "graph-action";
    openLink.target = "_blank";
    openLink.rel = "noopener noreferrer";
    openLink.textContent = "新窗口";
    openLink.title = "在新标签页打开当前 SVG";
    actions.append(openLink);

    // ---- 拖拽平移 ----
    let pointerId = null;
    let lastX = 0;
    let lastY = 0;

    viewport.addEventListener("pointerdown", (event) => {
        if (event.button !== 0 || !loaded) return;
        pointerId = event.pointerId;
        lastX = event.clientX;
        lastY = event.clientY;
        viewport.setPointerCapture(pointerId);
        viewport.classList.add("is-panning");
    });

    viewport.addEventListener("pointermove", (event) => {
        if (pointerId === null || event.pointerId !== pointerId) return;
        translateX += event.clientX - lastX;
        translateY += event.clientY - lastY;
        lastX = event.clientX;
        lastY = event.clientY;
        userAdjusted = true;
        paint();
    });

    function endPan(event) {
        if (pointerId === null) return;
        if (event && event.pointerId !== pointerId) return;
        if (viewport.hasPointerCapture(pointerId)) {
            viewport.releasePointerCapture(pointerId);
        }
        pointerId = null;
        viewport.classList.remove("is-panning");
    }

    viewport.addEventListener("pointerup", endPan);
    viewport.addEventListener("pointercancel", endPan);

    // ---- 滚轮缩放：passive: false 才能拦住页面滚动 ----
    viewport.addEventListener("wheel", (event) => {
        if (!loaded) return;
        event.preventDefault();
        // deltaY 在鼠标/触控板上量级差异极大，指数映射压平
        zoomAt(event.clientX, event.clientY, Math.exp(-event.deltaY * 0.0018));
    }, { passive: false });

    viewport.addEventListener("dblclick", () => {
        if (loaded) fit();
    });

    viewport.addEventListener("keydown", (event) => {
        if (!loaded) return;
        if (event.key === "+" || event.key === "=") {
            event.preventDefault();
            zoomCenter(1.25);
        } else if (event.key === "-" || event.key === "_") {
            event.preventDefault();
            zoomCenter(0.8);
        } else if (event.key === "0") {
            event.preventDefault();
            fit();
        }
    });

    // 窗口/侧栏尺寸变化时重算；用户手动调整过视角就不再打断他
    const observer = new ResizeObserver(() => {
        if (!loaded || userAdjusted) return;
        fit();
    });
    observer.observe(viewport);

    if (usable.length) {
        const start = Math.max(
            0,
            usable.findIndex((item) => item.graph_type === activeType),
        );
        select(start);
    } else {
        showMessage("后端未返回可显示的图。", true);
    }

    return {
        element: root,
        select,
        destroy() {
            disposed = true;
            observer.disconnect();
            // 断开 src 引用，避免已移除的节点继续占用后端连接
            canvas.removeAttribute("src");
        },
    };
}
