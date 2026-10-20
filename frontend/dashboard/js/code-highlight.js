// 轻量语法高亮：不依赖任何第三方库，只做词法着色（关键字 / 字符串 / 注释 / 数字）。
//
// 为什么不用 highlight.js / Prism：
//   项目是原生 HTML + ES module、没有任何 npm 依赖，也没有仓颉的语言定义。
//   为了一个输入框引入 vendor 包不划算，而且仓颉仍然要自己写。
//
// 渲染方式：返回 DocumentFragment，全部用 textContent 写入。
//   绝不用 innerHTML —— 用户粘贴的代码可以是任意内容（含 <script>）。

// 关键字表。仓颉按官方语法整理，其余语言只取常用子集，
// 目的是让代码看起来有结构，不追求编译器级准确。
const KEYWORDS = {
    cangjie: [
        "public", "private", "protected", "internal", "static", "open",
        "override", "abstract", "sealed", "mut", "unsafe", "foreign",
        "macro", "operator", "func", "class", "struct", "enum", "interface",
        "extend", "type", "var", "let", "const", "package", "import", "as",
        "init", "main", "if", "else", "while", "for", "in", "do", "match",
        "case", "return", "break", "continue", "throw", "try", "catch",
        "finally", "spawn", "synchronized", "where", "is", "async", "await",
        "true", "false", "this", "super", "not", "and", "or", "quote",
    ],
    c: [
        "auto", "break", "case", "char", "const", "continue", "default", "do",
        "double", "else", "enum", "extern", "float", "for", "goto", "if",
        "inline", "int", "long", "register", "restrict", "return", "short",
        "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while", "NULL", "true", "false",
    ],
    cpp: [
        "auto", "bool", "break", "case", "catch", "char", "class", "const",
        "constexpr", "continue", "default", "delete", "do", "double", "else",
        "enum", "explicit", "extern", "false", "float", "for", "friend",
        "if", "inline", "int", "long", "namespace", "new", "noexcept",
        "nullptr", "operator", "private", "protected", "public", "return",
        "short", "signed", "sizeof", "static", "struct", "switch", "template",
        "throw", "true", "try", "typename", "union", "unsigned", "using",
        "virtual", "void", "volatile", "while",
    ],
    java: [
        "abstract", "boolean", "break", "byte", "case", "catch", "char",
        "class", "const", "continue", "default", "do", "double", "else",
        "enum", "extends", "final", "finally", "float", "for", "if",
        "implements", "import", "instanceof", "int", "interface", "long",
        "native", "new", "package", "private", "protected", "public",
        "return", "short", "static", "super", "switch", "synchronized",
        "this", "throw", "throws", "try", "void", "volatile", "while",
        "true", "false", "null",
    ],
    python: [
        "and", "as", "assert", "async", "await", "break", "class", "continue",
        "def", "del", "elif", "else", "except", "finally", "for", "from",
        "global", "if", "import", "in", "is", "lambda", "nonlocal", "not",
        "or", "pass", "raise", "return", "try", "while", "with", "yield",
        "True", "False", "None", "self",
    ],
    javascript: [
        "async", "await", "break", "case", "catch", "class", "const",
        "continue", "default", "delete", "do", "else", "export", "extends",
        "finally", "for", "function", "if", "import", "in", "instanceof",
        "let", "new", "of", "return", "static", "super", "switch", "this",
        "throw", "try", "typeof", "var", "void", "while", "yield", "true",
        "false", "null", "undefined",
    ],
    go: [
        "break", "case", "chan", "const", "continue", "default", "defer",
        "else", "fallthrough", "for", "func", "go", "goto", "if", "import",
        "interface", "map", "package", "range", "return", "select", "struct",
        "switch", "type", "var", "true", "false", "nil",
    ],
    rust: [
        "as", "async", "await", "break", "const", "continue", "crate", "dyn",
        "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
        "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
        "self", "static", "struct", "super", "trait", "true", "type",
        "unsafe", "use", "where", "while",
    ],
};

// 语言标识归一化：前端只关心"用哪张关键字表"和"注释风格"
const LANG_ALIAS = {
    cj: "cangjie", cangjie: "cangjie",
    c: "c", h: "c",
    cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp",
    java: "java",
    py: "python", python: "python",
    js: "javascript", javascript: "javascript", mjs: "javascript",
    ts: "javascript", typescript: "javascript", tsx: "javascript",
    go: "go",
    rs: "rust", rust: "rust",
};

const EXT_LANG = {
    ".cj": "cangjie", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".cxx": "cpp", ".hpp": "cpp", ".java": "java", ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".go": "go", ".rs": "rust",
    ".php": "javascript", ".cs": "java", ".rb": "python", ".json": "javascript",
    ".yaml": "python", ".yml": "python", ".txt": null,
};

// 超过这个长度就不着色了，否则逐 token 生成 DOM 会明显卡顿
const MAX_HIGHLIGHT_CHARS = 120000;

export function langFromFilename(filename) {
    const name = String(filename || "").toLowerCase();
    const dot = name.lastIndexOf(".");
    if (dot < 0) return "cangjie";
    return EXT_LANG[name.slice(dot)] ?? "cangjie";
}

export function normalizeLang(lang) {
    return LANG_ALIAS[String(lang || "").toLowerCase()] || "cangjie";
}

// 一次性扫描出所有 token。用捕获组区分类型，未匹配部分是普通文本。
function buildRegex(lang) {
    const hashComments = lang === "python";
    const parts = [
        // 1 注释
        hashComments
            ? "(#[^\\n]*)"
            : "(//[^\\n]*|/\\*[\\s\\S]*?\\*/)",
        // 2 字符串（单/双引号，允许转义）
        "(\"(?:\\\\.|[^\"\\\\\\n])*\"|'(?:\\\\.|[^'\\\\\\n])*')",
        // 3 数字（十六/八/二进制 + 浮点）
        "(\\b0[xX][0-9a-fA-F_]+\\b|\\b0[oO][0-7_]+\\b|\\b0[bB][01_]+\\b"
        + "|\\b\\d[\\d_]*(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b)",
        // 4 标识符
        "([A-Za-z_][A-Za-z0-9_]*)",
    ];
    return new RegExp(parts.join("|"), "g");
}

const REGEX_CACHE = new Map();

function regexFor(lang) {
    if (!REGEX_CACHE.has(lang)) REGEX_CACHE.set(lang, buildRegex(lang));
    return REGEX_CACHE.get(lang);
}

/**
 * 把源码渲染成带高亮的 DocumentFragment。
 * @param {string} code 源码
 * @param {string} lang 语言标识（cangjie / c / cpp / java / python / ...）
 * @returns {DocumentFragment}
 */
export function highlightFragment(code, lang) {
    const fragment = document.createDocumentFragment();
    const text = String(code ?? "");
    const key = normalizeLang(lang);
    const keywords = new Set(KEYWORDS[key] || KEYWORDS.cangjie);

    // 代码过长时退化成纯文本，避免一次性生成上万个节点
    if (text.length > MAX_HIGHLIGHT_CHARS) {
        fragment.append(document.createTextNode(text));
        return fragment;
    }

    const regex = regexFor(key);
    regex.lastIndex = 0;
    let cursor = 0;
    let match;

    while ((match = regex.exec(text)) !== null) {
        if (match.index > cursor) {
            fragment.append(document.createTextNode(text.slice(cursor, match.index)));
        }
        const [raw, comment, string, number, ident] = match;
        let type = null;

        if (comment) type = "comment";
        else if (string) type = "string";
        else if (number) type = "number";
        else if (ident) {
            if (keywords.has(ident)) type = "keyword";
            // 紧跟在标识符后面的 ( 视为函数调用
            else if (text[match.index + raw.length] === "(") type = "function";
            // 首字母大写视为类型名（仓颉 / Rust / Go 都常见）
            else if (/^[A-Z]/.test(ident)) type = "type";
        }

        if (type) {
            const span = document.createElement("span");
            span.className = `tok-${type}`;
            span.textContent = raw;
            fragment.append(span);
        } else {
            fragment.append(document.createTextNode(raw));
        }
        cursor = match.index + raw.length;

        // 空匹配保护，避免死循环
        if (raw.length === 0) regex.lastIndex += 1;
    }

    if (cursor < text.length) {
        fragment.append(document.createTextNode(text.slice(cursor)));
    }
    return fragment;
}
