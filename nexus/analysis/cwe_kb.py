"""CWE 本地知识库，支持检索和 RAG 注入。"""

import json
import os
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("nexus.analysis.cwe_kb")


class CWEKnowledgeBase:

    def __init__(self, persist_dir: str = ".nexus/cwe_kb"):
        self.persist_dir = persist_dir
        self.entries: Dict[str, Dict] = {}
        self._ensure_dir()
        self._load_or_seed()

    def _ensure_dir(self):
        os.makedirs(self.persist_dir, exist_ok=True)

    def _load_or_seed(self):
        kb_path = os.path.join(self.persist_dir, "cwe_kb.json")
        if os.path.exists(kb_path):
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    self.entries = json.load(f)
                logger.info(f"[CWE-KB] Loaded {len(self.entries)} entries from {kb_path}")
                return
            except Exception:
                pass
        self.entries = self._seed_entries()
        self._save()

    def _save(self):
        kb_path = os.path.join(self.persist_dir, "cwe_kb.json")
        with open(kb_path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)

    def search(self, cwe_id: str) -> Optional[Dict]:
        return self.entries.get(cwe_id.upper())

    def search_by_pattern(self, code_pattern: str) -> List[Dict]:
        results = []
        pattern_lower = code_pattern.lower()
        for cwe_id, entry in self.entries.items():
            desc = entry.get("description", "").lower()
            name = entry.get("name", "").lower()
            if pattern_lower in desc or pattern_lower in name:
                result = entry.copy()
                result["cwe_id"] = cwe_id
                results.append(result)
        return results

    def export_kb(self) -> List[Dict]:
        results = []
        for cwe_id, entry in self.entries.items():
            result = entry.copy()
            result["cwe_id"] = cwe_id
            results.append(result)
        return results

    def get_mitigation(self, cwe_id: str) -> str:
        entry = self.search(cwe_id)
        return entry.get("mitigation", "") if entry else ""

    def export_kb(self) -> List[Dict]:
        return list(self.entries.values())

    def _seed_entries(self) -> Dict[str, Dict]:
        return {
            "CWE-22": {"name": "Path Traversal", "description": "使用外部输入构造路径名时未有效过滤 '../' 等特殊字符", "severity": 7.5, "mitigation": "使用白名单校验、规范化路径、限制访问根目录"},
            "CWE-78": {"name": "OS Command Injection", "description": "未充分过滤外部输入即用于构造系统命令", "severity": 7.8, "mitigation": "避免使用系统命令、使用参数化API、严格输入校验"},
            "CWE-79": {"name": "Cross-site Scripting (XSS)", "description": "未对输出到Web页面的数据进行HTML实体编码", "severity": 6.1, "mitigation": "输出编码、CSP头、输入校验"},
            "CWE-89": {"name": "SQL Injection", "description": "将外部输入拼接进SQL语句而未使用参数化查询", "severity": 8.6, "mitigation": "使用预编译语句/参数化查询、ORM框架、最小权限原则"},
            "CWE-119": {"name": "Buffer Overflow (Generic)", "description": "对内存缓冲区的读写操作未检查边界", "severity": 7.8, "mitigation": "使用安全函数(strncpy/snprintf)、边界检查、ASLR/DEP"},
            "CWE-120": {"name": "Classic Buffer Overflow", "description": "copy操作未校验源数据长度，超出目标缓冲区容量", "severity": 7.8, "mitigation": "校验输入长度、使用安全的字符串函数"},
            "CWE-122": {"name": "Heap-based Buffer Overflow", "description": "堆上分配的缓冲区被溢出写入", "severity": 7.8, "mitigation": "边界检查、使用安全分配函数、开启堆保护"},
            "CWE-125": {"name": "Out-of-bounds Read", "description": "读取操作超出缓冲区边界", "severity": 7.1, "mitigation": "边界检查、使用安全迭代器"},
            "CWE-134": {"name": "Uncontrolled Format String", "description": "将外部输入作为printf类函数的格式化字符串", "severity": 7.8, "mitigation": "使用固定格式字符串：printf(\"%s\", user_input)"},
            "CWE-190": {"name": "Integer Overflow", "description": "整数运算结果超过类型最大值导致回绕", "severity": 7.8, "mitigation": "使用安全整数运算库、校验运算前后值"},
            "CWE-191": {"name": "Integer Underflow", "description": "整数运算结果低于类型最小值导致回绕", "severity": 7.8, "mitigation": "校验运算前后值、使用安全整数类型"},
            "CWE-200": {"name": "Information Exposure", "description": "敏感信息被暴露给未授权访问者", "severity": 5.3, "mitigation": "最小化输出、脱敏处理、访问控制"},
            "CWE-250": {"name": "Execution with Unnecessary Privileges", "description": "程序以高于所需的权限运行", "severity": 7.8, "mitigation": "最小权限原则、权限分离、能力降级"},
            "CWE-269": {"name": "Improper Privilege Management", "description": "未能正确管理或校验权限", "severity": 7.8, "mitigation": "权限检查、最小权限、定期审计"},
            "CWE-287": {"name": "Improper Authentication", "description": "认证机制存在缺陷可被绕过", "severity": 8.1, "mitigation": "多因素认证、强密码策略、会话管理"},
            "CWE-295": {"name": "Improper Certificate Validation", "description": "TLS/SSL证书未正确验证", "severity": 7.4, "mitigation": "证书链校验、固定证书、吊销检查"},
            "CWE-306": {"name": "Missing Authentication", "description": "关键功能缺少认证机制", "severity": 9.8, "mitigation": "对所有敏感操作添加认证检查"},
            "CWE-311": {"name": "Missing Encryption of Sensitive Data", "description": "敏感数据未加密存储或传输", "severity": 7.5, "mitigation": "TLS加密传输、AES加密存储、密钥管理"},
            "CWE-327": {"name": "Use of Broken Cryptographic Algorithm", "description": "使用已被攻破或不安全的加密算法（如MD5/SHA1/DES）", "severity": 7.5, "mitigation": "使用SHA-256+、AES-256、RSA-2048+"},
            "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "description": "Web应用未验证请求是否为用户主动发起", "severity": 8.8, "mitigation": "CSRF Token、SameSite Cookie、Referer校验"},
            "CWE-362": {"name": "Race Condition", "description": "代码在并发执行中存在时序依赖，可导致非预期行为", "severity": 7.0, "mitigation": "互斥锁、原子操作、事务隔离"},
            "CWE-400": {"name": "Uncontrolled Resource Consumption", "description": "未限制资源的分配或消耗量，导致DoS", "severity": 7.5, "mitigation": "速率限制、超时机制、资源配额"},
            "CWE-415": {"name": "Double Free", "description": "对同一块内存调用2次free()", "severity": 7.8, "mitigation": "释放后置NULL、使用智能指针"},
            "CWE-416": {"name": "Use After Free", "description": "内存在被释放后仍被引用/使用", "severity": 7.8, "mitigation": "释放后置NULL、使用智能指针、静态分析"},
            "CWE-434": {"name": "Unrestricted File Upload", "description": "未限制上传文件类型，导致恶意文件上传", "severity": 8.8, "mitigation": "文件类型白名单、服务端校验、病毒扫描"},
            "CWE-476": {"name": "NULL Pointer Dereference", "description": "解引用空指针导致程序崩溃", "severity": 5.9, "mitigation": "空指针检查、可选类型、防御性编程"},
            "CWE-502": {"name": "Deserialization of Untrusted Data", "description": "未校验即反序列化外部数据", "severity": 8.1, "mitigation": "白名单类型检查、数据签名校验、避免反序列化不可信数据"},
            "CWE-522": {"name": "Insufficiently Protected Credentials", "description": "凭证未充分保护（明文存储/传输）", "severity": 7.8, "mitigation": "哈希加盐存储、安全传输、密钥管理服务"},
            "CWE-601": {"name": "URL Redirection to Untrusted Site", "description": "未校验重定向目标URL", "severity": 6.1, "mitigation": "重定向URL白名单、相对路径重定向、用户确认"},
            "CWE-611": {"name": "XML External Entity (XXE)", "description": "XML解析器处理外部实体引用", "severity": 7.5, "mitigation": "禁用DTD/外部实体、使用安全的XML解析器配置"},
            "CWE-668": {"name": "Exposure of Resource to Wrong Sphere", "description": "资源暴露给了不正确的控制范围", "severity": 5.3, "mitigation": "最小权限、访问控制、资源隔离"},
            "CWE-732": {"name": "Incorrect Permission Assignment", "description": "文件/资源的权限设置不当", "severity": 7.8, "mitigation": "最小权限原则、默认拒绝、定期审计"},
            "CWE-754": {"name": "Improper Check for Unusual Conditions", "description": "未对异常或例外情况进行适当检查", "severity": 7.5, "mitigation": "防御性编程、完善的错误处理、输入边界校验"},
            "CWE-770": {"name": "Allocation Without Limits or Throttling", "description": "无限制的内存/资源分配", "severity": 7.5, "mitigation": "分配上限、超时释放、资源池化"},
            "CWE-772": {"name": "Missing Release of Resource", "description": "资源使用后未释放导致泄漏", "severity": 5.3, "mitigation": "RAII模式、finally块、资源使用监控"},
            "CWE-787": {"name": "Out-of-bounds Write", "description": "写入操作超出缓冲区边界", "severity": 8.6, "mitigation": "边界检查、使用安全API、静态分析"},
            "CWE-798": {"name": "Hard-coded Credentials", "description": "代码中包含硬编码的密码/密钥", "severity": 9.8, "mitigation": "环境变量/配置文件/密钥管理服务、代码扫描"},
            "CWE-835": {"name": "Infinite Loop", "description": "循环条件永远为真导致无法退出", "severity": 7.5, "mitigation": "循环退出条件、超时机制、看门狗"},
            "CWE-862": {"name": "Missing Authorization", "description": "缺少对用户权限的检查", "severity": 8.1, "mitigation": "RBAC/ABAC、权限中间件、接口级鉴权"},
            "CWE-863": {"name": "Incorrect Authorization", "description": "权限检查逻辑存在缺陷", "severity": 7.8, "mitigation": "权限模型验证、集成测试、审计日志"},
            "CWE-908": {"name": "Use of Uninitialized Resource", "description": "使用了未初始化的变量/内存/资源", "severity": 6.2, "mitigation": "声明即初始化、编译器警告(all-Wall)、静态分析"},
            "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "description": "服务端在未校验目标的情况下发起请求", "severity": 7.5, "mitigation": "URL白名单、禁止内网地址、DNS重绑定防护"},
            "CWE-1004": {"name": "Sensitive Cookie Without 'HttpOnly'", "description": "敏感Cookie未设置HttpOnly属性", "severity": 5.3, "mitigation": "设置HttpOnly/Secure/SameSite属性"},
            "CWE-1173": {"name": "Improper Use of Validation Framework", "description": "使用了校验框架但配置不当", "severity": 7.5, "mitigation": "框架文档复核、边界测试、安全审计"},
            "CWE-1240": {"name": "Use of Cryptographic Primitive with Insufficient Security Margin", "description": "密码学原语的安全余量不足（如短密钥）", "severity": 7.5, "mitigation": "使用推荐密钥长度(>=2048 RSA, >=256 ECC)、跟踪NIST建议"},
            "CWE-1265": {"name": "Unintended Reentrant Invocation", "description": "不可重入的函数被意外重入调用", "severity": 7.0, "mitigation": "重入锁、状态机设计、禁用中断"},
            "CWE-1275": {"name": "Sensitive Cookie in HTTPS Session Without 'Secure'", "description": "HTTPS下Cookie未设置Secure属性", "severity": 5.3, "mitigation": "设置Secure属性、HSTS头"},
            "CWE-1284": {"name": "Improper Validation of Specified Quantity", "description": "未按规范对数量/大小进行验证", "severity": 7.5, "mitigation": "输入校验、边界检查、类型安全"},
            "CWE-1321": {"name": "Improperly Controlled Modification of Prototype", "description": "对象原型被意外修改（原型污染）", "severity": 8.6, "mitigation": "Object.freeze()、Map替代普通对象、输入过滤"},
            "CWE-1333": {"name": "Inefficient Regular Expression (ReDoS)", "description": "正则表达式存在灾难性回溯", "severity": 7.5, "mitigation": "使用非回溯引擎(RE2)、限制匹配长度、正则审查"},
        }