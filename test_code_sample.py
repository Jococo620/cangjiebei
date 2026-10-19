"""
代码扫描功能测试样例
包含多种典型安全漏洞，供鉴真代码扫描模块检测
"""


# ========== CWE-89: SQL注入 ==========
def login_user(username, password):
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 漏洞：直接拼接用户输入到SQL语句
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    result = cursor.fetchone()
    return result is not None


def search_products(keyword):
    import sqlite3
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    # 漏洞：格式化字符串构造SQL
    sql = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(sql)
    return cursor.fetchall()


# ========== CWE-78: 命令注入 ==========
def ping_host(host):
    import os
    # 漏洞：用户输入直接传入系统命令
    os.system("ping -c 4 " + host)


def run_command(user_input):
    import subprocess
    # 漏洞：shell=True 允许命令拼接
    subprocess.call(user_input, shell=True)


def backup_file(filename):
    import os
    # 漏洞：用户输入拼接到命令
    os.popen("cp " + filename + " /backup/")


# ========== CWE-22: 路径遍历 ==========
def read_file(filepath):
    # 漏洞：未校验路径，允许../../../etc/passwd
    with open(filepath, "r") as f:
        return f.read()


# ========== CWE-94: 代码注入 ==========
def evaluate_expression(expr):
    # 漏洞：直接执行用户输入的字符串
    return eval(expr)


def execute_code(code_str):
    # 漏洞：exec执行不可信输入
    exec(code_str)


# ========== CWE-79: XSS ==========
def render_page(username):
    # 漏洞：未转义直接输出到HTML
    return f"<h1>欢迎，{username}</h1>"


# ========== CWE-327: 弱加密 ==========
def encrypt_password(password):
    import hashlib
    # 漏洞：使用MD5弱哈希
    return hashlib.md5(password.encode()).hexdigest()


def encrypt_data(data):
    # 漏洞：使用DES弱加密
    from Crypto.Cipher import DES
    cipher = DES.new(b"8bytekey")
    return cipher.encrypt(data)


# ========== CWE-798: 硬编码凭据 ==========
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"


def connect_database():
    # 漏洞：硬编码数据库密码
    conn = connect("mysql://root:admin123@localhost/db")
    return conn


# ========== CWE-295: 证书校验缺失 ==========
def fetch_https(url):
    import requests
    # 漏洞：禁用SSL证书验证
    resp = requests.get(url, verify=False)
    return resp.text


# ========== CWE-502: 反序列化 ==========
def load_session(data):
    import pickle
    # 漏洞：pickle反序列化不可信数据
    return pickle.loads(data)


# ========== 安全写法（对照组） ==========
def login_user_safe(username, password):
    import sqlite3
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 安全：参数化查询
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    return cursor.fetchone() is not None


def ping_host_safe(host):
    import subprocess
    # 安全：列表传参，不经过shell
    subprocess.call(["ping", "-c", "4", host])
