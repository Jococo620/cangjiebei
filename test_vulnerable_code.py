"""
测试目标代码 - 包含多种安全漏洞

漏洞类型：
1. SQL注入 (CWE-89)
2. 路径遍历 (CWE-22)
3. 命令注入 (CWE-78)
4. XSS跨站脚本 (CWE-79)
5. 硬编码凭证 (CWE-798)
6. 缓冲区溢出风险 (CWE-122)

使用方法：
1. 启动智能体服务：python run.py
2. 通过API检测：POST /threat/analyze {"file": "test_vulnerable_code.py"}
"""

import os
import subprocess
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ==================== 漏洞1: SQL注入 (CWE-89) ====================
def search_user(username):
    """直接拼接SQL语句，存在SQL注入漏洞"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

# ==================== 漏洞2: 路径遍历 (CWE-22) ====================
def load_config(config_path):
    """未校验路径，存在路径遍历漏洞"""
    with open(config_path, 'r') as f:
        return f.read()

# ==================== 漏洞3: 命令注入 (CWE-78) ====================
def ping_host(host):
    """直接执行系统命令，存在命令注入漏洞"""
    result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)
    return result.stdout

# ==================== 漏洞4: XSS跨站脚本 (CWE-79) ====================
@app.route('/greet')
def greet():
    """未对用户输入进行HTML编码，存在XSS漏洞"""
    name = request.args.get('name', 'Guest')
    return f"<h1>Hello, {name}!</h1>"

# ==================== 漏洞5: 硬编码凭证 (CWE-798) ====================
DB_USERNAME = "admin"
DB_PASSWORD = "password123"
API_KEY = "secret_key_12345"

def connect_db():
    return sqlite3.connect(f"database.db?user={DB_USERNAME}&password={DB_PASSWORD}")

# ==================== 漏洞6: 缓冲区溢出风险 (CWE-122) ====================
def copy_buffer(source, dest, dest_size):
    """未校验源数据长度，存在缓冲区溢出风险"""
    for i in range(len(source)):
        if i < dest_size:
            dest[i] = source[i]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)