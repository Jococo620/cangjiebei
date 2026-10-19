@echo off
chcp 65001 >nul 2>&1
title 鉴真智能体 - 一键启动

echo ============================================
echo   鉴真智能体 一键启动脚本 (Windows)
echo ============================================
echo.

REM 优先使用项目自带的 .conda 环境，否则使用系统 Python
set PYEXE=d:\鉴真\.conda\python.exe

if not exist "%PYEXE%" (
    echo [信息] 未找到 .conda 环境，尝试使用系统 Python...
    where python >nul 2>&1
    if %errorlevel%==0 (
        set PYEXE=python
    ) else (
        echo [错误] 未检测到 Python，请先安装 Python 3.9+
        echo [提示] 下载地址: https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

echo [信息] 使用Python: %PYEXE%
"%PYEXE%" --version

REM 检查依赖是否已安装
"%PYEXE%" -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo [步骤] 首次运行，正在安装项目依赖...
    "%PYEXE%" -m pip install -r requirements.txt
)

REM 检查配置文件
if not exist ".nexus\llm_config.json" (
    echo.
    echo [提示] 首次使用需要配置LLM API密钥
    echo   1. 复制 .env.example 为 .env
    echo   2. 在 .env 中填写你的 API Key
    echo   3. 或运行: "%PYEXE%" -c "from nexus.config import init_llm_config; init_llm_config()"
    echo.
)

echo ============================================
echo   启动服务中...
echo ============================================
echo.
echo   前端界面: http://localhost:7800/frontend/dashboard/
echo   API接口:  http://localhost:7800/run/cang
echo   健康检查: http://localhost:7800/health
echo.
echo   按 Ctrl+C 停止服务
echo ============================================
echo.

"%PYEXE%" run.py
pause
