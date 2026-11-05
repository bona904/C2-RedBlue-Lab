@echo off
:: 设置控制台编码为 UTF-8，防止中文乱码
chcp 65001 >nul
title C2 红蓝对抗一键靶场启动器

echo ===================================================
echo        C2 恶意流量分析红蓝对抗靶场 (一键启动)
echo ===================================================
echo.

:: 1. 检查当前目录是否在项目根目录
if not exist "c2_simulator" (
    echo [错误] 找不到 c2_simulator 目录！
    echo 请确保把这个 start_lab.bat 放在项目根目录下运行。
    pause
    exit /b
)

:: 2. 检查 Python 环境
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python 环境，请先安装 Python 或激活虚拟环境！
    pause
    exit /b
)

echo [*] Python 环境检查通过，正在启动靶场...
echo.

:: 3. 启动 C2 服务端 (红队-指挥中心)
echo [1/3] 正在启动 C2 服务端 (Server)...
start "C2 Server" cmd /k "cd c2_simulator && python server.py"
:: 延时 2 秒，确保服务端先起来
timeout /t 2 >nul

:: 4. 启动 C2 客户端 (红队-被控端)
echo [2/3] 正在启动 C2 客户端 (Client / 高级规避模式)...
start "C2 Client" cmd /k "cd c2_simulator && python advanced_client.py"
:: 延时 2 秒
timeout /t 2 >nul

:: 5. 启动 Web 流量分析平台 (蓝队-安全研判)
echo [3/3] 正在启动 Web 流量分析平台 (Analyzer)...
start "Traffic Analyzer Web" cmd /k "cd traffic_analyzer && python app.py"

:: 6. 结束提示
echo.
echo ===================================================
echo [成功] 靶场三驾马车已全部拉起！
echo.
echo 请打开浏览器访问: http://127.0.0.1:5000
echo (关闭此黑框不会停止靶场，请手动关闭另外三个黑框以结束)
echo ===================================================
pause