@echo off
REM
chcp 65001 >nul
setlocal

cd /d "%~dp0"

echo.
echo   ============================================================
echo     网站安全巡检 · 分级靶场
echo   ============================================================
echo.

set "PY="
where py >nul 2>nul && set "PY=py"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo   [错误] 没有找到 Python。
  echo          请先安装 Python，或把 python.exe 加入 PATH。
  echo.
  pause
  exit /b 1
)

echo   使用 Python：%PY%
echo.

echo   检查 8081 端口...
netstat -ano | findstr /r /c:":8081 .*LISTENING" >nul 2>nul
if not errorlevel 1 (
  echo   [警告] 8081 端口已被占用。
  echo          可能是靶场已经在运行了。
  echo          若要用别的端口，请手动执行：  %PY% serve.py --port 9000
  echo.
  pause
  exit /b 1
)

echo   端口可用。
echo.
echo   ------------------------------------------------------------
echo    正在启动靶场服务器（按 Ctrl+C 停止）
echo   ------------------------------------------------------------
echo.
echo    自检（另开一个窗口执行）：
echo        %PY% verify_range.py --port 8081
echo.
echo    重新生成静态资产（改了关卡内容后）：
echo        %PY% build_assets.py
echo.

if not exist "C:\Program Files\.tool\php-8.5.10\php-cgi.exe" (
  echo    [提示] 未检测到 PHP，8 个动态漏洞考点会返回 503。
  echo           其余 85 项不受影响。装了 PHP 后自动启用。
  echo.
)

%PY% serve.py --port 8081

echo.
echo   靶场已停止。
pause
endlocal
