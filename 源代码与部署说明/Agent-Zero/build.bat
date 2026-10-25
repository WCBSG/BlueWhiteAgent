@echo off
chcp 65001 >nul
rem
rem
rem
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "MODE=release"
set "SUFFIX="
set "DEFS="
if /i "%~1"=="debug" set "MODE=debug"
if /i "%MODE%"=="release" (
    set "DEFS=-DBW_RELEASE=1"
) else (
    set "SUFFIX=-dev"
)

set "GXX="
where g++ >nul 2>nul && set "GXX=g++"
if not defined GXX if exist "C:\@Tool\mingw64\bin\g++.exe" set "GXX=C:\@Tool\mingw64\bin\g++.exe"
if not defined GXX (
    echo [ERROR] g++ not found. Install MinGW-w64 or put it in C:\@Tool\mingw64\bin.
    exit /b 2
)

if not exist build mkdir build
set "OBJDIR=build\obj"
if /i "%MODE%"=="debug" set "OBJDIR=build\obj-dev"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

if not exist "tools\mkres.cpp" (
    echo [ERROR] missing tools\mkres.cpp
    exit /b 3
)
"%GXX%" -std=c++20 -O2 -o build\mkres.exe tools\mkres.cpp -lcabinet
if errorlevel 1 ( echo [FAILED] mkres & exit /b 1 )

build\mkres.exe build\resources_core.cpp "@data/rules/=data\rules"
if errorlevel 1 ( echo [FAILED] tool resources & exit /b 1 )

set "CFLAGS=-std=c++20 -O2 %DEFS% -ffunction-sections -fdata-sections -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -I src\main -I src\tools"
set "LIBS=-lws2_32 -lwinhttp -lbcrypt -lcrypt32 -lole32 -loleaut32 -luuid -luser32 -lgdi32 -lshell32 -ladvapi32 -lcabinet"

echo [BUILD] mode=%MODE%
echo [BUILD] %GXX%
echo [BUILD] compiling sources...
set "OBJS="
for %%f in (src\main\*.cpp) do (
    set "BASE=%%~nf"
    set "SKIP="
    if /i "%MODE%"=="release" if /i "!BASE!"=="selftest" set "SKIP=1"
    if not defined SKIP (
        set "OBJ=%OBJDIR%\!BASE!.o"
        "%GXX%" %CFLAGS% -c "%%f" -o "!OBJ!"
        if errorlevel 1 ( echo [FAILED] compile %%f & exit /b 1 )
        if /i not "!BASE!"=="main" set "OBJS=!OBJS! !OBJ!"
    )
)
for %%f in (src\tools\*.cpp) do (
    set "OBJ=%OBJDIR%\tool_%%~nf.o"
    "%GXX%" %CFLAGS% -c "%%f" -o "!OBJ!"
    if errorlevel 1 ( echo [FAILED] compile %%f & exit /b 1 )
    set "OBJS=!OBJS! !OBJ!"
)
set "WV2LOADER=data\WebView2Loader.dll"
set "WV2RES="
if exist "%WV2LOADER%" set "WV2RES="data/WebView2Loader.dll=%WV2LOADER%""
if not defined WV2RES echo [WARN] %WV2LOADER% not found - embedded WebView2 disabled

build\mkres.exe build\resources.cpp ^
    "ui/index.html=ui\index.html" ^
    "ui/app.css=ui\app.css" ^
    "ui/app.js=ui\app.js" ^
    "ui/logo.png=ui\logo.png" ^
    "ui/favicon.ico=ui\favicon.ico" ^
    "data/mcp.json=data\mcp.json" ^
    "@data/rules/=data\rules" ^
    "@data/skills/=data\skills" ^
    "@data/tools/=data\tools" %WV2RES%
if errorlevel 1 ( echo [FAILED] app resources & exit /b 1 )
if not exist "build\resources.cpp" ( echo [FAILED] resources.cpp not generated & exit /b 1 )
if exist "third_party\windres.exe" set "WINDRES=third_party\windres.exe"
if not defined WINDRES for %%d in ("%GXX%") do if exist "%%~dpdwindres.exe" set "WINDRES=%%~dpdwindres.exe"
if not defined WINDRES where windres >nul 2>nul && set "WINDRES=windres"
if defined WINDRES (
    "%WINDRES%" --codepage=65001 -I . -I src\main -i src\main\app.rc -o build\app_res.o
    if errorlevel 1 ( echo [FAILED] windres & exit /b 1 )
)
echo [BUILD] linking main program...
set "EXTRA="
if exist "build\app_res.o" set "EXTRA=build\app_res.o"
set "EXTRA=!EXTRA! build\resources.cpp %OBJDIR%\main.o"
"%GXX%" %CFLAGS% -DAGENT_GUI_BUILD -mwindows -static -s -Wl,--gc-sections ^
    -o build\agent%SUFFIX%.exe !OBJS! !EXTRA! %LIBS%
if errorlevel 1 (
    echo.
    echo [FAILED] link main program
    exit /b 1
)

set "APPNAME="
for /f "usebackq delims=" %%n in ("product.name") do set "APPNAME=%%n"
if not defined APPNAME set "APPNAME=WebSecAgent"
copy /y build\agent%SUFFIX%.exe "build\!APPNAME!%SUFFIX%.exe" >nul 2>nul
if errorlevel 1 (
    echo.
    echo [FAILED] cannot overwrite build\!APPNAME!%SUFFIX%.exe
    echo          The program is probably still running. Close it first, then rebuild.
    echo          Fresh binary is at build\agent%SUFFIX%.exe
    exit /b 1
)

echo.
echo [DONE] %MODE% build: build\!APPNAME!%SUFFIX%.exe  ^(build\agent%SUFFIX%.exe^)
if /i "%MODE%"=="release" (
    echo        no selftest / regextest / netbench in this build
) else (
    echo        CLI: agent%SUFFIX%.exe selftest / regextest / netbench
)
echo        tools: agent%SUFFIX%.exe toolhost  (single-process tool host)
exit /b 0
