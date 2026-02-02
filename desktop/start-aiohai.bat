@echo off
REM --- AIOHAI Desktop --- One-Click Startup ---
REM Double-click this file to start everything.
REM Press Ctrl+C in this window to shut everything down.

echo.
echo  ======================================
echo       AIOHAI Desktop Launcher
echo  ======================================
echo.

REM --- Step 1: Start Open WebUI Docker container ---
echo [1/4] Starting Open WebUI Docker container...
docker start open-webui-dev >nul 2>&1
if %errorlevel% equ 0 (
    echo       OK - Open WebUI starting at http://localhost:3000
) else (
    echo       FAIL - Could not start open-webui-dev container
    echo         Make sure Docker Desktop is running
    echo.
    pause
    exit /b 1
)

REM --- Step 2: Navigate to desktop folder ---
cd /d "%~dp0"
echo [2/4] Building main process...
call npm run build:main >nul 2>&1
if %errorlevel% equ 0 (
    echo       OK - Main process compiled
) else (
    echo       FAIL - Build failed. Run "npm run build:main" manually to see errors
    pause
    exit /b 1
)

REM --- Step 3: Start Vite dev server in background ---
echo [3/4] Starting Vite dev server...
start /b "" cmd /c "npm run dev:renderer >nul 2>&1"

REM Give Vite a moment to start
timeout /t 3 /nobreak >nul
echo       OK - Vite dev server running

REM --- Step 4: Launch Electron ---
echo [4/4] Launching AIOHAI Desktop...
echo.
echo  -----------------------------------------
echo   App is running. Close the Electron
echo   window or press Ctrl+C here to stop.
echo  -----------------------------------------
echo.

call npm run start

REM --- Cleanup when Electron closes ---
echo.
echo Shutting down...

REM Kill the Vite dev server
taskkill /f /im node.exe >nul 2>&1

echo Done. Docker container is still running.
echo To stop it: docker stop open-webui-dev
echo.
pause
