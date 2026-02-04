@echo off
title AIOHAI Shutdown
echo ============================================
echo  AIOHAI - Stopping Services
echo ============================================
echo.

:: Stop Electron app
echo [1/3] Stopping AIOHAI Desktop...
taskkill /F /IM electron.exe >nul 2>&1
if errorlevel 1 (
    echo       App not running
) else (
    echo       App stopped
)

:: Ask about stopping other services
echo.
choice /C YN /M "Stop Open WebUI container"
if errorlevel 2 goto SKIP_WEBUI
echo [2/3] Stopping Open WebUI...
docker stop open-webui >nul 2>&1
echo       Open WebUI stopped
goto CHECK_OLLAMA

:SKIP_WEBUI
echo [2/3] Skipping Open WebUI

:CHECK_OLLAMA
echo.
choice /C YN /M "Stop Ollama"
if errorlevel 2 goto SKIP_OLLAMA
echo [3/3] Stopping Ollama...
taskkill /F /IM ollama.exe >nul 2>&1
echo       Ollama stopped
goto DONE

:SKIP_OLLAMA
echo [3/3] Skipping Ollama

:DONE
echo.
echo ============================================
echo  AIOHAI shutdown complete
echo ============================================
pause
