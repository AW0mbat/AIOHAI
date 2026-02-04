@echo off
title AIOHAI Startup
echo ============================================
echo  AIOHAI - Starting Services
echo ============================================
echo.

:: Start Docker Desktop if not running
echo [1/4] Checking Docker...
tasklist /FI "IMAGENAME eq Docker Desktop.exe" 2>nul | find /I "Docker Desktop.exe" >nul
if errorlevel 1 (
    echo       Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
) else (
    echo       Docker Desktop already running
)

:: Wait for Docker engine to be ready
echo       Waiting for Docker engine...
:WAIT_DOCKER
docker info >nul 2>&1
if errorlevel 1 (
    timeout /t 2 >nul
    goto WAIT_DOCKER
)
echo       Docker ready!

:: Start Ollama if not running
echo.
echo [2/4] Checking Ollama...
tasklist /FI "IMAGENAME eq ollama.exe" 2>nul | find /I "ollama.exe" >nul
if errorlevel 1 (
    echo       Starting Ollama...
    start "" /B ollama serve >nul 2>&1
    timeout /t 2 >nul
) else (
    echo       Ollama already running
)

:: Start Open WebUI container if not running
echo.
echo [3/4] Checking Open WebUI...
docker ps 2>nul | find "open-webui" >nul
if errorlevel 1 (
    echo       Starting Open WebUI container...
    docker start open-webui >nul 2>&1
    timeout /t 3 >nul
) else (
    echo       Open WebUI already running
)

:: Verify services
echo.
echo [4/4] Verifying services...
curl -s http://127.0.0.1:3000/api/config >nul 2>&1
if errorlevel 1 (
    echo       WARNING: Open WebUI not responding yet, waiting...
    timeout /t 5 >nul
)

echo.
echo ============================================
echo  All services ready - Launching app
echo ============================================
echo.

:: Launch the Electron app (hidden console)
wscript "C:\AIOHAI\desktop\launch-hidden.vbs"
exit