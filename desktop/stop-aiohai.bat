@echo off
REM --- AIOHAI Desktop --- Shutdown ---
REM Double-click this file to stop everything.

echo.
echo  Shutting down AIOHAI Desktop...
echo.

REM Stop Electron and Node processes
taskkill /f /im electron.exe >nul 2>&1 && echo  OK - Electron stopped || echo  - Electron was not running
taskkill /f /im node.exe >nul 2>&1 && echo  OK - Node processes stopped || echo  - Node was not running

REM Stop Docker container
docker stop open-webui-dev >nul 2>&1 && echo  OK - Open WebUI container stopped || echo  - Container was not running

echo.
echo  All services stopped.
echo.
pause
