<#
.SYNOPSIS
    AIOHAI Open WebUI Setup Script
    
.DESCRIPTION
    Configures AIOHAI to work with Open WebUI:
    - Sets up firewall rules to enforce proxy usage
    - Configures the secure proxy service
    - Provides Docker commands for Open WebUI
    
.EXAMPLE
    .\Setup-OpenWebUI.ps1 -Install
    .\Setup-OpenWebUI.ps1 -ConfigureFirewall
    .\Setup-OpenWebUI.ps1 -StartProxy
#>

param(
    [switch]$Install,
    [switch]$ConfigureFirewall,
    [switch]$StartProxy,
    [switch]$StopProxy,
    [switch]$Status,
    [switch]$Uninstall,
    [string]$InstallPath = "C:\AIOHAI",
    [int]$ProxyPort = 11435,
    [int]$OllamaPort = 11434
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $color = switch ($Type) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        default { "Cyan" }
    }
    $prefix = switch ($Type) {
        "OK" { "[OK]" }
        "WARN" { "[!!]" }
        "ERROR" { "[XX]" }
        default { "[**]" }
    }
    Write-Host "$prefix " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Install-OpenWebUIIntegration {
    Write-Status "Setting up AIOHAI for Open WebUI integration" "INFO"
    
    # Check for admin privileges (needed for firewall rules)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "This script requires Administrator privileges for firewall rules." "ERROR"
        Write-Status "Right-click PowerShell and select 'Run as Administrator'" "ERROR"
        return
    }
    
    # Check Python
    $pythonExe = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonExe) {
        Write-Status "Python not found. Install from https://www.python.org/downloads/" "ERROR"
        return
    }
    $pyVersion = & python --version 2>&1
    Write-Status "Python found: $pyVersion" "OK"
    
    # Check pip dependencies
    $reqFile = Join-Path $InstallPath "requirements.txt"
    if (Test-Path $reqFile) {
        Write-Status "Installing Python dependencies..." "INFO"
        & python -m pip install -r $reqFile --quiet 2>&1 | Out-Null
        Write-Status "Dependencies installed" "OK"
    }
    
    # Check Ollama
    $ollamaOK = Test-NetConnection -ComputerName localhost -Port $OllamaPort -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($ollamaOK) {
        Write-Status "Ollama running on port $OllamaPort" "OK"
    } else {
        Write-Status "Ollama not detected on port $OllamaPort — start it with 'ollama serve'" "WARN"
    }
    
    # Verify aiohai package directory exists
    $aiohaiDir = Join-Path $InstallPath "aiohai"
    if (-not (Test-Path $aiohaiDir)) {
        Write-Status "AIOHAI package directory not found — ensure the codebase is deployed to $InstallPath" "WARN"
    }
    
    # Configure firewall
    Install-FirewallRules
    
    # Show Docker command
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "Open WebUI Docker Command:" -ForegroundColor Yellow
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
    Write-Host @"
docker run -d ``
  --name open-webui ``
  -p 3000:8080 ``
  -e OLLAMA_BASE_URL=http://host.docker.internal:$ProxyPort ``
  -e ENABLE_SIGNUP=false ``
  -e DEFAULT_USER_ROLE=pending ``
  -e WEBUI_SESSION_COOKIE_SAME_SITE=strict ``
  -v open-webui:/app/backend/data ``
  --restart unless-stopped ``
  ghcr.io/open-webui/open-webui:main
"@
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    Write-Host ""
    Write-Status "Installation complete!" "OK"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Start the proxy: .\Setup.ps1 -StartProxy"
    Write-Host "  2. Run the Docker command above"
    Write-Host "  3. Open http://localhost:3000"
}

function Install-FirewallRules {
    Write-Status "Configuring Windows Firewall for Open WebUI mode" "INFO"
    
    # Remove existing AIOHAI rules
    Get-NetFirewallRule -DisplayName "AIOHAI*" -ErrorAction SilentlyContinue | 
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    
    # Rule 1: Block ALL direct access to Ollama
    New-NetFirewallRule -DisplayName "AIOHAI - Block Direct Ollama (Inbound)" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $OllamaPort `
        -Action Block `
        -Profile Any `
        -Description "Block all inbound connections to Ollama - must use proxy" | Out-Null
    Write-Status "  Blocked inbound to Ollama port $OllamaPort" "OK"
    
    # Rule 2: Allow only the proxy to connect to Ollama outbound
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    
    if ($pythonExe) {
        New-NetFirewallRule -DisplayName "AIOHAI - Allow Proxy to Ollama (Python)" `
            -Direction Outbound `
            -Protocol TCP `
            -RemotePort $OllamaPort `
            -Program $pythonExe `
            -Action Allow `
            -Profile Any | Out-Null
        Write-Status "  Allowed Python to connect to Ollama" "OK"
    }
    
    # Rule 3: Allow inbound to proxy port (for Open WebUI)
    New-NetFirewallRule -DisplayName "AIOHAI - Allow Inbound to Proxy" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $ProxyPort `
        -Action Allow `
        -Profile Any `
        -Description "Allow Open WebUI to connect to AIOHAI proxy" | Out-Null
    Write-Status "  Allowed inbound to proxy port $ProxyPort" "OK"
    
    # Rule 4: Allow Open WebUI port
    New-NetFirewallRule -DisplayName "AIOHAI - Allow Open WebUI" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 3000 `
        -Action Allow `
        -Profile Private `
        -Description "Allow access to Open WebUI (private network only)" | Out-Null
    Write-Status "  Allowed inbound to Open WebUI port 3000 (private only)" "OK"
    
    Write-Status "Firewall configured" "OK"
}

function Start-SecureProxy {
    Write-Status "Starting AIOHAI Proxy v5.0.0..." "INFO"
    
    # Use python -m aiohai as canonical entry point
    $proxyModule = "aiohai"
    
    # Check if aiohai package exists
    $aiohaInit = Join-Path $InstallPath "aiohai\__init__.py"
    if (-not (Test-Path $aiohaInit)) {
        Write-Status "AIOHAI package not found at: $InstallPath\aiohai\" "ERROR"
        Write-Status "Please ensure the aiohai package is in the install directory" "ERROR"
        return
    }
    
    # Check if already running
    $existing = Get-Process -Name "python*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*-m aiohai*" }
    
    if ($existing) {
        Write-Status "Proxy already running (PID: $($existing.Id))" "WARN"
        return
    }
    
    # Start proxy in background
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "python"
    $psi.Arguments = "-m aiohai --listen-port $ProxyPort --ollama-port $OllamaPort"
    $psi.WorkingDirectory = $InstallPath
    $psi.UseShellExecute = $true
    $psi.WindowStyle = "Minimized"
    
    $process = [System.Diagnostics.Process]::Start($psi)
    
    Start-Sleep -Seconds 2
    
    if (-not $process.HasExited) {
        Write-Status "Proxy started (PID: $($process.Id))" "OK"
        Write-Host ""
        Write-Host "Proxy listening on: http://localhost:$ProxyPort" -ForegroundColor Green
        Write-Host "Forwarding to Ollama: http://localhost:$OllamaPort" -ForegroundColor Green
    } else {
        Write-Status "Proxy failed to start" "ERROR"
    }
}

function Stop-SecureProxy {
    Write-Status "Stopping AIOHAI Proxy..." "INFO"
    
    $processes = Get-Process -Name "python*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*-m aiohai*" }
    
    if ($processes) {
        $processes | ForEach-Object {
            Stop-Process -Id $_.Id -Force
            Write-Status "Stopped process $($_.Id)" "OK"
        }
    } else {
        Write-Status "No proxy processes found" "WARN"
    }
}

function Get-ProxyStatus {
    Write-Host ""
    Write-Host "AIOHAI Open WebUI Integration Status" -ForegroundColor Cyan
    Write-Host "=" * 50
    Write-Host ""
    
    # Check Ollama
    $ollamaRunning = Test-NetConnection -ComputerName localhost -Port $OllamaPort -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($ollamaRunning) {
        Write-Status "Ollama (port $OllamaPort): Running" "OK"
    } else {
        Write-Status "Ollama (port $OllamaPort): Not running" "ERROR"
    }
    
    # Check Proxy
    $proxyRunning = Test-NetConnection -ComputerName localhost -Port $ProxyPort -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($proxyRunning) {
        Write-Status "AIOHAI Proxy (port $ProxyPort): Running" "OK"
    } else {
        Write-Status "AIOHAI Proxy (port $ProxyPort): Not running" "WARN"
    }
    
    # Check Open WebUI
    $openwebuiRunning = Test-NetConnection -ComputerName localhost -Port 3000 -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($openwebuiRunning) {
        Write-Status "Open WebUI (port 3000): Running" "OK"
    } else {
        Write-Status "Open WebUI (port 3000): Not running" "WARN"
    }
    
    # Check Firewall Rules
    Write-Host ""
    Write-Host "Firewall Rules:" -ForegroundColor Yellow
    Get-NetFirewallRule -DisplayName "AIOHAI*" -ErrorAction SilentlyContinue | ForEach-Object {
        $status = if ($_.Enabled) { "Enabled" } else { "Disabled" }
        Write-Host "  $($_.DisplayName): $status"
    }
    
    # Check Proxy Process
    Write-Host ""
    Write-Host "Proxy Processes:" -ForegroundColor Yellow
    $processes = Get-Process -Name "python*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*-m aiohai*" }
    
    if ($processes) {
        $processes | ForEach-Object {
            Write-Host "  PID $($_.Id): Running"
        }
    } else {
        Write-Host "  No proxy processes found"
    }
    
    Write-Host ""
}

function Uninstall-OpenWebUIIntegration {
    Write-Status "Removing Open WebUI integration..." "INFO"
    
    # Stop proxy
    Stop-SecureProxy
    
    # Remove firewall rules
    Get-NetFirewallRule -DisplayName "AIOHAI*" -ErrorAction SilentlyContinue | 
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Status "Removed firewall rules" "OK"
    
    Write-Status "Uninstallation complete" "OK"
    Write-Host ""
    Write-Host "Note: Open WebUI Docker container was not removed." -ForegroundColor Yellow
    Write-Host "To remove it: docker rm -f open-webui" -ForegroundColor Yellow
}

# Main
Write-Host ""
Write-Host "AIOHAI Open WebUI Integration" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

if ($Install) {
    Install-OpenWebUIIntegration
} elseif ($ConfigureFirewall) {
    Install-FirewallRules
} elseif ($StartProxy) {
    Start-SecureProxy
} elseif ($StopProxy) {
    Stop-SecureProxy
} elseif ($Status) {
    Get-ProxyStatus
} elseif ($Uninstall) {
    Uninstall-OpenWebUIIntegration
} else {
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Setup-OpenWebUI.ps1 -Install           # Full installation"
    Write-Host "  .\Setup-OpenWebUI.ps1 -ConfigureFirewall # Firewall only"
    Write-Host "  .\Setup-OpenWebUI.ps1 -StartProxy        # Start proxy"
    Write-Host "  .\Setup-OpenWebUI.ps1 -StopProxy         # Stop proxy"
    Write-Host "  .\Setup-OpenWebUI.ps1 -Status            # Show status"
    Write-Host "  .\Setup-OpenWebUI.ps1 -Uninstall         # Remove integration"
}

Write-Host ""
