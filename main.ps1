# Define configuration as a single hash table for better maintainability
$config = @{
    windowsExporter = @{
        url = "https://github.com/prometheus-community/windows_exporter/releases/latest/download/windows_exporter-0.20.0-amd64.msi"
        installerPath = "$env:TEMP\windows_exporter.msi"
        serviceName = "windows_exporter"
        firewallRuleName = "WindowsExporterPort9182"
        port = 9182
    }
    prometheus = @{
        url = "https://github.com/prometheus/prometheus/releases/download/v2.42.0/prometheus-2.42.0.windows-amd64.zip"
        zipPath = "$env:TEMP\prometheus.zip"
        extractPath = "$env:ProgramFiles\Prometheus"
        exePath = "$env:ProgramFiles\Prometheus\prometheus.exe"
        configPath = "$env:ProgramFiles\Prometheus\prometheus.yml"
        logPath = "$env:ProgramFiles\Prometheus\prometheus.log"
        firewallRuleName = "PrometheusPort9090"
        port = 9090
    }
}

# Get the system's IP address dynamically
$systemIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual' }).IPAddress | Select-Object -First 1
$exporterUrl = "http://${systemIp}:$($config.windowsExporter.port)/metrics"
$prometheusUrlCheck = "http://${systemIp}:$($config.prometheus.port)/metrics"

# Function to check the status of a service
function Get-ServiceStatus {
    param (
        [string]$serviceName
    )
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        return $service.Status
    } else {
        return "Not Installed"
    }
}

# Function to check firewall rule status
function Get-FirewallRuleStatus {
    param (
        [string]$ruleName
    )
    if ([string]::IsNullOrEmpty($ruleName)) {
        return "Not Configured"
    }
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        return "Exists"
    } else {
        return "Not Configured"
    }
}

# Function to test if an endpoint is reachable
function Test-Endpoint {
    param (
        [string]$url
    )
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -Method Head -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            return "Reachable"
        } else {
            return "Unreachable (Status Code: $($response.StatusCode))"
        }
    } catch {
        return "Unreachable"
    }
}

# Function to display the environment status
function Display-StatusTable {
    param (
        [string]$stage
    )

    $statusTable = @(
        [PSCustomObject]@{Component = "Windows Exporter"; Status = (Get-ServiceStatus -Name $config.windowsExporter.serviceName)}
        [PSCustomObject]@{Component = "Windows Exporter Firewall Rule"; Status = (Get-FirewallRuleStatus -ruleName $config.windowsExporter.firewallRuleName)}
        [PSCustomObject]@{Component = "Windows Exporter Endpoint"; Status = (Test-Endpoint -url $exporterUrl)}
        [PSCustomObject]@{Component = "Prometheus"; Status = (Get-ServiceStatus -Name $config.prometheus.serviceName)}
        [PSCustomObject]@{Component = "Prometheus Firewall Rule"; Status = (Get-FirewallRuleStatus -ruleName $config.prometheus.firewallRuleName)}
        [PSCustomObject]@{Component = "Prometheus Endpoint"; Status = (Test-Endpoint -url $prometheusUrlCheck)}
    )

    Write-Host "$stage Status:" -ForegroundColor Cyan
    $statusTable | Format-Table -AutoSize
}

# Function to create Prometheus configuration file
function Create-PrometheusConfig {
    param (
        [string]$configPath,
        [string]$systemIp,
        [int]$exporterPort,
        [int]$prometheusPort
    )
    $prometheusConfig = @"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'windows_exporter'
    static_configs:
      - targets: ['${systemIp}:${exporterPort}', 'localhost:${exporterPort}']
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:${prometheusPort}']
"@
    $prometheusConfig | Set-Content -Path $configPath
    Write-Host "Prometheus configuration created at $configPath."
}

# Function to configure firewall rule
function Configure-FirewallRule {
    param (
        [string]$ruleName,
        [int]$port
    )
    if ([string]::IsNullOrEmpty($ruleName)) {
        Write-Host "Error: Firewall rule name is empty. Skipping firewall configuration." -ForegroundColor Red
        return
    }
    
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating firewall rule for $ruleName on port $port..."
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port
    } else {
        Write-Host "Firewall rule '$ruleName' already exists."
    }
}

# Function to run Prometheus and capture output in a log file
function Start-Prometheus {
    param (
        [string]$exePath,
        [string]$configPath,
        [string]$logPath,
        [int]$port
    )
    $command = "& `"$exePath`" --config.file=`"$configPath`" --web.listen-address=`":$port`" --log.level=info > `"$logPath`" 2>&1"
    Write-Host "Starting Prometheus with command: $command"
    Invoke-Expression $command
    Write-Host "Prometheus is running and output is being logged to $logPath."
}

# Main execution script
clear-host
Write-Host "Starting setup..."

# Display Pre-Installation Status
Display-StatusTable -stage "Pre-Installation"
Write-Host "Windows Exporter URL: $exporterUrl"
Write-Host "Prometheus URL: $prometheusUrlCheck"

# Install and configure Windows Exporter
Install-WindowsExporter
Configure-FirewallRule -ruleName $config.windowsExporter.firewallRuleName -port $config.windowsExporter.port

# Install and configure Prometheus
Install-Prometheus
Create-PrometheusConfig -configPath $config.prometheus.configPath -systemIp $systemIp -exporterPort $config.windowsExporter.port -prometheusPort $config.prometheus.port
Configure-FirewallRule -ruleName $config.prometheus.firewallRuleName -port $config.prometheus.port

# Start Prometheus and log output
Start-Prometheus -exePath $config.prometheus.exePath -configPath $config.prometheus.configPath -logPath $config.prometheus.logPath -port $config.prometheus.port

# Display Post-Installation Status
Display-StatusTable -stage "Post-Installation"
Write-Host "Windows Exporter URL: $exporterUrl"
Write-Host "Prometheus URL: $prometheusUrlCheck"

Write-Host "Setup completed."
