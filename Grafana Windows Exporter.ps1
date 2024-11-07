# Define variables for Windows Exporter
$windowsExporterUrl = "https://github.com/prometheus-community/windows_exporter/releases/latest/download/windows_exporter-0.20.0-amd64.msi"
$installerPath = "$env:TEMP\windows_exporter.msi"
$serviceName = "windows_exporter"
$wmiServiceName = "wmiApSrv"  # WMI Performance Adapter
$firewallRuleName = "WindowsExporterPort9182"
$exporterPort = 9182

# Define variables for Prometheus
$prometheusUrl = "https://github.com/prometheus/prometheus/releases/download/v2.42.0/prometheus-2.42.0.windows-amd64.zip"
$prometheusZipPath = "$env:TEMP\prometheus.zip"
$prometheusExtractPath = "$env:ProgramFiles\Prometheus"
$prometheusExePath = "$prometheusExtractPath\prometheus.exe"
$prometheusConfigPath = "$prometheusExtractPath\prometheus.yml"
$prometheusServiceName = "Prometheus"
$prometheusFirewallRuleName = "PrometheusPort9090"
$prometheusPort = 9090

# Define variables for NSSM and Prometheus installation
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip" # Adjust version as necessary
$nssmZipPath = "$env:TEMP\nssm.zip"
$nssmExtractPath = "C:\nssm"
$nssmExePath = "$nssmExtractPath\nssm.exe"

$prometheusConfigPath = "C:\Program Files\Prometheus\prometheus.yml"
$nssmPath = "C:\Program Files\nssm\nssm.exe"
$prometheusExePath = "C:\Program Files\Prometheus\prometheus.exe"

$winswUrl = "https://github.com/winsw/winsw/releases/latest/download/WinSW.NET4.exe"
$winswPath = "$env:ProgramFiles\Prometheus\WinSW.exe"

# Get the system's IP address dynamically
# Get only the first IPv4 address
$systemIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -eq 'Dhcp' -or $_.PrefixOrigin -eq 'Manual' }).IPAddress | Select-Object -First 1

$exporterUrl = "http://${systemIp}:$exporterPort/metrics"
$prometheusUrlCheck = "http://${systemIp}:$prometheusPort/metrics"

# Function to create Prometheus configuration file
function Create-PrometheusConfig {
    param (
        [string]$prometheusConfigPath,
        [string]$systemIp,
        [int]$exporterPort = 9182,
        [int]$prometheusPort = 9090
    )
    $prometheusConfig = @"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'windows_exporter'
    static_configs:
      - targets: ['${systemIp}:$exporterPort', 'localhost:$exporterPort']
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:$prometheusPort']
"@
    $prometheusConfig | Set-Content -Path $prometheusConfigPath
    Write-Host "Prometheus configuration created at $prometheusConfigPath."
} 
# Function to check service status
function Get-ServiceStatus {
    param (
        [string]$Name
    )
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($service) {
        return $service.Status
    }
    return "Not Installed"
}

# Function to check firewall rule status
function Get-FirewallRuleStatus {
    param (
        [string]$ruleName
    )
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        return "Exists"
    }
    return "Not Configured"
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
        [PSCustomObject]@{Component = "WMI Performance Adapter"; Status = (Get-ServiceStatus -Name $wmiServiceName)}
        [PSCustomObject]@{Component = "Windows Exporter"; Status = (Get-ServiceStatus -Name $serviceName)}
        [PSCustomObject]@{Component = "Windows Exporter Firewall Rule"; Status = (Get-FirewallRuleStatus -ruleName $firewallRuleName)}
        [PSCustomObject]@{Component = "Windows Exporter Endpoint"; Status = (Test-Endpoint -url $exporterUrl)}
        [PSCustomObject]@{Component = "Prometheus"; Status = (Get-ServiceStatus -Name $prometheusServiceName)}
        [PSCustomObject]@{Component = "Prometheus Firewall Rule"; Status = (Get-FirewallRuleStatus -ruleName $prometheusFirewallRuleName)}
        [PSCustomObject]@{Component = "Prometheus Endpoint"; Status = (Test-Endpoint -url $prometheusUrlCheck)}
    )

    Write-Host "$stage Status:" -ForegroundColor Cyan
    $statusTable | Format-Table -AutoSize
}

# Function to check if a service exists
function Test-ServiceExists {
    param (
        [string]$Name
    )
    Get-Service -Name $Name -ErrorAction SilentlyContinue | ForEach-Object { return $true }
    return $false
}

# Function to check if a service is running
function Test-ServiceRunning {
    param (
        [string]$Name
    )
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        return $true
    }
    return $false
}

# Function to start a service if it's not running with retry mechanism
function Start-ServiceIfNotRunning {
    param (
        [string]$Name,
        [int]$MaxRetries = 3,
        [int]$DelayBetweenRetries = 5
    )
    if (Test-ServiceExists -Name $Name) {
        if (-not (Test-ServiceRunning -Name $Name)) {
            for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
                try {
                    Write-Host "Attempting to start service '$Name' (Attempt $attempt of $MaxRetries)..."
                    Start-Service -Name $Name -ErrorAction Stop
                    Write-Host "Service '$Name' started successfully."
                    break
                } catch {
                    Write-Host "Failed to start service '$Name' on attempt $attempt. Error: $_"
                    if ($attempt -lt $MaxRetries) {
                        Write-Host "Waiting $DelayBetweenRetries seconds before retrying..."
                        Start-Sleep -Seconds $DelayBetweenRetries
                    } else {
                        Write-Host "Exceeded maximum attempts. Please check service permissions or logs for further investigation."
                        Start-Process "sc.exe" -ArgumentList "start $Name" -Wait -NoNewWindow -ErrorAction Stop
                    }
                }
            }
        } else {
            Write-Host "Service '$Name' is already running."
        }
    } else {
        Write-Host "Service '$Name' does not exist."
    }
}

# Function to install Windows Exporter
function Install-WindowsExporter {
    if (-not (Test-ServiceExists -Name $serviceName)) {
        Write-Host "Downloading Windows Exporter..."
        Invoke-WebRequest -Uri $windowsExporterUrl -OutFile $installerPath

        Write-Host "Installing Windows Exporter..."
        Start-Process msiexec.exe -ArgumentList "/i", "`"$installerPath`"", "/quiet", "/norestart" -Wait

        if (Test-ServiceExists -Name $serviceName) {
            Write-Host "Windows Exporter installed successfully."
        } else {
            Write-Host "Failed to install Windows Exporter."
            exit 1
        }
    } else {
        Write-Host "Windows Exporter is already installed."
    }
}

# Function to configure firewall rule
function Configure-FirewallRule {
    param (
        [string]$ruleName,
        [int]$port
    )
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating firewall rule for $ruleName on port $port..."
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port
        Write-Host "Firewall rule '$ruleName' created."
    } else {
        Write-Host "Firewall rule '$ruleName' already exists."
    }
}

# Function to test if the exporter is reachable
function Test-ExporterEndpoint {
    try {
        $response = Invoke-WebRequest -Uri $exporterUrl -UseBasicParsing -Method Head -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Host "Windows Exporter is reachable at $exporterUrl."
        } else {
            Write-Host "Windows Exporter is not reachable. Status code: $($response.StatusCode)"
        }
    } catch {
        Write-Host "Failed to reach Windows Exporter at $exporterUrl. Error: $_"
    }
}

# Function to create a scheduled task for Prometheus
function Create-PrometheusScheduledTask {
    Write-Host "Creating a scheduled task to run Prometheus..."

    # Define the path and arguments for Prometheus
    $action = New-ScheduledTaskAction -Execute "$prometheusExeFullPath" -Argument "--config.file=`"$prometheusConfigPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Register the task
    Register-ScheduledTask -TaskName "PrometheusTask" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    Write-Host "Scheduled task for Prometheus created successfully."
}

# Function to install Prometheus and configure with dynamic path handling
function Install-Prometheus {
    if (-not (Test-ServiceExists -Name $prometheusServiceName)) {
        Write-Host "Downloading Prometheus..."
        Invoke-WebRequest -Uri $prometheusUrl -OutFile $prometheusZipPath

        Write-Host "Extracting Prometheus..."
        
        # Ensure the Prometheus directory is empty before extracting
        if (Test-Path $prometheusExtractPath) { Remove-Item -Recurse -Force $prometheusExtractPath }
        New-Item -ItemType Directory -Path $prometheusExtractPath -Force | Out-Null
        Expand-Archive -Path $prometheusZipPath -DestinationPath $prometheusExtractPath -Force

        # Check if the extracted contents are in a versioned subfolder
        $subfolder = Get-ChildItem -Path $prometheusExtractPath | Where-Object { $_.PSIsContainer } | Select-Object -First 1
        if ($subfolder) {
            Write-Host "Moving Prometheus files to the main directory..."
            Move-Item -Path "$($subfolder.FullName)\*" -Destination $prometheusExtractPath -Force
            Remove-Item -Recurse -Force $subfolder.FullName
        }

        # Locate the Prometheus executable in the main directory
        $prometheusExeFullPath = "$prometheusExtractPath\prometheus.exe"
        if (-not (Test-Path $prometheusExeFullPath)) {
            Write-Host "Failed to locate prometheus.exe after extraction."
            exit 1
        }

        # Configure Prometheus to scrape Windows Exporter
        $prometheusConfig = @"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'windows_exporter'
    static_configs:
      - targets: ['${systemIp}:$exporterPort']
"@
        $prometheusConfig | Set-Content -Path $prometheusConfigPath

        # Create a scheduled task to run Prometheus
        Create-PrometheusScheduledTask
    } else {
        Write-Host "Prometheus is already installed."
    }
}

# Function to install Prometheus and configure service with dynamic path handling
function _Install-Prometheus {
    if (-not (Test-ServiceExists -Name $prometheusServiceName)) {
        Write-Host "Downloading Prometheus..."
        Invoke-WebRequest -Uri $prometheusUrl -OutFile $prometheusZipPath

        Write-Host "Extracting Prometheus..."
        
        # Ensure the Prometheus directory is empty before extracting
        if (Test-Path $prometheusExtractPath) { Remove-Item -Recurse -Force $prometheusExtractPath }
        New-Item -ItemType Directory -Path $prometheusExtractPath -Force | Out-Null
        Expand-Archive -Path $prometheusZipPath -DestinationPath $prometheusExtractPath -Force

        # Check if the extracted contents are in a versioned subfolder
        $subfolder = Get-ChildItem -Path $prometheusExtractPath | Where-Object { $_.PSIsContainer } | Select-Object -First 1
        if ($subfolder) {
            Write-Host "Moving Prometheus files to the main directory..."
            Move-Item -Path "$($subfolder.FullName)\*" -Destination $prometheusExtractPath -Force
            Remove-Item -Recurse -Force $subfolder.FullName
        }

        # Locate the Prometheus executable in the main directory
        $prometheusExeFullPath = "$prometheusExtractPath\prometheus.exe"
        if (-not (Test-Path $prometheusExeFullPath)) {
            Write-Host "Failed to locate prometheus.exe after extraction."
            exit 1
        }

        # Configure Prometheus to scrape Windows Exporter
        $prometheusConfig = @"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'windows_exporter'
    static_configs:
      - targets: ['${systemIp}:$exporterPort']
"@
        $prometheusConfig | Set-Content -Path $prometheusConfigPath

        # Set up the Prometheus service with the executable path
        $prometheusServicePath = "`"$prometheusExeFullPath`" --config.file=`"$prometheusConfigPath`""
        Write-Host "Installing Prometheus as a service..."
        
        # Use Remove-Service if Prometheus service already exists with incorrect configuration
        if (Test-ServiceExists -Name $prometheusServiceName) {
            Write-Host "Removing existing Prometheus service with incorrect configuration..."
            sc.exe delete $prometheusServiceName
        }
        
        New-Service -Name $prometheusServiceName -BinaryPathName $prometheusServicePath -DisplayName "Prometheus" -StartupType Automatic
        Write-Host "Prometheus installed and configured to scrape Windows Exporter metrics."
    } else {
        Write-Host "Prometheus is already installed."
    }
}

# Function to correct Prometheus service path if necessary
function Correct-PrometheusServicePath {
    if (Test-ServiceExists -Name $prometheusServiceName) {
        Write-Host "Correcting Prometheus service path, looking for prometheus in $prometheusExtractPath..."

        # Find the Prometheus executable directly in the main directory
        $prometheusExeFullPath = "$prometheusExtractPath\prometheus.exe"

        # Confirm that the Prometheus executable exists in the main directory
        if (Test-Path $prometheusExeFullPath) {
            $configPathWithQuotes = "`"$prometheusExeFullPath`" --config.file=`"$prometheusConfigPath`""

            # Configure the service with the correct path
            Start-Process "sc.exe" -ArgumentList "config", $prometheusServiceName, "binPath=", $configPathWithQuotes -Wait
            
            Write-Host "Prometheus service path updated to $prometheusExeFullPath."

            # Verify the configuration by displaying the service details
            Write-Host "Verifying Prometheus service configuration:"
            & sc.exe qc $prometheusServiceName
        } else {
            Write-Host "Failed to locate prometheus.exe in $prometheusExtractPath. Please check the installation."
        }
    }
}

# Function to test if the Prometheus endpoint is reachable
function Test-PrometheusEndpoint {
    try {
        $response = Invoke-WebRequest -Uri $prometheusUrlCheck -UseBasicParsing -Method Head -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Host "Prometheus is reachable at $prometheusUrlCheck."
        } else {
            Write-Host "Prometheus is not reachable. Status code: $($response.StatusCode)"
        }
    } catch {
        Write-Host "Failed to reach Prometheus at $prometheusUrlCheck. Error: $_"
    }
}

function Remove_Service
{
    # Remove existing Prometheus service
    Stop-Service -Name Prometheus -Force
    sc.exe delete Prometheus
}

# Function to check and start WMI Performance Adapter service with correct startup type
function Ensure-WMIServiceRunning {
    # Check if the service exists
    if (Test-ServiceExists -Name $wmiServiceName) {
        # Get the service object
        $service = Get-Service -Name $wmiServiceName -ErrorAction SilentlyContinue

        # Check if the StartType is set to Disabled
        $wmiService = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq $wmiServiceName }
        if ($wmiService.StartMode -eq 'Disabled') {
            Write-Host "Changing StartType of '$wmiServiceName' to Automatic..."
            # Change StartType to Automatic
            sc.exe config $wmiServiceName start= auto | Out-Null
        }

        # Start the service if it is not already running
        if ($service.Status -ne 'Running') {
            try {
                Start-Service -Name $wmiServiceName -ErrorAction Stop
                Write-Host "Service '$wmiServiceName' started successfully."
            } catch {
                Write-Host "Failed to start service '$wmiServiceName'. Error: $_"
            }
        } else {
            Write-Host "Service '$wmiServiceName' is already running."
        }
    } else {
        Write-Host "Service '$wmiServiceName' does not exist."
    }
}

function Install-PrometheusUsingNSSM {
    # Download NSSM if it is not already installed
    if (-not (Test-Path $nssmExePath)) {
        Write-Host "Downloading NSSM..."
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZipPath

        Write-Host "Extracting NSSM..."
        if (Test-Path $nssmExtractPath) { Remove-Item -Recurse -Force $nssmExtractPath }
        New-Item -ItemType Directory -Path $nssmExtractPath -Force | Out-Null
        Expand-Archive -Path $nssmZipPath -DestinationPath $nssmExtractPath -Force

        # Move the correct NSSM executable to the main directory
        $nssmExe = Get-ChildItem -Path $nssmExtractPath -Recurse -Filter "nssm.exe" | Select-Object -First 1
        if ($nssmExe) {
            Move-Item -Path $nssmExe.FullName -Destination $nssmExePath -Force
        } else {
            Write-Host "Failed to locate nssm.exe after extraction. Please check the download."
            return
        }
        Write-Host "NSSM installed successfully at $nssmExePath."
    } else {
        Write-Host "NSSM is already installed at $nssmExePath."
    }

    # Check if Prometheus service exists; if so, remove it to recreate with NSSM
    if (Test-ServiceExists -Name $prometheusServiceName) {
        Write-Host "Removing existing Prometheus service..."
        Stop-Service -Name $prometheusServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $prometheusServiceName | Out-Null
    }

    # Use NSSM to install Prometheus as a service
    $prometheusArgs = "--config.file=`"$prometheusConfigPath`""
    Write-Host "Installing Prometheus as a service using NSSM..."

    # Using NSSM to configure the service with the correct executable and arguments
    & $nssmExePath install $prometheusServiceName $prometheusExePath $prometheusArgs
    & $nssmExePath set $prometheusServiceName Start SERVICE_AUTO_START

    # Verify the NSSM Prometheus service installation
    if (Test-ServiceExists -Name $prometheusServiceName) {
        Write-Host "Prometheus service installed successfully with NSSM."
    } else {
        Write-Host "Failed to install Prometheus service with NSSM."
    }
}

# Function to download and install WinSW for Prometheus service management
function Install-WinSW {
    if (-not (Test-Path $config.prometheus.winswPath)) {
        Write-Host "Downloading WinSW..."
        Invoke-WebRequest -Uri $config.prometheus.winswUrl -OutFile $config.prometheus.winswPath
    } else {
        Write-Host "WinSW is already downloaded."
    }
}

# Function to create WinSW XML configuration for Prometheus
function Create-WinSWConfig {
    param (
        [string]$exePath,
        [string]$configPath,
        [string]$winSWPath
    )
    $xmlConfig = @"
<service>
  <id>Prometheus</id>
  <name>Prometheus</name>
  <description>Prometheus monitoring service</description>
  <executable>$exePath</executable>
  <arguments>--config.file="$configPath"</arguments>
  <logmode>rotate</logmode>
</service>
"@
    $xmlFilePath = [System.IO.Path]::ChangeExtension($winSWPath, ".xml")
    $xmlConfig | Set-Content -Path $xmlFilePath
    Write-Host "WinSW configuration created at $xmlFilePath."
}

# Function to install Prometheus as a service using WinSW
function Install-PrometheusServiceUsingWinSW {
    Write-Host "Installing Prometheus as a Windows service using WinSW..."
    & $config.prometheus.winswPath install
    & $config.prometheus.winswPath start
}

# Function to install NSSM
function Install-NSSM {
    if (-not (Test-Path $config.nssm.exePath)) {
        Write-Host "Downloading NSSM..."
        Invoke-WebRequest -Uri $config.nssm.url -OutFile $config.nssm.zipPath
        Expand-Archive -Path $config.nssm.zipPath -DestinationPath $config.nssm.extractPath -Force
    } else {
        Write-Host "NSSM is already installed."
    }
}

# Function to install a service using NSSM
function Install-ServiceUsingNSSM {
    param (
        [string]$serviceName,
        [string]$exePath,
        [string]$configPath,
        [string]$nssmExePath
    )
    Write-Host "Setting up $serviceName service using NSSM..."
    & $nssmExePath install $serviceName $exePath "--config.file=`"$configPath`""
    & $nssmExePath set $serviceName Start SERVICE_AUTO_START
}
# & "C:\Program Files\Prometheus\prometheus.exe" --config.file="C:\Program Files\Prometheus\prometheus.yml" --web.listen-address ":9090" --log.level=info > "C:\Program Files\Prometheus\prometheus.log"
clear-host

# Main script execution
Write-Host "Starting setup..."

# Start WMI Performance Adapter service
Ensure-WMIServiceRunning

# Display pre-installation status
Display-StatusTable -stage "Pre-Installation"

# Start WMI Performance Adapter service
Start-ServiceIfNotRunning -Name $wmiServiceName

# Install Windows Exporter
Install-WindowsExporter

# Start Windows Exporter service
Start-ServiceIfNotRunning -Name $serviceName

# Configure firewall rule for Windows Exporter
Configure-FirewallRule -ruleName $firewallRuleName -port $exporterPort

# Test if the Windows Exporter endpoint is reachable
Test-Endpoint -url $exporterUrl

# Test if the Windows Exporter endpoint is reachable
Test-ExporterEndpoint

# Install Prometheus
Install-Prometheus
# Create Prometheus configuration
# Create-PrometheusConfig -prometheusConfigPath $prometheusConfigPath -systemIp $systemIp
Create-PrometheusConfig -configPath $config.prometheus.configPath -systemIp $systemIp -exporterPort $config.windowsExporter.port -prometheusPort $config.prometheus.port

# Install Prometheus using NSSM
Install-PrometheusUsingNSSM -nssmPath $nssmPath -prometheusExePath $prometheusExePath -prometheusConfigPath $prometheusConfigPath

# Install and configure NSSM
Install-NSSM
Install-ServiceUsingNSSM -serviceName $config.prometheus.serviceName -exePath $config.prometheus.exePath -configPath $config.prometheus.configPath -nssmExePath $config.nssm.exePath

# Install WinSW and configure Prometheus as a service
Install-WinSW
Create-WinSWConfig -exePath $config.prometheus.exePath -configPath $config.prometheus.configPath -winSWPath $config.prometheus.winswPath
Install-PrometheusServiceUsingWinSW

# Correct Prometheus service path if necessary
Correct-PrometheusServicePath

# Start Prometheus service
Start-ServiceIfNotRunning -Name $prometheusServiceName

# Configure firewall rule for Prometheus
Configure-FirewallRule -ruleName $prometheusFirewallRuleName -port $prometheusPort

# Test if the Prometheus endpoint is reachable
Test-PrometheusEndpoint

# Test if the Prometheus endpoint is reachable
Test-Endpoint -url $prometheusUrlCheck

# Display post-installation status
Display-StatusTable -stage "Post-Installation"

Write-Host "Setup completed."
