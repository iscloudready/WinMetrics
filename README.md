# WinMetrics
WinMetrics Setup: Automated Installation and Configuration of Windows Exporter and Prometheus


# WinMetrics Setup: Automated Installation and Configuration of Windows Exporter and Prometheus

## Overview
**WinMetrics Setup** is an automated script designed to install and configure [Windows Exporter](https://github.com/prometheus-community/windows_exporter) and [Prometheus](https://prometheus.io/) on Windows with the dashboard [dashboard](https://grafana.com/grafana/dashboards/15620-windows-node-exporter/). 
[windows-exporter-dashboard](https://grafana.com/grafana/dashboards/14694-windows-exporter-dashboard/)
[windows-exporter-dashboard-2024](https://grafana.com/grafana/dashboards/20763-windows-exporter-dashboard-2024/)
[prometheus-dashboard](https://grafana.com/grafana/dashboards/14451-windows-exporter-for-prometheus-dashboard-en/)
The script sets up Prometheus to monitor metrics from Windows Exporter and itself, and manages firewall rules for secure access. This project simplifies the process by automating installation, configuration, and service management.

## Features
- Downloads and installs Windows Exporter and Prometheus.
- Configures Prometheus to scrape metrics from Windows Exporter and its own endpoint.
- Manages firewall rules for Windows Exporter and Prometheus ports.
- Dynamic retrieval of system IP and customizable configuration paths.
- Pre- and post-installation status checks for component visibility.

## Prerequisites
- Windows PowerShell (version 5.1 or newer)
- Administrator privileges to configure firewall rules and install services

## Usage
1. Clone this repository or copy the script to your local machine.
2. Open PowerShell as Administrator.
3. Run the script:

    ```powershell
    .\WinMetricsSetup.ps1
    ```

## Script Details
The script follows these steps:
1. **Pre-Installation Check**: Displays the current status of each component.
2. **Windows Exporter Installation**: Downloads and installs Windows Exporter if not already installed.
3. **Firewall Configuration**: Adds firewall rules for Windows Exporter and Prometheus.
4. **Prometheus Installation**: Downloads Prometheus, configures it, and starts it as a background process.
5. **Post-Installation Check**: Displays the status of each component and endpoint reachability.

### Dynamic Configuration
The script uses dynamic paths and customizable variables for flexible configuration. System IP is detected automatically.

## Configuration
- **Windows Exporter Port**: `9182`
- **Prometheus Port**: `9090`
- **File Paths**: Set for the default installation in `C:\Program Files`

## Output
The script provides a table of statuses for each component before and after installation. Logs for Prometheus are stored at:

```
C:\Program Files\Prometheus\prometheus.log
```

## Example
Upon completion, you should see a status table showing all components as installed and running, with URLs for Windows Exporter and Prometheus displayed.

### Example URLs
- **Windows Exporter Metrics**: `http://<System IP>:9182/metrics`
- **Prometheus Metrics**: `http://<System IP>:9090/metrics`

## Troubleshooting
- Ensure PowerShell is running as Administrator.
- Verify that the firewall rules are configured correctly if endpoints are unreachable.
- Check the Prometheus log file for errors if Prometheus does not start.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
