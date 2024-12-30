# Log Monitoring Script

param (
    [string]$LogFilePath = "monitor_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [int[]]$EventIDs = @(4624, 4625, 4672),  # Successful login, failed login, privilege escalation
    [switch]$Verbose,
    [string]$EmailRecipient = "admin@example.com",
    [string]$EmailSender = "monitor@example.com",
    [string]$SmtpServer = "smtp.example.com"
)

# Enable verbose output if specified
if ($Verbose) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

# Validate email parameters
if ($EmailRecipient -and $EmailSender -and $SmtpServer) {
    $emailEnabled = $true
} else {
    $emailEnabled = $false
    Write-Warning "Email notifications are disabled due to missing parameters."
}

# Fetch events from the Security Log
Write-Verbose "Fetching Security Events for Event IDs: $($EventIDs -join ', ')..."
try {
    $timeFilter = (Get-Date).AddMinutes(-30)
    $events = Get-WinEvent -LogName Security | Where-Object {
        $_.Id -in $EventIDs -and $_.TimeCreated -ge $timeFilter
    }
} catch {
    Write-Error "Failed to fetch events from the Security Log: $_"
    exit 1
}

# Display and save the logs
Write-Output "Suspicious Events:"
$events | ForEach-Object {
    $user = $_.Properties | Where-Object { $_.Value -like "*User*" } | Select-Object -ExpandProperty Value
    $ip = $_.Properties | Where-Object { $_.Value -match "(\d{1,3}\.){3}\d{1,3}" } | Select-Object -ExpandProperty Value
    $logEntry = "Time: $($_.TimeCreated), Event ID: $($_.Id), User: $user, IP: $ip, Message: $($_.Message)"
    
    if ($_.Id -eq 4672) {
        Write-Host $logEntry -ForegroundColor Red
    } else {
        Write-Host $logEntry -ForegroundColor Green
    }
    
    Add-Content -Path $LogFilePath -Value $logEntry

    # Send email notification for critical events
    if ($emailEnabled -and $_.Id -eq 4672) {
        $subject = "Critical Event Detected: $($_.Id)"
        $body = @"
A critical event has been detected on $($env:COMPUTERNAME):

$logEntry

Please investigate immediately.
"@
        Send-MailMessage -To $EmailRecipient -From $EmailSender -Subject $subject -Body $body -SmtpServer $SmtpServer
    }
}

# Log rotation
if ((Get-Item $LogFilePath).Length -gt 10MB) {
    Rename-Item $LogFilePath "$($LogFilePath)_old"
}

Write-Output "Monitoring complete. Logs saved to $LogFilePath."