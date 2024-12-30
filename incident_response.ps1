param (
    [int]$FailedLoginThreshold = 5,  # Number of failed logins before action is taken
    [int]$TimeFrameMinutes = 30,    # Time frame to check for failed logins
    [string]$LogFilePath = "incident_response_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [switch]$Verbose,
    [string]$EmailRecipient = "admin@example.com",
    [string]$EmailSender = "incident-response@example.com",
    [string]$SmtpServer = "smtp.example.com"
)

# Enable verbose output if specified
if ($Verbose) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

# Function to log actions
function Log-Action {
    param (
        [string]$Message
    )
    Add-Content -Path $LogFilePath -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message"
    Write-Output $Message
}

# Validate email parameters
if ($EmailRecipient -and $EmailSender -and $SmtpServer) {
    $emailEnabled = $true
} else {
    $emailEnabled = $false
    Log-Action "Email notifications are disabled due to missing parameters."
}

# Detect compromised accounts
Log-Action "Starting incident response process..."
$timeFilter = (Get-Date).AddMinutes(-$TimeFrameMinutes)
$failedLogins = Get-WinEvent -LogName Security -FilterHashtable @{
    Id = 4625
    StartTime = $timeFilter
}

# Group failed logins by user and count occurrences
$compromisedAccounts = $failedLogins | Group-Object { $_.Properties[5].Value } | Where-Object {
    $_.Count -ge $FailedLoginThreshold
}

# Disable compromised accounts and isolate machines
foreach ($account in $compromisedAccounts) {
    $username = $account.Name
    try {
        Disable-ADAccount -Identity $username
        Log-Action "Disabled account: $username due to $($account.Count) failed logins."

        # Isolate machine (example: disable network adapter)
        $machineName = $account.Group | Select-Object -ExpandProperty MachineName -ErrorAction SilentlyContinue
        if ($machineName) {
            Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $machineName | Where-Object { $_.NetEnabled -eq $true } | ForEach-Object { $_.Disable() }
            Log-Action "Isolated machine: $machineName"
        } else {
            Log-Action "Machine name not found for account: $username"
        }

        # Send email notification for disabled accounts and isolated machines
        if ($emailEnabled) {
            $subject = "Incident Response Action: $username"
            $body = @"
An account has been disabled and a machine has been isolated due to repeated failed login attempts on $($env:COMPUTERNAME):

Account: $username
Failed Logins: $($account.Count)
Machine: $machineName
Time: $(Get-Date)

Please investigate immediately.
"@
            Send-MailMessage -To $EmailRecipient -From $EmailSender -Subject $subject -Body $body -SmtpServer $SmtpServer
        }
    } catch {
        Log-Action "Failed to disable account $username or isolate machine $machineName: $_"
    }
}

# Generate summary report
$reportPath = "incident_response_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$reportContent = Get-Content -Path $LogFilePath
Add-Content -Path $reportPath -Value $reportContent
Log-Action "Generated summary report: $reportPath"

Log-Action "Incident response complete. Logs saved to $LogFilePath."