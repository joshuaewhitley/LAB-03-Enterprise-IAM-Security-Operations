# LAB-03 - Failed Authentication Event Collector
# Purpose: Collect Windows Security Events 4625 and 4771
# Environment: Authorized lab only
# Operation: Read-only event query and CSV export

param(
    [int]$HoursBack = 48
)

$OutputFolder = "C:\CyberLab\Evidence\LAB-03\FailedLogons"

New-Item -ItemType Directory -Path $OutputFolder -Force |
    Out-Null

$StartTime = (Get-Date).AddHours(-$HoursBack)
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$OutputFile = Join-Path $OutputFolder `
    "FailedLogons-$Timestamp.csv"

$Events = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625,4771
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue
)

if ($Events.Count -eq 0) {
    Write-Host "No matching events found." -ForegroundColor Yellow
    return
}

$Events |
    Select-Object TimeCreated,Id,MachineName,
        ProviderName,Message |
    Export-Csv -Path $OutputFile -NoTypeInformation

Write-Host "Authentication events exported:" -ForegroundColor Green
Write-Host $OutputFile

$Events |
    Group-Object Id |
    Select-Object Name,Count |
    Format-Table -AutoSize
