# LAB-03 - Active Directory Access Review
# Purpose: Export user access information for review.
# Environment: Authorized lab only.

Import-Module ActiveDirectory -ErrorAction Stop

$OutputFolder = "C:\CyberLab\Evidence\LAB-03\AccessReviews"

New-Item -ItemType Directory -Path $OutputFolder -Force |
    Out-Null

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$OutputFile = Join-Path $OutputFolder `
    "AD-AccessReview-$Timestamp.csv"

Get-ADUser -Filter * -SearchBase "DC=corp,DC=whitleylab,DC=test" `
    -Properties Department,Enabled,MemberOf |
    Select-Object Name,SamAccountName,Department,Enabled,
        @{Name="SecurityGroups";Expression={
            ($_.MemberOf |
                ForEach-Object {
                    (Get-ADGroup $_ -ErrorAction Stop).Name
                } |
                Sort-Object) -join "; "
        }} |
    Export-Csv -Path $OutputFile -NoTypeInformation

Write-Host "Access review exported:" -ForegroundColor Green
Write-Host $OutputFile
