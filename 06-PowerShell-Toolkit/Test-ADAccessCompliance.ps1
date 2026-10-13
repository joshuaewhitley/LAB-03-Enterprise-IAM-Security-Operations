
# LAB-03 - Active Directory Access Compliance Assessment
# Purpose: Identify departmental group-membership inconsistencies.
# Environment: Authorized Active Directory lab only.
# Operation: Read-only assessment and CSV report export.

Import-Module ActiveDirectory -ErrorAction Stop

# Define the output directory.
$OutputFolder = "C:\CyberLab\Evidence\LAB-03\Compliance"

New-Item -ItemType Directory -Path $OutputFolder -Force |
    Out-Null

# Define lab-specific department access rules.
$Rules = @{
    "IT" = @{
        Required  = @("GG-Employees", "GG-IT")
        Forbidden = @("GG-Finance")
    }

    "Finance" = @{
        Required  = @("GG-Employees", "GG-Finance")
        Forbidden = @("GG-IT")
    }

    "Contractor" = @{
        Required  = @("GG-Contractors")
        Forbidden = @("GG-Employees", "GG-IT", "GG-Finance")
    }
}

# Retrieve users and exclude accounts without a mapped department.
$Users = Get-ADUser `
    -Filter * `
    -SearchBase "DC=corp,DC=whitleylab,DC=test" `
    -Properties Department,MemberOf |
    Where-Object {
        if ([string]::IsNullOrWhiteSpace($_.Department)) {
            $false
        }
        else {
            $Rules.ContainsKey($_.Department)
        }
    }

# Evaluate each user's direct group memberships.
$Results = foreach ($User in $Users) {

    $Groups = @(
        $User.MemberOf | ForEach-Object {
            (Get-ADGroup $_ -ErrorAction Stop).Name
        }
    )

    $Rule = $Rules[$User.Department]

    # Identify required groups that are missing.
    $Missing = @(
        $Rule.Required | Where-Object {
            $_ -notin $Groups
        }
    )

    # Identify prohibited departmental groups.
    $Excessive = @(
        $Rule.Forbidden | Where-Object {
            $_ -in $Groups
        }
    )

    # Assign compliance status.
    $Status = if (
        $Missing.Count -gt 0 -or
        $Excessive.Count -gt 0
    ) {
        "Review Required"
    }
    else {
        "Compliant"
    }

    # Create a structured assessment result.
    [PSCustomObject]@{
        User            = $User.SamAccountName
        Department      = $User.Department
        Status          = $Status
        MissingGroups   = $Missing -join "; "
        ExcessiveGroups = $Excessive -join "; "
    }
}

# Generate a timestamped CSV report.
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$OutputFile = Join-Path $OutputFolder `
    "AD-Compliance-$Timestamp.csv"

$Results |
    Export-Csv -Path $OutputFile -NoTypeInformation

# Display the results.
$Results |
    Format-Table -AutoSize

Write-Host "Compliance report exported:" -ForegroundColor Green
Write-Host $OutputFile
