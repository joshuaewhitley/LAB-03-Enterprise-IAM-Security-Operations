
# LAB-03 — Enterprise IAM & Security Operations

**Windows Server 2025 | Active Directory | PowerShell | Identity Security | Windows Security Event Analysis**

An isolated, hands-on cybersecurity lab demonstrating Active Directory identity administration, least-privilege assessments, security event investigation, and reusable PowerShell automation.

**Security Workflow:** Configure → Assess → Investigate → Remediate → Verify → Document

---

## Project Highlights

| Area | Completed Work | Evidence |
|---|---|---|
| Active Directory | Deployed Windows Server 2025 domain controller, internal DNS, four OUs, five security groups, and four fictional identities | Lab architecture |
| IAM-001 | Detected and removed obsolete Finance membership after an IT department transfer | Finding report and screenshots |
| INC-001 | Investigated a controlled authentication failure using Events 4625 and 4771 | Investigation report and screenshots |
| PowerShell Toolkit | Built and tested access-review, failed-logon collection, and department-group compliance workflows | Three scripts and toolkit documentation |

## Quick Navigation

- **[IAM-001 — Excessive Access Following Department Transfer](04-Security-Findings/IAM-001/finding-report.md)** — Finding, risk assessment, remediation, and before/after evidence.
- **[INC-001 — Failed Authentication Investigation](05-SOC-Investigations/INC-001/investigation-report.md)** — Authentication event analysis, evidence export validation, and supporting screenshots.
- **[PowerShell Security Toolkit](06-PowerShell-Toolkit/README.md)** — Three scripts, execution instructions, validation results, and limitations.

---

## Lab Architecture

| Component | Configuration |
|---|---|
| Hypervisor | Microsoft Hyper-V, Generation 2 VM |
| Host operating system | Windows 11 Pro |
| Domain controller | WL-DC01 |
| Server operating system | Windows Server 2025 Standard Evaluation |
| Active Directory domain | corp.whitleylab.test |
| NetBIOS domain | CORP |
| Virtual network | LAB-ISOLATED, internal switch |
| Network subnet | 10.10.10.0/24 |
| Host adapter IP | 10.10.10.1 |
| Domain controller IP | 10.10.10.10 |
| Infrastructure services | Active Directory Domain Services, DNS |
| Security tools | PowerShell, ADUC, auditpol, Windows Security Event Log |

### Network Architecture

```text
Windows 11 Pro - Hyper-V Host
|
+-- LAB-ISOLATED (Internal Virtual Switch)
    |
    +-- Network: 10.10.10.0/24
    |
    +-- Host Adapter: 10.10.10.1
    |
    +-- WL-DC01: 10.10.10.10
        |
        +-- Windows Server 2025
        +-- Active Directory Domain Services
        +-- DNS Server
        +-- Windows Security Event Logs
```

The internal lab network was configured without a default gateway, separating the initial lab segment from the physical home network.

### Active Directory Configuration

**Organizational Units**

- Employees
- Contractors
- SecurityGroups
- ServiceAccounts

**Global Security Groups**

| Group | Purpose |
|---|---|
| GG-Employees | Baseline employee access |
| GG-Finance | Finance department membership |
| GG-IT | IT department membership |
| GG-Security | Security team membership |
| GG-Contractors | Contractor identities |

### Fictional Test Identities

| Identity | Department | Lab Scenario |
|---|---|---|
| Alex Morgan | IT | Employee onboarding |
| Jordan Lee | Finance | Authentication investigation |
| Taylor Reed | Finance → IT | Department transfer and remediation |
| Casey Smith | Contractor | Contractor provisioning |

All identities were created for the isolated laboratory.

---

## Security Finding — IAM-001

### Excessive Access Following Department Transfer

**Category:** Identity and Access Management  
**Risk Rating:** Medium (scenario-based)  
**Status:** Remediated — Directory-Level Verification Complete

### Scenario

During a simulated Finance-to-IT department transfer, `taylor.reed` received the required `GG-IT` membership but retained membership in `GG-Finance`.

This violated the defined lab access requirements and represented a potential least-privilege concern.

### Detection

PowerShell was used to inspect the employee's department and Active Directory group memberships.

**Observed Before Remediation**

```text
Name       : Taylor Reed
Department : IT
Groups     : GG-IT, GG-Finance, GG-Employees
```

### Remediation

The obsolete Finance membership was removed using:

```powershell
Remove-ADGroupMember -Identity "GG-Finance" `
    -Members "taylor.reed" `
    -Confirm:$false
```

### Verification

A separate Active Directory group-membership query confirmed:

```text
GG-Employees
GG-IT
```

**Outcome:** The excessive directory-level group membership was successfully removed while required memberships remained assigned.

**Limitation:** Access to protected Finance applications or file shares was not tested.

**[View IAM-001 Investigation Report and Evidence →](04-Security-Findings/IAM-001/finding-report.md)**

---

## Security Investigation — INC-001

### Failed Authentication Investigation

**Category:** Security Operations / Authentication Monitoring  
**Classification:** Authorized Lab Simulation  
**Status:** Investigation Complete — Event Evidence Validated

### Scenario

A deliberately incorrect password was supplied for fictional account `CORP\jordan.lee` using the Windows `runas` command.

```powershell
runas /user:CORP\jordan.lee "cmd.exe"
```

Windows returned error `1326`, indicating that the username or password was incorrect.

### Security Events Identified

| Event / Field | Observed Value |
|---|---|
| Event ID 4625 | Failed interactive Windows logon |
| Event ID 4771 | Kerberos pre-authentication failure |
| Target account | CORP\jordan.lee |
| Event timestamp | October 12, 2026, 18:45:05 |
| Logon type | 2 — Interactive |
| Authentication package | Negotiate |
| NTSTATUS | 0xC000006D |
| Substatus | 0xC000006A |
| Kerberos failure code | 0x18 |
| Source workstation | WL-DC01 |
| Source address | ::1 (IPv6 loopback) |

### Technical Analysis

Event 4625 documented an unsuccessful Windows logon with an incorrect-password substatus.

Event 4771 recorded a Kerberos pre-authentication failure consistent with invalid credentials.

The matching account, timestamp, failure codes, and local source context were consistent with the controlled test.

The events provide complementary authentication telemetry. They do not establish two distinct authentication attempts or prove a shared transaction identifier.

### Evidence Collection and Validation

PowerShell was used to retrieve relevant Windows Security events and export them to private CSV and TXT files.

The investigation CSV was independently validated.

| Event ID | Verified Count |
|---|---:|
| 4625 | 1 |
| 4771 | 1 |
| **Total** | **2** |

**Outcome:** The controlled authentication failure was identified, investigated, correlated, and documented using native Windows security telemetry.

**Limitation:** This was an authorized simulation, not a confirmed malicious security incident.

**[View INC-001 Investigation Report and Evidence →](05-SOC-Investigations/INC-001/investigation-report.md)**

---

## PowerShell Security Toolkit

Three reusable PowerShell scripts were developed to automate common security administration and investigation tasks in the isolated lab.

| Script | Function | Lab Validation |
|---|---|---|
| [Get-ADAccessReview.ps1](06-PowerShell-Toolkit/Get-ADAccessReview.ps1) | Export user information and direct AD group memberships | Seven directory accounts exported and reviewed |
| [Get-FailedLogons.ps1](06-PowerShell-Toolkit/Get-FailedLogons.ps1) | Collect Windows Security Events 4625 and 4771 | Six records exported during a 48-hour query |
| [Test-ADAccessCompliance.ps1](06-PowerShell-Toolkit/Test-ADAccessCompliance.ps1) | Identify missing or excessive departmental memberships | Baseline, simulated finding, remediation, and retesting completed |

### Access Review Automation

The access-review script exports:

- User and account names
- Department information
- Account-enabled status
- Direct Active Directory group memberships

**Validated Result:** Seven directory accounts were exported, including four fictional lab identities and three built-in accounts.

### Authentication Event Collection

The failed-logon collector queries Windows Security Events 4625 and 4771 using a configurable lookback period.

**Validated Result:**

| Event ID | Records |
|---|---:|
| 4625 | 5 |
| 4771 | 1 |
| **Total** | **6** |

These records were collected across the selected 48-hour window and do not necessarily represent six separate authentication attempts.

### Automated Access Compliance

The access-compliance script compares direct Active Directory group memberships against predefined lab department requirements.

The validation workflow included:

1. Confirming all four fictional identities passed the initial baseline.
2. Temporarily assigning `taylor.reed` to the unauthorized `GG-Finance` group.
3. Detecting the excessive membership with a `Review Required` result.
4. Removing the temporary Finance membership through a separate administrative command.
5. Rerunning the script and confirming all four accounts returned `Compliant`.
6. Independently verifying that Taylor retained only `GG-Employees` and `GG-IT` among the lab's departmental groups.

The script itself is read-only and does not modify Active Directory.

**Validation note:** The compliance workflow was successfully tested using the original script logic. The subsequently reformatted published revision should be rerun before claiming that exact revision has been separately validated.

**[View PowerShell Toolkit Documentation →](06-PowerShell-Toolkit/README.md)**

---

## Security Practices Demonstrated

**Identity Lifecycle Management**

Provision fictional identities, manage departmental assignments, and reconcile memberships following role changes.

**Least Privilege**

Identify excessive security-group memberships and independently verify targeted remediation.

**Authentication Monitoring**

Configure relevant auditing, collect Windows Security events, and analyze authentication failures.

**Event Correlation**

Compare target identities, event timestamps, source context, and failure codes without overstating causal relationships.

**Audit Readiness**

Generate structured exports, validate record counts, document findings, and preserve evidence-handling limitations.

**PowerShell Automation**

Develop repeatable workflows supporting access reviews, event collection, and departmental compliance assessments.

---

## Repository Structure

```text
LAB-03-Enterprise-IAM-Security-Operations/
|
+-- README.md
|
+-- 04-Security-Findings/
|   +-- IAM-001/
|       +-- finding-report.md
|       +-- evidence/
|           +-- IAM-001-Before.png
|           +-- IAM-001-After.png
|
+-- 05-SOC-Investigations/
|   +-- INC-001/
|       +-- investigation-report.md
|       +-- evidence/
|           +-- README.md
|           +-- INC-001-Authentication-Failure.png
|           +-- INC-001-Security-Events.png
|           +-- INC-001-Export-Validation.png
|
+-- 06-PowerShell-Toolkit/
    +-- README.md
    +-- Get-ADAccessReview.ps1
    +-- Get-FailedLogons.ps1
    +-- Test-ADAccessCompliance.ps1
```

### Repository Navigation

| Resource | Description |
|---|---|
| [IAM-001 Finding Report](04-Security-Findings/IAM-001/finding-report.md) | Excessive access assessment, remediation, and evidence |
| [INC-001 Investigation Report](05-SOC-Investigations/INC-001/investigation-report.md) | Authentication event investigation and evidence |
| [PowerShell Toolkit README](06-PowerShell-Toolkit/README.md) | Script documentation, execution instructions, and testing |
| [AD Access Review Script](06-PowerShell-Toolkit/Get-ADAccessReview.ps1) | Active Directory inventory and direct membership export |
| [Failed Logon Collector](06-PowerShell-Toolkit/Get-FailedLogons.ps1) | Windows Security event collection |
| [AD Compliance Assessment](06-PowerShell-Toolkit/Test-ADAccessCompliance.ps1) | Departmental access-rule assessment |

---

## Scope, Evidence Handling, and Limitations

LAB-03 is a controlled cybersecurity training environment, not a production enterprise deployment or real-world incident response case.

- All test identities are fictional.
- Authentication failures were deliberately generated.
- IAM checks evaluate direct AD group memberships rather than nested memberships, approved access exceptions, or effective permissions on protected resources.
- Departmental compliance rules are specific to the simulated environment.
- Users without a mapped department are excluded from the current compliance assessment.
- The published INC-001 evidence screenshots demonstrate the authentication failure, event collection commands, and export validation. They do not display every detailed field from the individual Security events.
- CSV record-count verification is not cryptographic integrity validation.
- SHA-256 hashing and a formal chain-of-custody record were not performed during the original investigation.
- Original Security event exports and access-review CSV files remain private.
- Only reviewed laboratory screenshots and reusable scripts are published.
- SIEM integration, EDR deployment, production authorization testing, and broader incident containment were outside the completed project scope.

---

## Project Outcome

LAB-03 combines Active Directory administration, identity lifecycle management, least-privilege assessment, Windows authentication investigation, evidence-based remediation, and PowerShell security automation within one documented cybersecurity laboratory.

The project demonstrates the ability to configure an isolated security environment, identify potential access-control weaknesses, investigate authentication telemetry, validate corrective actions, and document technical findings with supporting evidence.

**Focus Areas:** Identity Security | Security Operations | PowerShell | Windows Administration | Audit Readiness

**Environment:** Isolated and authorized cybersecurity training lab using fictional identities.
