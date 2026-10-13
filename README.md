# LAB-03 — Enterprise IAM & Security Operations

**Windows Server 2025 | Active Directory | PowerShell | Identity Security | Security Event Analysis**

A hands-on cybersecurity lab demonstrating enterprise identity administration, security control validation, least-privilege remediation, and Windows authentication event investigation.

## Project Overview

Designed and deployed an isolated Windows Server 2025 Active Directory environment using Microsoft Hyper-V.

The project simulates enterprise identity management and security operations workflows, including employee onboarding, department transfers, access reviews, security misconfiguration remediation, and authentication event analysis.

The primary objective is to demonstrate an evidence-based security workflow:

**Configure → Monitor → Investigate → Remediate → Verify → Document**

## Verified Project Outcomes

- Deployed and validated a Windows Server 2025 Active Directory domain controller.
- Configured an isolated Hyper-V network with static addressing and internal DNS.
- Created four organizational units and five Global Security Groups.
- Provisioned four fictional identities with department-based group memberships.
- Identified and remediated excessive access following a simulated employee transfer (IAM-001).
- Generated and investigated a controlled authentication failure using Windows Security Event IDs 4625 and 4771 (INC-001).
- Used PowerShell to automate identity administration, audit security configurations, and export investigative evidence.
- Validated the incident evidence export against the original Security Event Log results.

## Lab Architecture

| Component | Configuration |
|---|---|
| Virtualization | Microsoft Hyper-V — Generation 2 VM |
| Operating system | Windows Server 2025 Standard Evaluation |
| Domain controller | WL-DC01 |
| Active Directory domain | corp.whitleylab.test |
| NetBIOS domain | CORP |
| Domain controller IP | 10.10.10.10 |
| Host lab IP | 10.10.10.1 |
| Network | LAB-ISOLATED — Internal virtual switch |
| Services | Active Directory Domain Services, DNS |
| Security tools | PowerShell, ADUC, auditpol, Windows Security Event Log |

### Network Architecture

```text
Windows 11 Pro — Hyper-V Host
    |
    | LAB-ISOLATED
    | 10.10.10.0/24
    |
    +-- Host: 10.10.10.1
    |
    +-- WL-DC01: 10.10.10.10
         |
         +-- Windows Server 2025
         +-- Active Directory Domain Services
         +-- DNS Server
         +-- Security Event Logs
```

The environment uses an internal virtual switch without a default gateway, keeping the initial lab network separate from the physical home network.

## Active Directory and Identity Management

### Organizational Units

Created four custom organizational units:

- Employees
- Contractors
- SecurityGroups
- ServiceAccounts

Each OU was configured with protection against accidental deletion.

### Security Groups

Created five Global Security Groups:

| Group | Purpose |
|---|---|
| GG-Employees | Baseline employee membership |
| GG-Finance | Finance department |
| GG-IT | IT department |
| GG-Security | Security team |
| GG-Contractors | Contractor identities |

### Test Identity Provisioning

Provisioned four fictional Active Directory identities:

| Identity | Department | Scenario |
|---|---|---|
| Alex Morgan | IT | Employee onboarding |
| Jordan Lee | Finance | Authentication investigation |
| Taylor Reed | Finance → IT | Department transfer and access review |
| Casey Smith | Contractor | Contractor identity provisioning |

Used PowerShell to create and manage identities, assign group memberships, update department attributes, and verify configurations.

## IAM-001 — Excessive Access Following Department Transfer

**Category:** Identity and Access Management  
**Classification:** Simulated security finding  
**Status:** Remediated and verified

### Scenario

A fictional employee transferred from Finance to IT. The employee received the new IT group membership but retained an unnecessary Finance security-group membership.

This represented a potential least-privilege violation caused by privilege accumulation.

### Detection

Used PowerShell to review the employee's Active Directory department and security-group memberships.

**Observed configuration:**

```text
Name       : Taylor Reed
Department : IT
Groups     : GG-Employees, GG-Finance, GG-IT
```

### Risk Assessment

Retained department memberships can create unnecessary authorization paths and increase the risk of access to resources unrelated to an employee's current responsibilities.

The lab confirmed excessive directory-group membership, not actual access to a protected Finance resource.

### Remediation

Removed the unnecessary membership:

```powershell
Remove-ADGroupMember -Identity "GG-Finance" -Members "taylor.reed" -Confirm:$false
```

### Verification

Performed a post-remediation membership review.

**Verified result:**

```text
GG-Employees
GG-IT
```

**Outcome:** The employee's directory-level group memberships were aligned with the intended IT role.

### Detailed Investigation

[IAM-001 — Access Review and Remediation](04-Security-Findings/IAM-001/finding-report.md)

*Detailed report to be added.*

## INC-001 — Failed Authentication Investigation

**Category:** Security Operations / Authentication Monitoring  
**Classification:** Controlled security simulation  
**Status:** Investigation completed

### Scenario

Generated a controlled incorrect-password attempt against a fictional Active Directory account to validate authentication failure auditing and investigate the resulting security events.

### Audit Configuration

Enabled success and failure auditing for:

- Kerberos Authentication Service
- Kerberos Service Ticket Operations
- Credential Validation

Verified the settings using:

```powershell
auditpol /get /category:"Account Logon"
```

### Authentication Test

Used the following command:

```powershell
runas /user:CORP\jordan.lee "cmd.exe"
```

Intentionally supplied an incorrect password to generate a failed authentication.

The command returned Windows error 1326.

### Security Events Identified

| Event field | Verified result |
|---|---|
| Event ID 4625 | Failed interactive logon |
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

The Windows Security events indicated an unsuccessful local authentication attempt.

Event 4625 documented a failed logon with an incorrect-password substatus.

Event 4771 documented a Kerberos pre-authentication failure consistent with invalid credentials.

The IPv6 loopback address indicated that the authentication request originated locally on the domain controller.

The evidence was consistent with the intentionally generated test; no external origin was identified.

### Evidence Collection

Queried the Windows Security Event Log using PowerShell and exported the resulting events in CSV and text formats.

Validated the export:

| Event ID | Verified count |
|---|---:|
| 4625 | 1 |
| 4771 | 1 |
| **Total** | **2** |

The two events corresponded to the controlled authentication scenario and do not establish two separate login attempts.

### Security Analyst Assessment

One failed login does not independently indicate malicious activity.

In a production environment, the investigation would include reviewing authentication frequency, account activity, source systems, lockout events, and relevant security alerts.

### Detailed Investigation

[INC-001 — Authentication Event Investigation](05-SOC-Investigations/INC-001/investigation-report.md)

*Detailed report to be added.*

## PowerShell Skills Demonstrated

- Active Directory user provisioning with `New-ADUser`
- Attribute management with `Set-ADUser`
- Security-group creation with `New-ADGroup`
- Membership assignment with `Add-ADGroupMember`
- Access remediation with `Remove-ADGroupMember`
- Identity auditing with `Get-ADUser` and `Get-ADGroupMember`
- Authentication auditing with `auditpol`
- Security event investigation with `Get-WinEvent`
- Evidence export using `Export-Csv` and `Out-File`

## Security Principles Demonstrated

**Least privilege:** Users should retain only the access required for their current responsibilities.

**Identity lifecycle management:** Onboarding and department changes should include appropriate provisioning and removal of obsolete access.

**Security monitoring:** Authentication failure auditing must be enabled and validated to provide reliable investigative evidence.

**Event correlation:** Multiple event records may describe different stages of the same authentication attempt.

**Evidence-based remediation:** Security findings should include observed evidence, a clearly defined risk, corrective action, and post-remediation verification.

## Scope and Limitations

This project is a controlled, isolated cybersecurity lab intended for professional development.

- All test identities are fictional.
- Authentication failures were deliberately generated.
- The lab is not a production enterprise deployment.
- Group membership remediation was verified at the directory level; protected-resource authorization testing was not performed.
- SIEM integration, EDR deployment, and broader incident containment were outside the completed scope.
- Raw security logs and sensitive configuration details are retained privately. Public evidence will be sanitized.

## Repository Documentation

| Section | Contents |
|---|---|
| 01-Infrastructure | Hyper-V, networking and server configuration |
| 02-Active-Directory | AD DS, organizational units and security groups |
| 03-IAM-Lifecycle | Identity provisioning and lifecycle workflows |
| 04-Security-Findings | IAM-001 finding and remediation |
| 05-SOC-Investigations | INC-001 event investigation |
| 06-PowerShell-Scripts | Administrative and security investigation scripts |
| 07-Interview-Evidence | Sanitized screenshots and project summary |

Supporting files and detailed reports will be added as the repository is populated.

## Project Outcome

Successfully built an operational Active Directory security lab and completed two evidence-backed security exercises demonstrating IAM administration, least-privilege remediation, Windows authentication investigation, and PowerShell security automation.

**Project focus:** Identity Security | Security Operations | Windows Administration | PowerShell | Audit Readiness
