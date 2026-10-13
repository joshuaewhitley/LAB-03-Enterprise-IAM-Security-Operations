# LAB-03 — PowerShell Security Toolkit

**Project:** Enterprise IAM & Security Operations  
**Environment:** Windows Server 2025 / Active Directory / Microsoft Hyper-V  
**Domain:** `corp.whitleylab.test`  
**Focus Areas:** Identity & Access Management (IAM), Security Operations, PowerShell Automation, and Audit Readiness

## Overview

This toolkit contains three PowerShell scripts developed as part of LAB-03, an isolated Active Directory security laboratory.

The objective was to automate common security administration and investigation tasks, assess identity access against defined requirements, and produce evidence that supports security reviews.

The toolkit demonstrates practical experience with:

- Active Directory administration and group membership analysis
- Identity lifecycle and least-privilege validation
- Automated security configuration assessments
- Windows Security Event 4625 and 4771 collection
- Structured CSV reporting and evidence validation
- Security investigation documentation

## PowerShell Toolkit

| Script | Purpose | Validation |
|---|---|---|
| [Get-ADAccessReview.ps1](Get-ADAccessReview.ps1) | Export account details and direct group memberships | Tested |
| [Get-FailedLogons.ps1](Get-FailedLogons.ps1) | Collect failed Windows authentication events | Tested |
| [Test-ADAccessCompliance.ps1](Test-ADAccessCompliance.ps1) | Flag missing or excessive departmental access | Baseline and detection/remediation workflow tested |

---

## 1. Active Directory Access Review

**Script:** [Get-ADAccessReview.ps1](Get-ADAccessReview.ps1)

### Objective

Generate an Active Directory access-review report containing account names, usernames, departments, enabled states, and direct group memberships.

### Execution

```powershell
.\Get-ADAccessReview.ps1
```

### Validated Results

The script successfully generated a timestamped CSV report containing seven directory accounts, including four fictional lab identities and three built-in domain accounts.

The results were reviewed to confirm expected departmental group memberships.

**Output:** `C:\CyberLab\Evidence\LAB-03\AccessReviews\`

### Security Relevance

Supports identity inventory, access reviews, user lifecycle assessments, and audit evidence preparation.

### Limitations

The script reports direct group memberships only. It does not expand nested memberships, confirm formal access approvals, or test access to protected applications and resources.

---

## 2. Windows Failed Authentication Collector

**Script:** [Get-FailedLogons.ps1](Get-FailedLogons.ps1)

### Objective

Retrieve authentication-related Windows Security events and export results for investigation.

The script queries:

- **Event ID 4625:** Failed Windows logon
- **Event ID 4771:** Kerberos pre-authentication failure

### Execution

```powershell
.\Get-FailedLogons.ps1 -HoursBack 48
```

### Validated Results

The script retrieved six Security event records within the selected 48-hour window:

| Event ID | Exported records |
|---|---:|
| 4625 | 5 |
| 4771 | 1 |
| **Total** | **6** |

The CSV was independently read back to verify the exported event identifiers, timestamps, and source machine.

Two records had timestamps consistent with the controlled authentication test documented in INC-001.

**Output:** `C:\CyberLab\Evidence\LAB-03\FailedLogons\`

### Security Relevance

Supports SOC investigations, authentication monitoring, event collection, and security evidence preparation.

### Limitations

The script does not determine whether activity is malicious or whether multiple event records represent distinct authentication attempts. Its current error handling may also obscure certain event-query failures.

---

## 3. Active Directory Access Compliance Assessment

**Script:** [Test-ADAccessCompliance.ps1](Test-ADAccessCompliance.ps1)

### Objective

Compare user departments against predefined lab access requirements to identify missing or excessive Active Directory group memberships.

### Lab Access Rules

| Department | Required groups | Groups flagged as excessive |
|---|---|---|
| IT | GG-Employees, GG-IT | GG-Finance |
| Finance | GG-Employees, GG-Finance | GG-IT |
| Contractor | GG-Contractors | GG-Employees, GG-IT, GG-Finance |

These rules are specific to the simulated lab environment.

### Execution

```powershell
.\Test-ADAccessCompliance.ps1
```

### Validation Workflow

**Baseline:** Four fictional Active Directory accounts passed the configured department-based access checks.

**Detection:** An intentionally introduced `GG-Finance` membership for `taylor.reed`, whose department was IT, was flagged as `Review Required`.

**Remediation:** The unnecessary Finance membership was removed using a separate PowerShell command.

**Retesting:** The compliance assessment returned `Compliant` for all four accounts.

**Independent verification:** An Active Directory membership query confirmed that Taylor Reed retained only `GG-Employees` and `GG-IT` among the lab's `GG-*` groups.

**Output:** `C:\CyberLab\Evidence\LAB-03\Compliance\`

### Security Relevance

Supports least-privilege reviews, Joiner–Mover–Leaver controls, security configuration assessments, and remediation validation.

### Limitations

The script checks direct group memberships against configured lab rules. Accounts without a mapped Department value are excluded.

A `Compliant` result means the evaluated memberships match these specific rules. It does not establish complete enterprise access compliance or confirm resource-level authorization.

The script does not modify Active Directory.

---

## Environment and Prerequisites

- Windows Server 2025 Active Directory laboratory
- PowerShell with appropriate permissions
- ActiveDirectory PowerShell module for IAM scripts
- Permission to read Windows Security Event Logs for authentication queries
- Existing `C:\CyberLab` working directory

The IAM scripts currently use a fixed search base of `DC=corp,DC=whitleylab,DC=test`.

## Security and Evidence Handling

All testing was conducted within an isolated, authorized laboratory using fictional user accounts.

Scripts and documentation may be published for educational and portfolio purposes. Original CSV exports and raw Windows Security events are retained privately.

The scripts are learning and demonstration tools, not production-hardened compliance or detection solutions.

## Related Security Investigations

- [IAM-001 — Excessive Access Following Department Transfer](../04-Security-Findings/IAM-001/finding-report.md)
- [INC-001 — Failed Authentication Investigation](../05-SOC-Investigations/INC-001/investigation-report.md)

## Future Enhancements

- Parameterize Active Directory domain and OU search scopes
- Add structured error handling and logging
- Report users with missing or unmapped departments
- Support approved access exceptions and nested group assessment
- Improve authentication event parsing and correlation
- Add automated tests and sanitized sample output

---

**Project Summary:** LAB-03 demonstrates the development, execution, and validation of reusable PowerShell security tools supporting IAM administration, security monitoring, and evidence-based access assessments.
