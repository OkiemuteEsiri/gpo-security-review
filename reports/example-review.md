# Example GPO Security Review

> Synthetic demonstration only. No real domain, user, endpoint, or organization is represented.

## Executive summary
The sample review identified one critical privilege condition plus multiple high/medium control gaps. The most important issue is a broad group receiving local administrator rights through policy, which materially increases privilege and lateral-movement risk.

## Findings

| ID | Severity | Finding | Defensive priority |
|---|---|---|---|
| GPO-PRIV-001 | Critical | Broad group receives local administrator rights | Remove broad membership immediately and validate effective membership |
| GPO-SCOPE-001 | High | Security-sensitive policy linked broadly | Constrain scope and validate resultant policy |
| GPO-AUDIT-001 | High | Process creation auditing disabled | Restore telemetry and confirm ingestion |
| GPO-RM-001 | High | RDP enabled without NLA | Require NLA and restrict administration path |
| GPO-SCRIPT-001 | Medium | Unsigned PowerShell broadly allowed | Apply approved execution/signing governance and monitoring |

## ATT&CK context
- **T1078 Valid Accounts:** broad administrative rights can amplify the impact of credential misuse.
- **T1021.001 Remote Desktop Protocol:** RDP configuration affects lateral/remote access exposure.
- **T1059.001 PowerShell:** script governance and logging improve prevention/detection around PowerShell execution.

## Validation plan
After remediation, re-run the analyzer against a fresh approved export, review effective policy on representative systems, and retain evidence for each closed finding.
