# Group Policy Security Review

A defensive Active Directory security engineering project for reviewing synthetic Group Policy Objects (GPOs) and identifying configuration patterns that can increase privilege, weaken endpoint controls, or create broad administrative exposure.

## Security problem
Group Policy is a powerful control plane. Mis-scoped policies, insecure local administrator configuration, weak audit settings, exposed remote-management rules, and risky script execution can materially increase enterprise attack paths. This project models how security teams can review GPO metadata and settings in a repeatable, evidence-driven way.

## What this project demonstrates
- Active Directory / GPO security assessment
- Identity and privilege-governance analysis
- Windows security-control review
- Deterministic Python security checks
- Synthetic policy datasets
- Unit testing and CI
- MITRE ATT&CK-aligned defensive context
- Remediation and revalidation workflows

## Architecture

```text
Synthetic GPO export
       |
       v
src/gpo_review.py
  |-- scope checks
  |-- local admin checks
  |-- audit-policy checks
  |-- remote-management checks
  |-- script-policy checks
       |
       v
Normalized findings + evidence
       |
       +--> remediation
       +--> ATT&CK context
       +--> validation criteria
```

## Controls

| ID | Control | Defensive concern |
|---|---|---|
| GPO-PRIV-001 | Broad local administrator grant | Privilege escalation / lateral movement |
| GPO-SCOPE-001 | Security-sensitive GPO linked broadly | Excessive blast radius |
| GPO-AUDIT-001 | Process creation auditing disabled | Reduced detection visibility |
| GPO-RM-001 | RDP allowed without network-level authentication | Remote access hardening |
| GPO-SCRIPT-001 | Unsigned PowerShell execution allowed broadly | Script execution governance |

## MITRE ATT&CK context
Relevant findings are mapped defensively to techniques including **T1078 Valid Accounts**, **T1021.001 Remote Desktop Protocol**, and **T1059.001 PowerShell**. Mappings describe prevention/detection value and do not include exploitation procedures.

## Run

```bash
python -m src.gpo_review data/synthetic_gpos.json
python -m unittest discover -s tests -v
```

## Repository structure

```text
gpo-security-review/
├── src/gpo_review.py
├── data/synthetic_gpos.json
├── tests/test_gpo_review.py
├── docs/assessment-methodology.md
├── docs/remediation-validation.md
├── reports/example-review.md
└── .github/workflows/tests.yml
```

## Safety
The repository contains only synthetic GPO data and defensive analysis logic. It does not modify Active Directory, execute scripts remotely, enumerate production domains, or provide credential-abuse instructions.

## Skills demonstrated
Active Directory security, Windows hardening, identity security, attack-path reduction, Python, security automation, evidence-based remediation, ATT&CK mapping, testing, and CI/CD.

## Roadmap
- Add inheritance/block-inheritance analysis
- Add privileged group assignment review
- Add password/lockout policy checks
- Add GPO exception register support
- Add JSON/SARIF reporting
