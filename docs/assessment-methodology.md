# Assessment Methodology

## Objective
Review GPO configuration and scope for security conditions that increase privilege, weaken telemetry, or widen remote/script execution exposure.

## Workflow
1. Define the authorized domain/OU scope.
2. Export approved GPO metadata using a read-only process.
3. Normalize settings into the project schema.
4. Run deterministic control checks.
5. Review finding evidence and effective policy context.
6. Assign remediation ownership and due date.
7. Re-export and re-run after remediation.

## Review domains
- Privileged local-group assignment
- Scope/link blast radius
- Windows audit policy
- Remote desktop hardening
- PowerShell/script execution governance

## Evidence quality
A finding should record the GPO name, relevant setting, scope, collection timestamp, and source export. Production use should also account for inheritance, enforcement, security filtering, WMI filtering, and resultant set of policy before declaring impact.

## Risk classification
- **Critical:** configuration directly grants broad administrative privilege.
- **High:** materially weakens security boundaries, remote access protection, or detection visibility.
- **Medium:** governance weakness that increases execution or control risk but requires additional conditions.
- **Low:** hygiene issue with limited direct impact.

## ATT&CK usage
ATT&CK mappings provide defensive context for why a control matters. They are not proof of compromise and should not be used as a substitute for environment-specific threat modeling.
