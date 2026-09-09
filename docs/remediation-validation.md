# Remediation and Validation

## Broad local administrator grants
Remove broad groups from local Administrators configuration and replace them with explicitly approved administrative groups. Validate resultant local-group membership on representative systems and confirm the GPO control no longer flags the setting.

## Broad GPO scope
Use OU design, link placement, and security filtering to constrain security-sensitive settings to intended systems. Validate with resultant-set-of-policy evidence before closure.

## Process creation auditing
Enable the approved audit policy and confirm that expected process-creation events are generated and ingested by the monitoring platform. A registry/configuration change without telemetry validation is incomplete.

## RDP hardening
Require NLA, restrict membership in remote desktop groups, and limit network reachability to authorized administration paths. Validate effective policy plus approved connectivity tests.

## PowerShell governance
Apply an approved execution/code-signing policy appropriate to operational needs, combine with logging/monitoring, and document exceptions. Do not treat execution policy alone as a security boundary.

## Closure criteria
A finding is considered remediated only when:
- the intended GPO setting is corrected;
- effective policy matches the intended state;
- downstream control behavior is validated where applicable;
- evidence is attached to the remediation record; and
- exceptions have an owner, justification, and expiry date.
