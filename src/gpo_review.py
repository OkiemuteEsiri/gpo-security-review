from __future__ import annotations

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    gpo: str
    title: str
    evidence: str
    remediation: str
    attack_mapping: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def review_gpos(document: dict) -> list[Finding]:
    findings: list[Finding] = []
    for gpo in document.get("gpos", []):
        name = gpo["name"]
        settings = gpo.get("settings", {})
        scope = gpo.get("scope", [])

        if settings.get("local_admin_group") in {"Domain Users", "Authenticated Users"}:
            findings.append(Finding(
                "GPO-PRIV-001", "CRITICAL", name,
                "Broad group receives local administrator rights",
                f"local_admin_group={settings['local_admin_group']}",
                "Remove broad membership, define named administrative groups, and revalidate effective local-group membership.",
                "T1078 Valid Accounts",
            ))

        sensitive = any(k in settings for k in ("local_admin_group", "allow_rdp", "powershell_execution"))
        if sensitive and any(item in {"Domain Root", "All Workstations"} for item in scope):
            findings.append(Finding(
                "GPO-SCOPE-001", "HIGH", name,
                "Security-sensitive GPO has broad scope",
                f"scope={','.join(scope)}",
                "Narrow the link/security filtering to the intended administrative boundary and validate resultant policy.",
            ))

        if settings.get("process_creation_auditing") is False:
            findings.append(Finding(
                "GPO-AUDIT-001", "HIGH", name,
                "Process creation auditing disabled",
                "process_creation_auditing=false",
                "Enable approved process creation auditing and confirm events reach the monitoring platform.",
            ))

        if settings.get("allow_rdp") and not settings.get("rdp_nla_required", False):
            findings.append(Finding(
                "GPO-RM-001", "HIGH", name,
                "RDP enabled without Network Level Authentication requirement",
                "allow_rdp=true; rdp_nla_required=false",
                "Require NLA and restrict RDP to authorized administration paths and groups.",
                "T1021.001 Remote Desktop Protocol",
            ))

        if settings.get("powershell_execution") == "unsigned_allowed":
            findings.append(Finding(
                "GPO-SCRIPT-001", "MEDIUM", name,
                "Unsigned PowerShell execution broadly allowed",
                "powershell_execution=unsigned_allowed",
                "Apply an approved script execution policy, code-signing governance, and monitoring appropriate to the environment.",
                "T1059.001 PowerShell",
            ))

    return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def main(path: str) -> int:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = review_gpos(document)
    for finding in findings:
        print(f"{finding.severity:<8} {finding.control_id:<14} {finding.gpo}: {finding.title}")
    print(json.dumps(severity_counts(findings), indent=2))
    return 1 if any(f.severity == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "data/synthetic_gpos.json"))
