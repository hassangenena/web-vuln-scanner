"""
Report Generator — prints a colour-coded summary and saves a JSON report.
"""

import json
from datetime import datetime

SEVERITY_COLORS = {
    "HIGH":   "\033[91m",  # Red
    "MEDIUM": "\033[93m",  # Yellow
    "LOW":    "\033[94m",  # Blue
    "INFO":   "\033[96m",  # Cyan
}
RESET = "\033[0m"


class Finding:
    def __init__(self, module: str, severity: str, title: str, detail: str, evidence: str = ""):
        self.module = module
        self.severity = severity
        self.title = title
        self.detail = detail
        self.evidence = evidence

    def to_dict(self):
        return {
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


class ReportGenerator:
    def __init__(self, target: str, results: dict):
        self.target = target
        self.results = results  # {module_name: [Finding, ...]}
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def all_findings(self):
        findings = []
        for module_findings in self.results.values():
            findings.extend(module_findings)
        return findings

    def print_summary(self):
        findings = self.all_findings()
        print("\n" + "═" * 50)
        print("  SCAN SUMMARY")
        print("═" * 50)
        print(f"  Target    : {self.target}")
        print(f"  Timestamp : {self.timestamp}")
        print(f"  Findings  : {len(findings)}")
        print("═" * 50)

        if not findings:
            print("  \033[92m[✓] No vulnerabilities detected.\033[0m")
        else:
            for f in sorted(findings, key=lambda x: ["HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)):
                color = SEVERITY_COLORS.get(f.severity, "")
                print(f"\n  {color}[{f.severity}]{RESET} [{f.module.upper()}] {f.title}")
                print(f"        {f.detail}")
                if f.evidence:
                    print(f"        Evidence: {f.evidence[:120]}")
        print("\n" + "═" * 50)

    def save_json(self, path: str):
        report = {
            "target": self.target,
            "timestamp": self.timestamp,
            "total_findings": len(self.all_findings()),
            "findings": [f.to_dict() for f in self.all_findings()],
        }
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)