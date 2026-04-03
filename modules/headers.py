

from utils.report import Finding


# Each entry: (header_name, severity, why_it_matters)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "HIGH",
        "Missing HSTS — browser can be forced onto HTTP, enabling MITM attacks.",
    ),
    (
        "Content-Security-Policy",
        "HIGH",
        "Missing CSP — no protection against XSS and data injection attacks.",
    ),
    (
        "X-Frame-Options",
        "MEDIUM",
        "Missing X-Frame-Options — page may be embeddable in iframes (Clickjacking risk).",
    ),
    (
        "X-Content-Type-Options",
        "MEDIUM",
        "Missing X-Content-Type-Options — browser may MIME-sniff responses (Script injection risk).",
    ),
    (
        "Referrer-Policy",
        "LOW",
        "Missing Referrer-Policy — sensitive URL data may leak to third parties.",
    ),
    (
        "Permissions-Policy",
        "LOW",
        "Missing Permissions-Policy — no control over browser feature access (camera, mic, etc.).",
    ),
]

INSECURE_VALUES = {
    "Strict-Transport-Security": {
        "check": lambda v: "max-age=0" in v.lower(),
        "detail": "HSTS max-age is 0 — effectively disabled.",
    },
    "Content-Security-Policy": {
        "check": lambda v: "unsafe-inline" in v.lower() or "unsafe-eval" in v.lower(),
        "detail": "CSP contains 'unsafe-inline' or 'unsafe-eval' — weakens XSS protection.",
    },
    "X-Frame-Options": {
        "check": lambda v: v.strip().upper() == "ALLOWALL",
        "detail": "X-Frame-Options set to ALLOWALL — clickjacking protection disabled.",
    },
}


class HeaderScanner:
    MODULE = "headers"

    def __init__(self, client, verbose: bool = False):
        self.client = client
        self.verbose = verbose

    def run(self) -> list:
        findings = []
        response = self.client.get()

        if response is None:
            print("  [!] Could not reach target.")
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, severity, detail in SECURITY_HEADERS:
            if header.lower() not in headers:
                findings.append(Finding(
                    module=self.MODULE,
                    severity=severity,
                    title=f"Missing header: {header}",
                    detail=detail,
                    evidence=f"Header '{header}' not present in response.",
                ))
                print(f"  [-] MISSING: {header}")
            else:
                value = headers[header.lower()]
                print(f"  [+] Present: {header}: {value[:80]}")
                # Check for insecure values
                if header in INSECURE_VALUES:
                    check = INSECURE_VALUES[header]
                    if check["check"](value):
                        findings.append(Finding(
                            module=self.MODULE,
                            severity="MEDIUM",
                            title=f"Insecure value: {header}",
                            detail=check["detail"],
                            evidence=f"{header}: {value}",
                        ))

        # Bonus: flag server version disclosure
        server = headers.get("server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                module=self.MODULE,
                severity="LOW",
                title="Server version disclosure",
                detail="The Server header reveals software version — aids fingerprinting.",
                evidence=f"Server: {server}",
            ))

        return findings