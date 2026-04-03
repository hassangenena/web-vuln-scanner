

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.report import Finding

# XSS payloads ranging from simple to evasion-focused
# We check if these reflect back unescaped in the response body
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    # Evasion: mixed case
    "<ScRiPt>alert(1)</ScRiPt>",
    # Evasion: encoding
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

# These strings in the response indicate the payload reflected without escaping
REFLECTION_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=",
    "<svg onload=",
    "javascript:alert(1)",
    "<body onload=",
    "<script>alert(1)<",
]


class XSSScanner:
    MODULE = "xss"

    def __init__(self, client, verbose: bool = False):
        self.client = client
        self.verbose = verbose

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _payload_reflected(self, body: str, payload: str) -> bool:
        """Check if any known XSS indicator appears unescaped in the body."""
        body_lower = body.lower()
        for indicator in REFLECTION_INDICATORS:
            if indicator.lower() in body_lower:
                return True
        # Also directly check if the raw payload appears
        if payload.lower() in body_lower:
            return True
        return False

    def run(self) -> list:
        findings = []
        base_url = self.client.base_url
        parsed_base = urlparse(base_url)
        params = parse_qs(parsed_base.query)

        if not params:
            print("  [i] No query parameters found — skipping XSS scan.")
            print("      Tip: Try a URL like: http://target.com/search?q=test")
            return findings

        for param in params:
            print(f"  [*] Testing parameter: '{param}'")
            for payload in PAYLOADS:
                injected_url = self._inject_param(base_url, param, payload)
                parsed = urlparse(injected_url)
                path_and_query = parsed.path + ("?" + parsed.query if parsed.query else "")

                response = self.client.get(path_and_query)
                if response is None:
                    continue

                # Only check HTML responses
                content_type = response.headers.get("Content-Type", "")
                if "html" not in content_type.lower():
                    continue

                if self._payload_reflected(response.text, payload):
                    print(f"  [!] Reflected XSS in '{param}' with payload: {payload[:50]}")
                    findings.append(Finding(
                        module=self.MODULE,
                        severity="HIGH",
                        title=f"Reflected XSS in parameter '{param}'",
                        detail=(
                            f"XSS payload reflected in response without HTML encoding. "
                            f"An attacker can craft a malicious link to steal cookies or hijack sessions. "
                            f"Fix: HTML-encode all user-supplied output (use frameworks' built-in escaping)."
                        ),
                        evidence=f"Payload: {payload!r}",
                    ))
                    break  # One finding per parameter

        return findings