
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.report import Finding

# Common redirect parameter names (very common in login flows, etc.)
REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_url", "redirect_uri",
    "return", "returnurl", "return_url", "dest", "destination",
    "go", "goto", "target", "link", "forward", "continue",
    "location", "ref", "back",
]

# Payloads — external URLs we try to redirect to
PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/",
    "//evil.com/%2F..",
    "https:evil.com",
    "/\\evil.com",
]


class OpenRedirectScanner:
    MODULE = "redirect"

    def __init__(self, client, verbose: bool = False):
        self.client = client
        self.verbose = verbose

    def _is_external_redirect(self, response, payload: str) -> bool:
        """Check if response redirects to an external domain."""
        if response.status_code not in (301, 302, 303, 307, 308):
            return False
        location = response.headers.get("Location", "")
        parsed_payload = urlparse(payload)
        parsed_location = urlparse(location)
        # If Location header points outside the target domain
        if parsed_payload.netloc and parsed_payload.netloc in location:
            return True
        if location.startswith("//evil.com") or location.startswith("https://evil.com"):
            return True
        return False

    def run(self) -> list:
        findings = []
        base_url = self.client.base_url
        parsed_base = urlparse(base_url)
        existing_params = parse_qs(parsed_base.query)

        # Test existing params + well-known redirect param names
        params_to_test = set(existing_params.keys()) | set(REDIRECT_PARAMS)

        for param in params_to_test:
            for payload in PAYLOADS:
                # Build test URL
                test_params = dict(existing_params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_parsed = parsed_base._replace(query=new_query)
                path_and_query = test_parsed.path + ("?" + new_query if new_query else "")

                response = self.client.get(path_and_query)
                if response is None:
                    continue

                if self._is_external_redirect(response, payload):
                    print(f"  [!] Open Redirect in param '{param}' -> {payload}")
                    findings.append(Finding(
                        module=self.MODULE,
                        severity="MEDIUM",
                        title=f"Open Redirect via parameter '{param}'",
                        detail=(
                            f"Application redirects to attacker-controlled URL without validation. "
                            f"Enables phishing: attackers craft links like {base_url}?{param}=https://evil.com "
                            f"Fix: Whitelist allowed redirect destinations, or use relative paths only."
                        ),
                        evidence=f"Param: {param!r} | Payload: {payload!r} | Location: {response.headers.get('Location', '')}",
                    ))
                    break

        if not findings:
            print("  [+] No open redirects detected.")

        return findings