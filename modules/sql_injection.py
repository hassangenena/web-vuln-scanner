
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.report import Finding


# Payloads that trigger SQL errors in common databases
# These are classic "break the quote" payloads
PAYLOADS = [
    "'",               # Single quote — most common SQLi trigger
    "''",              # Double single quote
    "`",               # Backtick (MySQL)
    '"',               # Double quote
    "' OR '1'='1",    # Classic boolean bypass
    "' OR 1=1--",      # Comment-based bypass
    "' AND 1=2--",     # False condition
    "1; DROP TABLE--", # Stacked query attempt (mostly for detection)
    "' UNION SELECT NULL--",  # UNION-based probe
]

# Database error signatures to detect in responses
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query()",
    "pg::syntax",
    "unterminated quoted string",
    # MSSQL
    "unclosed quotation mark",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    # Oracle
    "ora-00933",
    "ora-01756",
    "oracle error",
    # SQLite
    "sqlite3.operationalerror",
    "unrecognized token",
    # Generic
    "sql syntax",
    "syntax error",
    "unexpected end of sql",
]


class SQLiScanner:
    MODULE = "sqli"

    def __init__(self, client, verbose: bool = False):
        self.client = client
        self.verbose = verbose

    def _extract_params(self, url: str) -> dict:
        """Pull query parameters from the base URL."""
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Return a new URL with one parameter replaced by the payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _check_for_errors(self, body: str) -> str | None:
        """Return the matched error signature, or None."""
        body_lower = body.lower()
        for sig in ERROR_SIGNATURES:
            if sig in body_lower:
                return sig
        return None

    def run(self) -> list:
        findings = []
        base_url = self.client.base_url
        params = self._extract_params(base_url)

        if not params:
            print("  [i] No query parameters found in URL — skipping SQLi scan.")
            print("      Tip: Try a URL like: http://target.com/page?id=1&name=test")
            return findings

        for param in params:
            print(f"  [*] Testing parameter: '{param}'")
            for payload in PAYLOADS:
                injected_url = self._inject_param(base_url, param, payload)
                # Extract just the path+query for the relative request
                parsed = urlparse(injected_url)
                path_and_query = parsed.path + ("?" + parsed.query if parsed.query else "")

                response = self.client.get(path_and_query)
                if response is None:
                    continue

                matched = self._check_for_errors(response.text)
                if matched:
                    print(f"  [!] Possible SQLi in '{param}' with payload: {payload}")
                    findings.append(Finding(
                        module=self.MODULE,
                        severity="HIGH",
                        title=f"Possible SQL Injection in parameter '{param}'",
                        detail=(
                            f"Error-based SQLi detected. DB error signature found in response. "
                            f"Parameter '{param}' appears unsanitized. "
                            f"Fix: Use prepared statements / parameterized queries."
                        ),
                        evidence=f"Payload: {payload!r} | DB error: '{matched}'",
                    ))
                    break  # One finding per parameter is enough

        return findings