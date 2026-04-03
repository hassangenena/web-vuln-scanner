"""
HTTP Client utility — wraps requests with shared session, timeouts, and logging.
"""

import requests
from urllib.parse import urljoin, urlparse


class HTTPClient:
    def __init__(self, base_url: str, timeout: int = 10, verbose: bool = False):
        self.base_url = base_url
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebVulnScanner/1.0 (Educational)",
        })

    def get(self, path: str = "", params: dict = None, **kwargs) -> requests.Response | None:
        url = urljoin(self.base_url, path) if path else self.base_url
        try:
            if self.verbose:
                print(f"    [GET] {url} params={params}")
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False, **kwargs)
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"    [ERR] {e}")
            return None

    def post(self, path: str = "", data: dict = None, **kwargs) -> requests.Response | None:
        url = urljoin(self.base_url, path) if path else self.base_url
        try:
            if self.verbose:
                print(f"    [POST] {url} data={data}")
            return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False, **kwargs)
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"    [ERR] {e}")
            return None

    def get_full_url(self, path: str = "") -> str:
        return urljoin(self.base_url, path)