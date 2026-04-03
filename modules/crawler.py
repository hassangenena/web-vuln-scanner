
from urllib.parse import urljoin, urlparse
from collections import deque
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class Crawler:
    def __init__(self, client, same_domain_only: bool = True, max_pages: int = 50, verbose: bool = False):
        self.client = client
        self.same_domain_only = same_domain_only
        self.max_pages = max_pages
        self.verbose = verbose
        self.base_domain = urlparse(client.base_url).netloc
        self.visited = set()
        self.discovered_urls = []  # URLs with parameters (good for scanning)
        self.all_urls = []         # Every URL found

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain

    def _is_scannable(self, url: str) -> bool:
        """Skip static assets — only crawl HTML pages."""
        skip_extensions = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                           ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf",
                           ".zip", ".tar", ".gz", ".mp4", ".mp3")
        path = urlparse(url).path.lower()
        return not any(path.endswith(ext) for ext in skip_extensions)

    def _extract_links(self, base_url: str, html: str) -> list:
        """Extract all href links from a page."""
        if not BS4_AVAILABLE:
            # Fallback: basic regex-free extraction using split
            links = []
            for part in html.split('href="')[1:]:
                href = part.split('"')[0]
                if href:
                    links.append(href)
            for part in html.split("href='")[1:]:
                href = part.split("'")[0]
                if href:
                    links.append(href)
            return links

        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            links.append(tag["href"])
        # Also grab form actions
        for form in soup.find_all("form", action=True):
            links.append(form["action"])
        return links

    def _normalize_url(self, base: str, href: str) -> str | None:
        """Turn a relative href into an absolute URL."""
        if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
            return None
        return urljoin(base, href).split("#")[0]  # Strip fragments

    def crawl(self) -> list:
        """
        BFS crawl starting from base_url.
        Returns list of all discovered URLs (with and without params).
        """
        if not BS4_AVAILABLE:
            print("  [i] Tip: Install beautifulsoup4 for better link extraction:")
            print("      pip install beautifulsoup4")

        queue = deque([self.client.base_url])
        self.visited.add(self.client.base_url)

        print(f"  [*] Starting crawl from: {self.client.base_url}")
        print(f"  [*] Mode: {'Same domain only' if self.same_domain_only else 'Follow all links'}")
        print(f"  [*] Max pages: {self.max_pages}\n")

        pages_crawled = 0
        while queue and pages_crawled < self.max_pages:
            current_url = queue.popleft()

            if not self._is_scannable(current_url):
                continue

            parsed = urlparse(current_url)

            # Use a fresh client per URL so each absolute URL is fetched correctly
            from utils.http_client import HTTPClient
            page_client = HTTPClient(current_url, verbose=self.verbose)
            response = page_client.get(follow_redirects=True)
            if response is None:
                continue

            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                continue

            self.all_urls.append(current_url)
            pages_crawled += 1
            if parsed.query:
                self.discovered_urls.append(current_url)

            print(f"  [crawl] ({pages_crawled}/{self.max_pages}) {current_url}")

            links = self._extract_links(current_url, response.text)
            for href in links:
                absolute = self._normalize_url(current_url, href)
                if not absolute:
                    continue
                if self.same_domain_only and not self._is_same_domain(absolute):
                    continue
                if absolute not in self.visited:
                    self.visited.add(absolute)
                    queue.append(absolute)

        print(f"\n  [+] Crawl complete: {len(self.all_urls)} pages found, {len(self.discovered_urls)} with parameters\n")
        return self.all_urls