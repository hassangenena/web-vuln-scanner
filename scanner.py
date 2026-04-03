

import argparse
from modules.sql_injection import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeaderScanner
from modules.open_redirect import OpenRedirectScanner
from modules.dir_traversal import DirTraversalScanner
from modules.crawler import Crawler
from utils.report import ReportGenerator, Finding
from utils.http_client import HTTPClient


BANNER = """
╔══════════════════════════════════════════════╗
║         Web Vulnerability Scanner           ║
║     Educational Tool — Use Ethically        ║
╚══════════════════════════════════════════════╝
"""

MODULE_MAP = {
    "headers":   HeaderScanner,
    "sqli":      SQLiScanner,
    "xss":       XSSScanner,
    "redirect":  OpenRedirectScanner,
    "traversal": DirTraversalScanner,
}


def scan_url(client, modules, verbose):
    """Run selected modules against the client's current base_url."""
    results = {}
    for mod_name in modules:
        scanner = MODULE_MAP[mod_name](client, verbose=verbose)
        results.setdefault(mod_name, []).extend(scanner.run())
    return results


def run_single(target, modules, verbose):
    """Scan a single URL."""
    print(BANNER)
    print(f"[*] Target : {target}")
    print(f"[*] Modules: {', '.join(modules)}\n")

    client = HTTPClient(target, verbose=verbose)
    results = scan_url(client, modules, verbose)

    report = ReportGenerator(target, results)
    report.print_summary()
    report.save_json("scan_report.json")
    print("\n[+] Full report saved to scan_report.json")


def run_crawl(target, modules, verbose, same_domain_only, max_pages):
    """Crawl entire site then scan every discovered page."""
    print(BANNER)
    print(f"[*] Mode   : FULL SITE CRAWL")
    print(f"[*] Target : {target}")
    print(f"[*] Modules: {', '.join(modules)}")
    print(f"[*] Scope  : {'Same domain only' if same_domain_only else 'All links'}")
    print(f"[*] Max pages: {max_pages}\n")

    base_client = HTTPClient(target, verbose=verbose)

    # Phase 1: Crawl
    print("=" * 50)
    print("  PHASE 1: CRAWLING")
    print("=" * 50)
    crawler = Crawler(base_client, same_domain_only=same_domain_only, max_pages=max_pages, verbose=verbose)
    all_urls = crawler.crawl()

    if not all_urls:
        print("[!] No pages discovered. Check the target URL.")
        return

    all_results = {}

    # Phase 2a: Headers once on base URL
    if "headers" in modules:
        print("=" * 50)
        print("  PHASE 2a: HEADERS CHECK (base URL)")
        print("=" * 50)
        scanner = HeaderScanner(base_client, verbose=verbose)
        all_results["headers"] = scanner.run()

    # Phase 2b: Scan every page with remaining modules
    remaining_modules = [m for m in modules if m != "headers"]
    if remaining_modules:
        print("\n" + "=" * 50)
        print(f"  PHASE 2b: SCANNING {len(all_urls)} PAGES")
        print("=" * 50)

        for i, url in enumerate(all_urls, 1):
            print(f"\n[{i}/{len(all_urls)}] Scanning: {url}")
            page_client = HTTPClient(url, verbose=verbose)
            page_results = scan_url(page_client, remaining_modules, verbose)
            for mod, findings in page_results.items():
                all_results.setdefault(mod, []).extend(findings)

    # Phase 3: Report
    report = ReportGenerator(target, all_results)
    report.print_summary()
    report.save_json("scan_report.json")
    print("\n[+] Full report saved to scan_report.json")


def main():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — Educational Tool"
    )
    parser.add_argument("target", help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument(
        "--modules",
        nargs="+",
        default=["headers", "sqli", "xss", "redirect", "traversal"],
        choices=["headers", "sqli", "xss", "redirect", "traversal"],
        help="Modules to run (default: all)",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl entire site and scan every page found",
    )
    parser.add_argument(
        "--follow-external",
        action="store_true",
        help="Follow links to external domains (default: same domain only)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=50,
        help="Max pages to crawl (default: 50)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    if args.crawl:
        run_crawl(target, args.modules, args.verbose,
                  same_domain_only=not args.follow_external,
                  max_pages=args.max_pages)
    else:
        run_single(target, args.modules, args.verbose)


if __name__ == "__main__":
    main()