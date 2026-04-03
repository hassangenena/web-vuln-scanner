#!/usr/bin/env python3
"""
Web Vulnerability Scanner
A learning-focused tool for intermediate cybersecurity students.
Tests for: SQLi, XSS, Security Headers, Open Redirects, Directory Traversal
"""

import argparse
import sys
from modules.sql_injection import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeaderScanner
from modules.open_redirect import OpenRedirectScanner
from modules.dir_traversal import DirTraversalScanner
from utils.report import ReportGenerator
from utils.http_client import HTTPClient


BANNER = """
╔══════════════════════════════════════════════╗
║         Web Vulnerability Scanner           ║
║     Educational Tool — Use Ethically        ║
╚══════════════════════════════════════════════╝
"""


def run_scan(target: str, modules: list, verbose: bool = False):
    print(BANNER)
    print(f"[*] Target: {target}")
    print(f"[*] Modules: {', '.join(modules)}\n")

    client = HTTPClient(target, verbose=verbose)
    results = {}

    module_map = {
        "headers":   HeaderScanner,
        "sqli":      SQLiScanner,
        "xss":       XSSScanner,
        "redirect":  OpenRedirectScanner,
        "traversal": DirTraversalScanner,
    }

    for mod_name in modules:
        if mod_name not in module_map:
            print(f"[!] Unknown module: {mod_name}")
            continue
        print(f"[*] Running module: {mod_name.upper()}")
        scanner = module_map[mod_name](client, verbose=verbose)
        results[mod_name] = scanner.run()

    report = ReportGenerator(target, results)
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Normalize target URL
    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    run_scan(target, args.modules, args.verbose)


if __name__ == "__main__":
    main()