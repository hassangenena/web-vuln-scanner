"""
Flask backend — bridges the Electron UI to the Python scanner.
Runs locally on http://127.0.0.1:5000
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import threading
import json
import os
import sys
import shutil

def get_python():
    """Find the correct python executable."""
    # Try the same python running this server first
    candidates = [sys.executable, "python", "python3"]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    return "python"

app = Flask(__name__)
CORS(app)

# Global scan state
scan_state = {
    "running": False,
    "lines": [],
    "done": False,
    "error": None,
}


@app.route("/api/scan", methods=["POST"])
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "A scan is already running"}), 409

    data = request.json
    target = data.get("target", "").strip()
    modules = data.get("modules", ["headers", "sqli", "xss", "redirect", "traversal"])
    crawl = data.get("crawl", False)
    follow_external = data.get("follow_external", False)
    max_pages = data.get("max_pages", 20)
    verbose = data.get("verbose", False)

    if not target:
        return jsonify({"error": "No target provided"}), 400

    cmd = [get_python(), "scanner.py", target, "--modules"] + modules
    if crawl:
        cmd += ["--crawl", "--max-pages", str(max_pages)]
    if follow_external:
        cmd.append("--follow-external")
    if verbose:
        cmd.append("--verbose")

    # Reset state
    scan_state["running"] = True
    scan_state["lines"] = []
    scan_state["done"] = False
    scan_state["error"] = None

    def run_scan():
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            for line in process.stdout:
                scan_state["lines"].append(line.rstrip())
            stderr_output = process.stderr.read()
            if stderr_output:
                for line in stderr_output.splitlines():
                    scan_state["lines"].append(f"[ERR] {line}")
            process.wait()
            scan_state["done"] = True
        except Exception as e:
            scan_state["error"] = str(e)
            scan_state["done"] = True
        finally:
            scan_state["running"] = False

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/scan/poll")
def poll_scan():
    """Frontend polls this every second to get new output lines."""
    offset = int(request.args.get("offset", 0))
    new_lines = scan_state["lines"][offset:]
    return jsonify({
        "lines": new_lines,
        "offset": offset + len(new_lines),
        "done": scan_state["done"],
        "running": scan_state["running"],
        "error": scan_state["error"],
    })


@app.route("/api/reports")
def get_reports():
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_report.json")
    if not os.path.exists(report_path):
        return jsonify({"findings": [], "target": None, "timestamp": None})
    with open(report_path) as f:
        return jsonify(json.load(f))


@app.route("/api/status")
def status():
    return jsonify({"running": scan_state["running"]})


if __name__ == "__main__":
    app.run(port=5000, debug=False)