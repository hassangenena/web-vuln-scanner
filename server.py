"""
Flask backend — bridges the Electron UI to the Python scanner.
Runs locally on http://localhost:5000
"""

from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import subprocess
import threading
import json
import os
import sys
import queue

app = Flask(__name__)
CORS(app)

# Store active scan output
scan_queue = queue.Queue()
scan_running = False


@app.route("/api/scan", methods=["POST"])
def start_scan():
    global scan_running

    data = request.json
    target = data.get("target", "").strip()
    modules = data.get("modules", ["headers", "sqli", "xss", "redirect", "traversal"])
    crawl = data.get("crawl", False)
    follow_external = data.get("follow_external", False)
    max_pages = data.get("max_pages", 20)
    verbose = data.get("verbose", False)

    if not target:
        return jsonify({"error": "No target provided"}), 400

    if scan_running:
        return jsonify({"error": "A scan is already running"}), 409

    # Build command
    cmd = [sys.executable, "scanner.py", target, "--modules"] + modules
    if crawl:
        cmd += ["--crawl", "--max-pages", str(max_pages)]
    if follow_external:
        cmd.append("--follow-external")
    if verbose:
        cmd.append("--verbose")

    def run_scan():
        global scan_running
        scan_running = True
        # Clear queue
        while not scan_queue.empty():
            scan_queue.get()

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            for line in process.stdout:
                scan_queue.put({"type": "output", "line": line.rstrip()})
            process.wait()
            scan_queue.put({"type": "done", "returncode": process.returncode})
        except Exception as e:
            scan_queue.put({"type": "error", "message": str(e)})
        finally:
            scan_running = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@app.route("/api/scan/stream")
def stream_scan():
    def generate():
        while True:
            try:
                item = scan_queue.get(timeout=30)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/reports")
def get_reports():
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_report.json")
    if not os.path.exists(report_path):
        return jsonify({"findings": [], "target": None, "timestamp": None})
    with open(report_path) as f:
        return jsonify(json.load(f))


@app.route("/api/status")
def status():
    return jsonify({"running": scan_running})


if __name__ == "__main__":
    app.run(port=5000, debug=False)