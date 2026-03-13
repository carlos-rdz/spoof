#!/usr/bin/env python3
"""
Automated tests for spoof_server.py endpoints.
Run: python3 test_spoof_server.py

Starts the server on a random port, hits all endpoints, validates responses.
"""

import json
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import socket
import os
import signal

BASE = None
SERVER_PROC = None
PORT = None


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def start_server():
    global SERVER_PROC, PORT, BASE
    PORT = find_free_port()
    BASE = f"http://localhost:{PORT}"
    SERVER_PROC = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "spoof_server.py"), str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    # Wait for server to be ready
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{BASE}/status", timeout=1)
            return
        except:
            time.sleep(0.2)
    raise RuntimeError("Server did not start in time")


def stop_server():
    if SERVER_PROC:
        SERVER_PROC.terminate()
        SERVER_PROC.wait(timeout=5)


def fetch(path, method="GET", data=None, content_type=None):
    url = BASE + path
    if data and isinstance(data, dict) and not content_type:
        data = urllib.parse.urlencode(data).encode()
        content_type = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    resp = urllib.request.urlopen(req, timeout=30)
    body = resp.read()
    return resp.status, resp.headers, body


def fetch_json(path, **kwargs):
    status, headers, body = fetch(path, **kwargs)
    return status, json.loads(body)


# ── Test definitions ──

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} — {detail}")


def test_homepage():
    print("\n── GET / (HTML UI) ──")
    status, headers, body = fetch("/")
    check("returns 200", status == 200)
    check("content-type is html", "text/html" in headers.get("Content-Type", ""))
    html = body.decode()
    check("has title", "<title>Spoof</title>" in html)
    check("has compose form", 'id="from_addr"' in html)
    check("has preflight button", "Preflight" in html)
    check("has send button", "Send" in html)
    check("has ngrok bar", 'id="ngrok-bar"' in html)
    check("has open tracker tab", "Open Tracker" in html)
    check("has pipeline stage preview", 'id="stage-preview"' in html)
    check("has pipeline stages", 'id="stage-preflight"' in html)
    check("has pipeline stage inflight", 'id="stage-inflight"' in html)
    check("has pipeline stage delivered", 'id="stage-delivered"' in html)
    check("has pipeline stage opened", 'id="stage-opened"' in html)
    check("has pipe-track", 'id="pipe-track"' in html)
    check("has pipe-dot elements", 'class="pipe-dot"' in html)
    check("has Preview tab", '>Preview</button>' in html)
    check("has preview iframe", 'id="preview-iframe-main"' in html)
    check("has setPipeStage function", "setPipeStage" in html)
    check("has ngrok JS check", "checkNgrok" in html)
    check("has startTrackingPolling", "startTrackingPolling" in html)
    check("has DNS Records tab", "DNS Records" in html)
    check("has Send Log tab", "Send Log" in html)


def test_status_endpoint():
    print("\n── GET /status (ngrok check) ──")
    status, data = fetch_json("/status")
    check("returns 200", status == 200)
    check("has ngrok key", "ngrok" in data)
    check("ngrok is null (no tunnel)", data["ngrok"] is None, f"got {data['ngrok']}")


def test_preflight_missing_params():
    print("\n── GET /preflight (missing params) ──")
    status, data = fetch_json("/preflight")
    check("returns 200", status == 200)
    check("has error", "error" in data, f"keys: {list(data.keys())}")


def test_preflight_real_domain():
    print("\n── GET /preflight (rvuwallet.com → yopmail.com) ──")
    params = urllib.parse.urlencode({
        "from_addr": "support@rvuwallet.com",
        "to_addr": "test@yopmail.com",
        "envelope_from": "bounce@rvuwallet.com"
    })
    status, data = fetch_json(f"/preflight?{params}")
    check("returns 200", status == 200)
    check("has from_domain", data.get("from_domain") == "rvuwallet.com", f"got {data.get('from_domain')}")
    check("has to_domain", data.get("to_domain") == "yopmail.com", f"got {data.get('to_domain')}")
    check("has mx section", "mx" in data)
    check("has spf section", "spf" in data)
    check("has dkim section", "dkim" in data)
    check("has dmarc section", "dmarc" in data)
    check("has probe section", "probe" in data)
    check("has log", "log" in data and len(data["log"]) > 0)
    check("mx resolved", data["mx"].get("selected") is not None, f"mx={data['mx']}")
    check("spf has verdict", data["spf"].get("verdict") is not None)
    check("dmarc has policy", data["dmarc"].get("policy") is not None)
    check("probe has prediction", data["probe"].get("prediction") is not None)


def test_preflight_gmail():
    print("\n── GET /preflight (→ gmail.com, expect extra protections) ──")
    params = urllib.parse.urlencode({
        "from_addr": "support@rvuwallet.com",
        "to_addr": "test@gmail.com",
        "envelope_from": "bounce@rvuwallet.com"
    })
    status, data = fetch_json(f"/preflight?{params}")
    check("returns 200", status == 200)
    check("to_domain is gmail.com", data.get("to_domain") == "gmail.com")
    check("mx found google", data["mx"].get("selected") is not None)


def test_tracking_pixel_endpoint():
    print("\n── GET /track/<id>.gif (tracking pixel) ──")
    status, headers, body = fetch("/track/aabbcc112233.gif")
    check("returns 200", status == 200)
    check("content-type is gif", "image/gif" in headers.get("Content-Type", ""))
    check("body is small 1x1 GIF", len(body) <= 50, f"got {len(body)} bytes")
    check("no-cache header", "no-store" in headers.get("Cache-Control", ""))


def test_track_events_empty():
    print("\n── GET /track-events (no tracked emails) ──")
    status, data = fetch_json("/track-events")
    check("returns 200", status == 200)
    check("returns dict/object", isinstance(data, dict))


def test_track_events_with_id():
    print("\n── GET /track-events?id=nonexistent ──")
    status, data = fetch_json("/track-events?id=doesnotexist")
    check("returns 200", status == 200)
    # Should return all tracked (empty dict since no sends)
    check("returns dict", isinstance(data, dict))


def test_tracking_pixel_records_open():
    print("\n── Tracking pixel records open events ──")
    # First hit the pixel to register an unknown track
    fetch("/track/aabb00112233.gif")
    # Check events — should not crash
    status, data = fetch_json("/track-events?id=aabb00112233")
    check("returns 200", status == 200)


def test_send_no_recipient():
    print("\n── POST /send (no recipient) ──")
    status, data = fetch_json("/send", method="POST", data={
        "from_addr": "test@example.com",
        "envelope_from": "test@example.com",
        "to_addr": "",
        "subject": "test",
        "body_text": "test",
        "body_html": ""
    })
    check("returns 200", status == 200)
    check("success is false", data.get("success") is False)
    check("has error log", "Error" in data.get("log", "") or "No recipient" in data.get("log", ""),
          f"log: {data.get('log', '')[:80]}")


def test_send_nonexistent_domain():
    print("\n── POST /send (nonexistent MX domain) ──")
    status, data = fetch_json("/send", method="POST", data={
        "from_addr": "test@rvuwallet.com",
        "envelope_from": "test@rvuwallet.com",
        "to_addr": "nobody@thisdomain-doesnt-exist-xyz123.com",
        "subject": "test",
        "body_text": "test body",
        "body_html": ""
    })
    check("returns 200", status == 200)
    check("success is false", data.get("success") is False)
    check("mentions MX issue in log", "MX" in data.get("log", "") or "No MX" in data.get("log", ""),
          f"log snippet: {data.get('log', '')[:100]}")


def test_pipeline_states():
    """Verify pipeline CSS states exist."""
    print("\n── Pipeline CSS states ──")
    _, _, body = fetch("/")
    html = body.decode()
    check("CSS has .pipe-stage.idle", ".pipe-stage.idle" in html)
    check("CSS has .pipe-stage.active", ".pipe-stage.active" in html)
    check("CSS has .pipe-stage.done", ".pipe-stage.done" in html)
    check("CSS has .pipe-stage.fail", ".pipe-stage.fail" in html)
    check("CSS has .pipe-stage.glow", ".pipe-stage.glow" in html)
    check("CSS has .pipe-seg.done", ".pipe-seg.done" in html)
    check("JS setPipeStage function", "function setPipeStage" in html)
    check("JS setPipeConn function", "function setPipeConn" in html)
    check("JS resetPipeline function", "function resetPipeline" in html)
    check("JS STAGE_TAB_MAP auto-switch", "STAGE_TAB_MAP" in html)
    check("resetPipeline includes preview", "'preview'" in html)


def test_ngrok_js():
    print("\n── JS ngrok integration ──")
    _, _, body = fetch("/")
    html = body.decode()
    check("checkNgrok function exists", "async function checkNgrok()" in html)
    check("fetches /status", "fetch('/status')" in html)
    check("shows ngrok URL when connected", "data.ngrok" in html)
    check("shows warning when disconnected", "ngrok http 8090" in html)
    check("polls every 15s", "setInterval(checkNgrok, 15000)" in html)


# ── Runner ──

def main():
    global PASS, FAIL
    print("=" * 50)
    print("  Spoof Server Test Suite")
    print("=" * 50)

    try:
        print("\nStarting server...")
        start_server()
        print(f"Server running on port {PORT}")

        test_homepage()
        test_status_endpoint()
        test_preflight_missing_params()
        test_preflight_real_domain()
        test_preflight_gmail()
        test_tracking_pixel_endpoint()
        test_track_events_empty()
        test_track_events_with_id()
        test_tracking_pixel_records_open()
        test_send_no_recipient()
        test_send_nonexistent_domain()
        test_pipeline_states()
        test_ngrok_js()

    finally:
        stop_server()

    print("\n" + "=" * 50)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  ALL {total} CHECKS PASSED ✓")
    else:
        print(f"  {PASS}/{total} passed, {FAIL} FAILED ✗")
    print("=" * 50)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
