#!/usr/bin/env python3
"""
demo.py — Record a Spoof demo video using Playwright.

Shows the full lifecycle: fill form → preflight → send → check inbox → track open.
Uses two browser tabs like a real person would.

Usage:
    python3 demo.py                          # uses localhost:8090
    python3 demo.py https://xxxx.ngrok.io    # uses ngrok URL

Outputs: demo.webm
Requires: pip install playwright && playwright install chromium
"""

import sys
import glob
import shutil
import os
from playwright.sync_api import sync_playwright

# ── Config ──
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
YOPMAIL = "https://yopmail.com"
RECIPIENT = "spooftest"
FROM_ADDR = "testing@evil.com"
SUBJECT = "Security Test — Spoof Demo"
HTML_BODY = """\
<div style="font-family:Arial;padding:20px;background:#f9f9f9;border-radius:8px;max-width:500px;margin:0 auto">
  <h2 style="color:#e53e3e">⚠ Account Verification Required</h2>
  <p>Your account needs immediate verification. Click the link below to secure your account.</p>
  <a href="#" style="display:inline-block;background:#e53e3e;color:white;padding:10px 24px;border-radius:4px;text-decoration:none;margin:12px 0">Verify Now</a>
  <p style="color:#888;font-size:12px">This is a security test sent via Spoof.</p>
</div>"""

PAUSE = 3000      # ms to hold on each step so viewer can read
TYPE_DELAY = 800  # ms between field fills


def show_caption(page, step, total, title, subtitle=""):
    """Show a non-interactive caption bar at the top of the page."""
    sub_html = f'<div style="font-size:12px;opacity:0.85;margin-top:2px">{subtitle}</div>' if subtitle else ''
    page.evaluate(f"""(() => {{
        let el = document.getElementById('demo-caption');
        if (!el) {{
            el = document.createElement('div');
            el.id = 'demo-caption';
            el.style.cssText = `
                position: fixed; top: 0; left: 0; right: 0; z-index: 99999;
                background: linear-gradient(135deg, #166534, #22c55e);
                color: white; padding: 14px 24px; font-family: system-ui, sans-serif;
                display: flex; align-items: center; gap: 16px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                pointer-events: none;
            `;
            document.body.appendChild(el);
        }}
        el.style.display = 'flex';
        el.innerHTML = `
            <div style="background:rgba(255,255,255,0.2);border-radius:50%;width:32px;height:32px;
                        display:flex;align-items:center;justify-content:center;font-weight:bold;
                        font-size:14px;flex-shrink:0">{step}/{total}</div>
            <div>
                <div style="font-weight:600;font-size:15px">{title}</div>
                {sub_html}
            </div>`;
    }})()""")


def hide_caption(page):
    page.evaluate("""(() => {
        const el = document.getElementById('demo-caption');
        if (el) el.style.display = 'none';
    })()""")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, args=["--window-size=1280,800"])
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            record_video_dir=".",
            record_video_size={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )

        # ── Tab 1: Spoof app ──
        spoof = context.new_page()
        total = 8

        # Step 1: Open Spoof
        print("[1/8] Opening Spoof UI...")
        spoof.goto(BASE_URL)
        # Handle ngrok interstitial if using ngrok URL
        if "ngrok" in BASE_URL:
            try:
                spoof.click("button:has-text('Visit Site')", timeout=5000)
                spoof.wait_for_timeout(2000)
            except:
                pass
        spoof.wait_for_timeout(1500)
        show_caption(spoof, 1, total, "Spoof — Email Security Testing Tool",
                     "Single-file Python server for SPF/DKIM/DMARC analysis and email spoofing tests")
        spoof.wait_for_timeout(PAUSE + 1000)

        # Step 2: Fill the form
        print("[2/8] Filling form...")
        hide_caption(spoof)
        show_caption(spoof, 2, total, "Composing a spoofed email",
                     f"From: {FROM_ADDR}  →  To: {RECIPIENT}@yopmail.com")
        spoof.wait_for_timeout(1500)

        spoof.fill("#from_addr", FROM_ADDR)
        spoof.wait_for_timeout(TYPE_DELAY)
        spoof.fill("#envelope_from", FROM_ADDR)
        spoof.wait_for_timeout(TYPE_DELAY)
        spoof.fill("#to_addr", f"{RECIPIENT}@yopmail.com")
        spoof.wait_for_timeout(TYPE_DELAY)
        spoof.fill("#subject", SUBJECT)
        spoof.wait_for_timeout(TYPE_DELAY)

        spoof.click("#body_html")
        spoof.keyboard.press("Meta+a")
        spoof.fill("#body_html", HTML_BODY)
        spoof.wait_for_timeout(PAUSE)

        # Step 3: Run preflight
        print("[3/8] Running preflight...")
        show_caption(spoof, 3, total, "Running preflight checks",
                     "Querying MX, SPF, DKIM, DMARC records + SMTP connectivity")
        spoof.wait_for_timeout(1500)
        spoof.click("#probe-btn")
        spoof.wait_for_timeout(6000)  # let DNS + SMTP probe finish

        # Open DNS section to show results
        try:
            spoof.click("#sec-dns .section-header", timeout=2000)
        except:
            pass
        spoof.wait_for_timeout(1000)
        spoof.evaluate("document.getElementById('sec-dns')?.scrollIntoView({behavior:'smooth',block:'center'})")
        show_caption(spoof, 3, total, "DNS records loaded",
                     "SPF, DKIM, DMARC policies for yopmail.com — shows what protections exist")
        spoof.wait_for_timeout(PAUSE + 1000)

        # Step 4: Send the email
        print("[4/8] Sending email...")
        spoof.evaluate("window.scrollTo({top:0, behavior:'smooth'})")
        spoof.wait_for_timeout(500)
        show_caption(spoof, 4, total, "Sending the spoofed email",
                     "Password-gated send → raw SMTP delivery on port 25")
        spoof.wait_for_timeout(PAUSE)

        spoof.click("#send-btn")
        spoof.wait_for_timeout(1000)

        show_caption(spoof, 4, total, "Password gate",
                     "Send action requires password to prevent unauthorized use")
        spoof.wait_for_timeout(1500)
        spoof.fill("#pw-input", "password")
        spoof.wait_for_timeout(800)
        spoof.click("#pw-inline button")
        spoof.wait_for_timeout(10000)  # wait for SMTP delivery

        state_text = spoof.inner_text("#state-text")
        print(f"  State: {state_text}")

        # Show SMTP log
        try:
            spoof.click("#sec-log .section-header", timeout=2000)
        except:
            pass
        spoof.evaluate("document.getElementById('sec-log')?.scrollIntoView({behavior:'smooth',block:'center'})")
        show_caption(spoof, 4, total, f"Sent! — {state_text}",
                     "SMTP log shows the raw server conversation")
        spoof.wait_for_timeout(PAUSE + 1000)

        # Step 5: Switch to Dashboard on the same tab
        print("[5/8] Checking dashboard...")
        spoof.evaluate("window.scrollTo({top:0, behavior:'smooth'})")
        spoof.wait_for_timeout(500)
        show_caption(spoof, 5, total, "Dashboard — activity feed",
                     "Tracks all sends and opens in real time")
        spoof.wait_for_timeout(1500)
        spoof.click("button:has-text('Dashboard')")

        # Wait for events to load
        print("  Waiting for send event...")
        for i in range(20):
            has_events = spoof.evaluate("""(() => {
                const el = document.getElementById('dash-events');
                return el && el.children.length > 0 && !el.innerHTML.includes('No events yet');
            })()""")
            if has_events:
                print(f"  Events loaded after {i+1}s")
                break
            spoof.wait_for_timeout(1000)

        spoof.wait_for_timeout(PAUSE)

        # Step 6: Navigate to yopmail (same tab, one continuous video)
        print("[6/8] Opening yopmail inbox...")
        hide_caption(spoof)
        spoof.goto(YOPMAIL)
        spoof.wait_for_timeout(2000)
        show_caption(spoof, 6, total, "Checking the recipient's inbox",
                     f"Did the spoofed email from {FROM_ADDR} arrive at {RECIPIENT}@yopmail.com?")
        spoof.wait_for_timeout(PAUSE)

        spoof.fill("input#login", RECIPIENT)
        spoof.wait_for_timeout(TYPE_DELAY)
        spoof.click("input#login")
        spoof.keyboard.press("Enter")
        spoof.wait_for_timeout(5000)

        show_caption(spoof, 6, total, "Email delivered!",
                     "The spoofed email landed in the inbox")
        spoof.wait_for_timeout(PAUSE)

        # Step 7: Open the email (triggers tracking pixel)
        print("[7/8] Opening email (triggers tracking pixel)...")
        try:
            inbox_frame = spoof.frame("ifinbox")
            if inbox_frame:
                inbox_frame.wait_for_selector(".m", timeout=5000)
                show_caption(spoof, 7, total, "Opening the email",
                             "Loading the email triggers the hidden 1x1 tracking pixel")
                spoof.wait_for_timeout(1500)
                inbox_frame.click(".m")
                spoof.wait_for_timeout(PAUSE + 1000)
            else:
                print("  ifinbox frame not found")
                spoof.wait_for_timeout(2000)
        except Exception as e:
            print(f"  Could not open email: {e}")
            spoof.wait_for_timeout(2000)

        # Step 8: Navigate back to Spoof dashboard
        print("[8/8] Checking tracking on dashboard...")
        hide_caption(spoof)
        spoof.goto(f"{BASE_URL}/#dashboard")
        spoof.wait_for_timeout(2000)
        # Handle ngrok interstitial on return
        if "ngrok" in BASE_URL:
            try:
                spoof.click("button:has-text('Visit Site')", timeout=4000)
                spoof.wait_for_timeout(2000)
            except:
                pass

        # Click Dashboard tab to trigger loadDashboard
        spoof.click("button:has-text('Dashboard')")
        spoof.wait_for_timeout(2000)

        # Wait for events to appear
        print("  Waiting for events...")
        for i in range(20):
            has_events = spoof.evaluate("""(() => {
                const el = document.getElementById('dash-events');
                return el && el.children.length > 0 && !el.innerHTML.includes('No events yet');
            })()""")
            if has_events:
                event_count = spoof.evaluate("document.getElementById('dash-events').children.length")
                print(f"  Events loaded after {i+1}s ({event_count} events)")
                break
            spoof.wait_for_timeout(1000)

        show_caption(spoof, 8, total, "Full lifecycle complete",
                     "Send → Deliver → Open — all tracked on the dashboard")
        spoof.wait_for_timeout(PAUSE + 3000)

        hide_caption(spoof)
        spoof.wait_for_timeout(1500)

        print("\nDone! Closing browser...")
        context.close()
        browser.close()

    # Find and rename the recorded video
    videos = sorted(glob.glob("*.webm"), key=lambda f: os.path.getmtime(f), reverse=True)
    if videos:
        shutil.move(videos[0], "demo.webm")
        print(f"\n Video saved: demo.webm")
        # Convert to mp4
        os.system("ffmpeg -i demo.webm -c:v libx264 -preset fast -crf 23 demo.mp4 -y 2>/dev/null")
        if os.path.exists("demo.mp4"):
            print(f" Converted: demo.mp4")
    else:
        print("\n No video file found")


if __name__ == "__main__":
    main()
