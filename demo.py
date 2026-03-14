#!/usr/bin/env python3
"""
demo.py — Record a full Spoof demo video using Playwright.

Usage:
    python3 demo.py                          # uses localhost:8090
    python3 demo.py https://xxxx.ngrok.io    # uses ngrok URL

Outputs: demo.webm (raw video)
Requires: pip install playwright && playwright install chromium
"""

import sys
import subprocess
import json
from playwright.sync_api import sync_playwright

# ── Config ──
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
YOPMAIL = "https://yopmail.com"
RECIPIENT = "spooftest"  # spooftest@yopmail.com
FROM_ADDR = "testing@evil.com"
SUBJECT = "Security Test — Spoof Demo"
HTML_BODY = """<div style="font-family:Arial;padding:20px;background:#f9f9f9;border-radius:8px;max-width:500px;margin:0 auto">
  <h2 style="color:#e53e3e">⚠ Account Verification Required</h2>
  <p>Your account needs immediate verification. Click the link below to secure your account.</p>
  <a href="#" style="display:inline-block;background:#e53e3e;color:white;padding:10px 24px;border-radius:4px;text-decoration:none;margin:12px 0">Verify Now</a>
  <p style="color:#888;font-size:12px">This is a security test sent via Spoof.</p>
</div>"""

PAUSE = 1500  # ms between actions (readable pacing)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, args=["--window-size=1280,800"])
        context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            record_video_dir=".",
            record_video_size={"width": 1280, "height": 800},
            ignore_https_errors=True,
        )
        page = context.new_page()

        # ── 1. Open Spoof UI ──
        print("[1/8] Opening Spoof UI...")
        page.goto(BASE_URL)
        # Dismiss ngrok browser warning if present
        if "ngrok" in BASE_URL:
            try:
                page.click("button:has-text('Visit Site')", timeout=3000)
            except:
                pass
        page.wait_for_timeout(PAUSE)

        # ── 2. Fill the form ──
        print("[2/8] Filling form...")
        page.fill("#from_addr", FROM_ADDR)
        page.wait_for_timeout(500)
        page.fill("#to_addr", f"{RECIPIENT}@yopmail.com")
        page.wait_for_timeout(500)
        page.fill("#subject", SUBJECT)
        page.wait_for_timeout(500)

        # Clear default HTML and type our demo body
        page.click("#body_html")
        page.keyboard.press("Meta+a")
        page.fill("#body_html", HTML_BODY)
        page.wait_for_timeout(PAUSE)

        # ── 3. Run Preflight ──
        print("[3/8] Running preflight...")
        page.click("#probe-btn")
        page.wait_for_timeout(4000)  # let DNS results load

        # Open DNS section to show results
        page.click("#sec-dns .section-header")
        page.wait_for_timeout(PAUSE)

        # ── 4. Send email ──
        print("[4/8] Sending email...")
        page.click("#send-btn")
        page.wait_for_timeout(800)

        # Password prompt appears — type password
        page.fill("#pw-input", "password")
        page.wait_for_timeout(500)
        page.click("#pw-inline button")
        page.wait_for_timeout(5000)  # wait for send to complete

        # Open SMTP log section
        page.click("#sec-log .section-header")
        page.wait_for_timeout(PAUSE)

        # ── 5. Switch to Dashboard ──
        print("[5/8] Checking dashboard...")
        page.click("button:has-text('Dashboard')")
        page.wait_for_timeout(2000)

        # ── 6. Check yopmail inbox ──
        print("[6/8] Opening yopmail inbox...")
        page.goto(f"{YOPMAIL}")
        page.wait_for_timeout(PAUSE)

        # Type recipient name and check inbox
        page.fill("input#login", RECIPIENT)
        page.wait_for_timeout(500)
        # Click the arrow/submit button next to the input
        page.click("input#login")
        page.keyboard.press("Enter")
        page.wait_for_timeout(4000)

        # ── 7. Open the email (triggers tracking pixel) ──
        print("[7/8] Opening email (triggers tracking pixel)...")
        try:
            # Yopmail loads inbox in an iframe called "ifinbox"
            inbox_frame = page.frame("ifinbox")
            if inbox_frame:
                inbox_frame.wait_for_selector(".m", timeout=5000)
                inbox_frame.click(".m")
                page.wait_for_timeout(3000)
            else:
                print("  Note: ifinbox frame not found, trying direct click")
                page.wait_for_timeout(2000)
        except Exception as e:
            print(f"  Note: Could not click email in inbox: {e}")
            page.wait_for_timeout(2000)

        # ── 8. Back to Spoof dashboard to see tracking ──
        print("[8/8] Checking tracking on dashboard...")
        page.goto(f"{BASE_URL}/#dashboard")
        if "ngrok" in BASE_URL:
            try:
                page.click("button:has-text('Visit Site')", timeout=3000)
            except:
                pass
        page.wait_for_timeout(3000)

        # Final pause on dashboard
        page.wait_for_timeout(2000)

        print("\nDone! Closing browser...")
        context.close()
        browser.close()

    # Find the recorded video
    import glob
    videos = sorted(glob.glob("*.webm"), key=lambda f: __import__("os").path.getmtime(f), reverse=True)
    if videos:
        import shutil
        shutil.move(videos[0], "demo.webm")
        print(f"\n✅ Video saved: demo.webm")
        print("Convert to GIF:  ffmpeg -i demo.webm -vf 'fps=10,scale=960:-1' -loop 0 demo.gif")
    else:
        print("\n⚠ No video file found — check Playwright output")


if __name__ == "__main__":
    main()
