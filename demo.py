#!/usr/bin/env python3
"""
demo.py — Record a Spoofy demo video using Playwright.

Clean recording with visible cursor, no zoom/camera effects.

Usage:
    python3 demo.py                          # uses localhost:8090
    python3 demo.py https://xxxx.ngrok.io    # uses ngrok URL

Outputs: demo.webm / demo.mp4
Requires: pip install playwright && playwright install chromium
"""

import sys
import glob
import shutil
import os
import json
import urllib.request

from playwright.sync_api import sync_playwright

# ── Try to import private demo config, fall back to defaults ──
try:
    from demo_config import FROM_ADDR, RECIPIENT, SUBJECT, HTML_BODY, ATTACHMENT_PATH, ATTACHMENT_NAME
    HAS_ATTACHMENT = os.path.exists(ATTACHMENT_PATH)
except ImportError:
    FROM_ADDR = "security@acme-corp.com"
    RECIPIENT = "spoofydemo"
    SUBJECT = "ACME Corp — Email Security Assessment Results"
    HTML_BODY = """\
<div style="font-family:system-ui,Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
  <div style="background:#166534;color:white;padding:16px 20px;border-radius:8px 8px 0 0">
    <h2 style="margin:0;font-size:18px">ACME Corp Security Team</h2>
    <p style="margin:4px 0 0;opacity:0.8;font-size:13px">Internal Security Assessment</p>
  </div>
  <div style="background:#ffffff;border:1px solid #e5e7eb;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <p style="margin:0 0 12px;color:#111">Hi Team,</p>
    <p style="margin:0 0 12px;color:#374151;line-height:1.6">
      Attached is the Q1 2026 email security assessment report. We identified
      <strong style="color:#dc2626">2 domains</strong> with missing or misconfigured
      email authentication records that could allow spoofing.
    </p>
    <div style="background:#fef2f2;border-left:4px solid #dc2626;padding:12px 16px;margin:16px 0;border-radius:0 6px 6px 0">
      <strong style="color:#991b1b">Action Required:</strong>
      <span style="color:#7f1d1d"> Review findings and implement SPF/DKIM/DMARC fixes within 14 days.</span>
    </div>
    <p style="margin:16px 0 0;color:#6b7280;font-size:12px">
      This is a simulated email for demonstration purposes only.
    </p>
  </div>
</div>"""
    ATTACHMENT_PATH = "sample_report.pdf"
    ATTACHMENT_NAME = "ACME_Security_Assessment_Q1_2026.pdf"
    HAS_ATTACHMENT = os.path.exists(ATTACHMENT_PATH)


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8090"
YOPMAIL = "https://yopmail.com"

PAUSE = 2500
TYPE_DELAY = 400

# ── Visible cursor CSS ──
SETUP_JS = """
const style = document.createElement('style');
style.id = 'demo-styles';
style.textContent = `
  #demo-cursor {
    position: fixed; z-index: 999999; pointer-events: none;
    width: 20px; height: 20px;
    border: 2px solid rgba(22,101,52,0.7);
    border-radius: 50%;
    background: rgba(34,197,94,0.15);
    transform: translate(-50%, -50%);
    transition: left 0.35s cubic-bezier(.23,1,.32,1), top 0.35s cubic-bezier(.23,1,.32,1), transform 0.15s ease;
  }
  #demo-cursor.click {
    transform: translate(-50%, -50%) scale(0.7);
    background: rgba(34,197,94,0.35);
  }
`;
document.head.appendChild(style);
if (!document.getElementById('demo-cursor')) {
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    document.body.appendChild(cursor);
}
"""


def inject_cursor(page):
    page.evaluate(SETUP_JS)


def move_to(page, selector, click=False):
    page.evaluate(f"""(() => {{
        const el = document.querySelector('{selector}');
        const c = document.getElementById('demo-cursor');
        if (el && c) {{
            const r = el.getBoundingClientRect();
            c.style.left = (r.left + r.width/2) + 'px';
            c.style.top = (r.top + r.height/2) + 'px';
        }}
    }})()""")
    page.wait_for_timeout(400)
    if click:
        page.evaluate("""(() => {
            const c = document.getElementById('demo-cursor');
            if (c) { c.classList.add('click'); setTimeout(() => c.classList.remove('click'), 150); }
        })()""")
        page.click(selector)


def move_cursor_xy(page, x, y):
    page.evaluate(f"""(() => {{
        const c = document.getElementById('demo-cursor');
        if (c) {{ c.style.left = '{x}px'; c.style.top = '{y}px'; }}
    }})()""")


def fill_with_cursor(page, selector, value):
    move_to(page, selector)
    page.fill(selector, value)


def handle_ngrok(page):
    try:
        page.click("button:has-text('Visit Site')", timeout=4000)
        page.wait_for_timeout(2000)
    except:
        pass


def get_track_ids():
    try:
        resp = urllib.request.urlopen(f"{BASE_URL}/track-events", timeout=5)
        data = json.loads(resp.read())
        return list(data.keys())
    except:
        return []


def trigger_open(track_id):
    try:
        urllib.request.urlopen(f"{BASE_URL}/track/{track_id}.gif", timeout=5)
        print(f"  Triggered open for {track_id}")
    except:
        pass


def nav_prompt(page, title, subtitle):
    """Dark overlay transition prompt."""
    page.evaluate(f"""(() => {{
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed; inset: 0; z-index: 99999;
            background: rgba(0,0,0,0.75); display: flex;
            align-items: center; justify-content: center;
            pointer-events: none;
            animation: demoFadeIn 0.4s ease-out;
        `;
        overlay.innerHTML = `
            <div style="text-align:center;color:white;font-family:system-ui,sans-serif;">
                <div style="font-size:28px;font-weight:700;margin-bottom:8px">{title}</div>
                <div style="font-size:16px;opacity:0.7">{subtitle}</div>
            </div>
        `;
        if (!document.getElementById('demo-fade-style')) {{
            const s = document.createElement('style');
            s.id = 'demo-fade-style';
            s.textContent = '@keyframes demoFadeIn{{from{{opacity:0}}to{{opacity:1}}}}';
            document.head.appendChild(s);
        }}
        document.body.appendChild(overlay);
    }})()""")
    page.wait_for_timeout(1800)


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

        # ── 1: Open Spoofy ──
        print("[1] Opening Spoofy...")
        page.goto(BASE_URL)
        if "ngrok" in BASE_URL:
            handle_ngrok(page)
        page.wait_for_timeout(1200)
        inject_cursor(page)
        page.wait_for_timeout(PAUSE - 700)

        # ── 2: Fill compose form ──
        print("[2] Composing email...")
        fill_with_cursor(page, "#from_addr", FROM_ADDR)
        page.wait_for_timeout(TYPE_DELAY)
        fill_with_cursor(page, "#envelope_from", FROM_ADDR)
        page.wait_for_timeout(TYPE_DELAY)
        fill_with_cursor(page, "#to_addr", f"{RECIPIENT}@yopmail.com")
        page.wait_for_timeout(TYPE_DELAY)
        fill_with_cursor(page, "#subject", SUBJECT)
        page.wait_for_timeout(TYPE_DELAY)

        # Fill HTML body
        move_to(page, "#body_html")
        page.click("#body_html")
        page.keyboard.press("Meta+a")
        page.fill("#body_html", HTML_BODY)
        page.wait_for_timeout(600)

        # Attach PDF if available
        if HAS_ATTACHMENT:
            abs_path = os.path.abspath(ATTACHMENT_PATH)
            page.set_input_files("#file-input", abs_path)
            page.wait_for_timeout(1000)

        # Show preview
        page.evaluate("""(() => {
            const iframe = document.getElementById('preview-iframe-main');
            if (iframe) iframe.scrollIntoView({behavior:'smooth', block:'center'});
        })()""")
        page.wait_for_timeout(800)
        move_to(page, "#preview-iframe-main")
        page.wait_for_timeout(PAUSE)

        # ── 3: Run Preflight ──
        print("[3] Running preflight...")
        page.evaluate("document.getElementById('probe-btn')?.scrollIntoView({behavior:'smooth',block:'center'})")
        page.wait_for_timeout(500)
        move_to(page, "#probe-btn", click=True)
        page.wait_for_timeout(7000)

        # Show DNS results
        page.evaluate("document.getElementById('sec-dns')?.scrollIntoView({behavior:'smooth',block:'center'})")
        move_to(page, "#sec-dns")
        page.wait_for_timeout(PAUSE)

        # ── 4: Send email ──
        print("[4] Sending email...")
        page.evaluate("window.scrollTo({top:0, behavior:'smooth'})")
        page.wait_for_timeout(400)

        move_to(page, "#send-btn", click=True)
        page.wait_for_timeout(1000)
        fill_with_cursor(page, "#pw-input", "password")
        page.wait_for_timeout(400)
        move_to(page, "#pw-inline button", click=True)
        page.wait_for_timeout(10000)

        # Show SMTP log
        page.evaluate("document.getElementById('sec-log')?.scrollIntoView({behavior:'smooth',block:'center'})")
        move_to(page, "#sec-log")
        page.wait_for_timeout(PAUSE)

        # ── 5: Monitor (auto-advances after send) ──
        print("[5] Checking monitor...")
        page.evaluate("window.scrollTo({top:0, behavior:'smooth'})")
        page.wait_for_timeout(1500)

        for i in range(12):
            has_events = page.evaluate("""(() => {
                const el = document.getElementById('dash-events');
                return el && el.children.length > 0 && !el.innerHTML.includes('No events yet');
            })()""")
            if has_events:
                print(f"  Events loaded after {i+1}s")
                break
            page.wait_for_timeout(1000)

        move_to(page, "#dash-events")
        page.wait_for_timeout(PAUSE)

        # ── 6: Check yopmail ──
        print("[6] Opening yopmail inbox...")
        nav_prompt(page, "Checking recipient inbox", f"{RECIPIENT}@yopmail.com")
        page.goto(YOPMAIL)
        page.wait_for_timeout(2000)
        inject_cursor(page)

        fill_with_cursor(page, "input#login", RECIPIENT)
        page.wait_for_timeout(TYPE_DELAY)
        page.keyboard.press("Enter")
        page.wait_for_timeout(5000)
        page.wait_for_timeout(PAUSE)

        # ── 7: Open email ──
        print("[7] Opening email...")
        try:
            inbox_frame = page.frame("ifinbox")
            if inbox_frame:
                inbox_frame.wait_for_selector(".m", timeout=5000)
                move_cursor_xy(page, 200, 300)
                page.wait_for_timeout(500)
                inbox_frame.click(".m")
                page.wait_for_timeout(PAUSE)

                # Trigger tracking pixel
                track_ids = get_track_ids()
                for tid in track_ids:
                    trigger_open(tid)
                page.wait_for_timeout(500)
        except Exception as e:
            print(f"  Could not open email: {e}")
            page.wait_for_timeout(2000)

        # ── 8: Back to Spoofy monitor ──
        print("[8] Verifying open tracking...")
        nav_prompt(page, "Back to Spoofy", "Verifying open tracking")
        page.goto(f"{BASE_URL}/#dashboard")
        page.wait_for_timeout(2000)
        if "ngrok" in BASE_URL:
            handle_ngrok(page)
        inject_cursor(page)

        page.evaluate("if (typeof goStep === 'function') goStep(3)")
        page.wait_for_timeout(2000)

        for i in range(12):
            has_open = page.evaluate("""(() => {
                const el = document.getElementById('dash-events');
                return el && el.innerHTML.includes('open');
            })()""")
            if has_open:
                print(f"  Open event detected after {i+1}s")
                break
            page.wait_for_timeout(1000)

        move_to(page, "#dash-events")
        page.wait_for_timeout(PAUSE + 1000)

        # Final pause
        page.wait_for_timeout(2000)

        print("\nDone! Closing browser...")
        context.close()
        browser.close()

    # Find and rename the recorded video
    videos = sorted(glob.glob("*.webm"), key=lambda f: os.path.getmtime(f), reverse=True)
    if videos:
        shutil.move(videos[0], "demo.webm")
        print(f"\n Video saved: demo.webm")
        os.system("ffmpeg -ss 0.3 -i demo.webm -c:v libx264 -preset fast -crf 23 demo.mp4 -y 2>/dev/null")
        if os.path.exists("demo.mp4"):
            print(f" Converted: demo.mp4")
    else:
        print("\n No video file found")


if __name__ == "__main__":
    main()
