<p align="center">
  <img src="https://img.shields.io/badge/python-3.6+-22c55e?style=flat-square&logo=python&logoColor=white" alt="Python 3.6+">
  <img src="https://img.shields.io/badge/dependencies-zero-22c55e?style=flat-square" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/file-single-22c55e?style=flat-square" alt="Single file">
  <img src="https://img.shields.io/github/license/carlos-rdz/spoof?style=flat-square&color=22c55e" alt="MIT License">
  <img src="https://img.shields.io/github/stars/carlos-rdz/spoof?style=flat-square&color=22c55e" alt="Stars">
</p>

<h1 align="center">
  <br>
  <img width="48" src="ghost.svg" alt="Spoofy">
  <br>
  Spoofy
  <br>
</h1>

<p align="center">
  <strong>See how easy it is to spoof an email. Then fix it.</strong>
  <br>
  <sub>A single-file email security testing tool with DNS analysis, spoofed sends, and open tracking.</sub>
</p>

<br>

<p align="center">
  <img src="demo.gif" alt="Spoofy Demo" width="800">
</p>

---

## Why Spoofy exists

Most companies think their email is secure. It isn't.

Spoofy lets you **test your own domains** in under 60 seconds. Probe SPF, DKIM, and DMARC records, send a spoofed test email, and watch in real-time whether it lands. If it does, you've got work to do.

> **This is not a hacking tool.** It's a mirror. It shows you what an attacker already sees.

## Features

| | Feature | Description |
|---|---|---|
| **1** | DNS Analysis | MX, SPF, DKIM, DMARC record lookups with vulnerability assessment |
| **2** | SMTP Probe | Tests mail server connectivity before sending |
| **3** | Spoofed Sends | Delivers email with custom From, Envelope-From, Subject, HTML body, and attachments |
| **4** | Open Tracking | Embeds a 1x1 tracking pixel — logs when recipients open the email |
| **5** | Live Monitor | Real-time activity feed of sends, deliveries, and opens |
| **6** | Zero Dependencies | Python 3.6+ standard library only. No pip install. No Docker. |

## Quick start

```bash
git clone https://github.com/carlos-rdz/spoof.git
cd spoof
python3 spoof_server.py
```

Open [localhost:8090](http://localhost:8090). That's it.

## The 3-step workflow

```
 1. Compose        2. Preflight / Send       3. Monitor
 ┌─────────────┐   ┌───────────────────┐   ┌──────────────┐
 │ From:       │   │ SPF:  ✓ soft fail │   │ ● Sent  9:41 │
 │ To:         │──▶│ DKIM: ✗ missing   │──▶│ ● Open  9:42 │
 │ Subject:    │   │ DMARC: ✗ none     │   │              │
 │ HTML body   │   │                   │   │ Open rate: ∞  │
 │ Attachment  │   │ [Confirm & Send]  │   │              │
 └─────────────┘   └───────────────────┘   └──────────────┘
```

**Step 1** — Compose your spoofed email with full HTML and optional PDF attachments.

**Step 2** — Run preflight to analyze the target domain's DNS records. See exactly which protections are missing. Then send.

**Step 3** — Watch your live dashboard. Did the email land? Did they open it? The tracking pixel tells you.

## Share publicly with ngrok

For open tracking to work across networks, expose the server:

```bash
ngrok http 8090
```

Spoofy auto-detects the tunnel and rewrites tracking pixel URLs to use your public ngrok address.

## Architecture

```
Browser (Single-Page UI)
    │
    ▼
spoof_server.py (localhost:8090)    ← single file, ~1900 lines
    │
    ├── GET  /              → serves the full UI (HTML + CSS + JS embedded)
    ├── GET  /preflight     → DNS lookups + SMTP probe
    ├── POST /send          → builds MIME message, delivers via SMTP :25
    ├── GET  /track/<id>.gif → 1x1 tracking pixel, logs open event
    ├── GET  /dashboard/events → JSON activity feed
    └── GET  /status        → ngrok tunnel detection
    │
    ▼
Target MX server (port 25)
```

Everything is in **one Python file**. The entire UI — HTML, CSS, JavaScript, animations — is embedded as a string. No build step. No node_modules. No webpack. Just `python3 spoof_server.py`.

## Running tests

```bash
python3 -m pytest test_spoof_server.py -v
```

## Re-recording the demo

```bash
pip install playwright && playwright install chromium
python3 demo.py                                      # localhost
python3 demo.py https://your-url.ngrok.io            # ngrok
ffmpeg -i demo.webm -vf 'fps=8,scale=800:-1:flags=lanczos' -loop 0 demo.gif -y
```

Override inputs by creating a `demo_config.py` (gitignored) — see `demo.py` for the expected exports.

## FAQ

<details>
<summary><strong>Is this legal?</strong></summary>
<br>
Only when used against domains and recipients you have explicit permission to test. Unauthorized email spoofing violates laws in most jurisdictions. Spoofy is for security professionals, pentesters, and domain owners evaluating their own infrastructure.
</details>

<details>
<summary><strong>Does this work on Gmail / Outlook / etc?</strong></summary>
<br>
It depends on the target domain's DNS configuration. Domains with properly configured SPF, DKIM, and DMARC (with <code>p=reject</code>) will block or quarantine spoofed emails. That's the whole point — Spoofy helps you verify those protections are in place.
</details>

<details>
<summary><strong>Why single-file?</strong></summary>
<br>
Portability. You can <code>scp</code> it to any server with Python 3.6+, run it, and you're live. No dependency hell. No containerization required. One file to audit, one file to deploy.
</details>

<details>
<summary><strong>Why port 25?</strong></summary>
<br>
SMTP delivery happens on port 25. Some ISPs and cloud providers block outbound port 25. If you're running from a machine where port 25 is blocked, you'll see connection errors in the SMTP log. Try running from a VPS or server with open port 25.
</details>

## License

[MIT](LICENSE) — do whatever you want with it.

---

<p align="center">
  <sub>For educational and authorized security testing purposes only.</sub>
  <br>
  <sub>Built with Python and questionable judgment.</sub>
</p>
