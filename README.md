# Spoof

Email security testing tool. Single-file Python server with a web UI for probing SPF/DKIM/DMARC records and sending test emails via raw SMTP.

## What it does

- **DNS analysis** — MX, SPF, DKIM, DMARC record lookups for any domain
- **SMTP probe** — tests mail server connectivity before sending
- **Spoofed sends** — delivers email with configurable From, Envelope-From, To, Subject, and HTML body via raw SMTP on port 25
- **Open tracking** — embeds a 1x1 tracking pixel; logs when recipients open the email
- **Dashboard** — real-time activity feed of send attempts, deliveries, and opens
- **Attachments** — supports file attachments on outgoing emails

## Quick start

```bash
python3 spoof_server.py
```

Open `http://localhost:8090`. No dependencies beyond Python 3.6+ standard library.

Custom port:

```bash
python3 spoof_server.py 9000
```

## Share publicly (ngrok)

For open tracking to work — or to share the UI with someone else — expose the server with ngrok:

```bash
ngrok http 8090
```

The app auto-detects the ngrok tunnel and uses the public URL for tracking pixels. The status pill in the top-right turns green when connected.

## How it works

```
Browser (Web UI)
    |
    v
spoof_server.py (localhost:8090)
    |
    |-- GET  /              -> serves the single-page UI
    |-- GET  /preflight     -> DNS lookups + SMTP probe
    |-- POST /send          -> builds MIME message, delivers via SMTP :25
    |-- GET  /track/<id>.gif -> 1x1 pixel, logs open event
    |-- GET  /dashboard/events -> JSON activity feed
    |-- GET  /status        -> ngrok tunnel detection
    |
    v
Target MX server (port 25)
```

## Send protection

The send action is password-gated in the UI (hardcoded to `password`). This is a simple gate to prevent accidental sends, not real authentication.

## Running tests

```bash
python3 -m pytest test_spoof_server.py -v
```

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only test against domains and recipients you have permission to test. Unauthorized email spoofing may violate laws in your jurisdiction.

## License

MIT
