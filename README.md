# Chetana Browser Guard

Chrome extension (MV3) for real-time scam detection, built for India-specific threat patterns.

Version 6.2 — Chrome/Chromium only — Load unpacked (no Web Store listing yet)

---

## What It Does

Chetana scores every page you visit (0–100 trust) and scans for active fraud patterns before you interact. It runs a four-layer fallback chain so analysis works offline, on slow connections, and at scale:

```
domain cache (24h) → Ollama local (phi4-mini) → cloud API → local gate (10 rules, offline)
```

Key capabilities:
- Badge trust score (0–100) on every page
- WhatsApp Web live message scan
- Telegram Web forwarded-message scan
- Right-click context menu: "Check with Chetana"
- Side panel with full analysis
- Form guard — warns before submitting sensitive data to low-trust domains
- Link hover tooltips with pre-flight trust check
- Persistent domain cache (24h TTL)

---

## Install (Developer Mode)

1. Clone the repo:
   ```bash
   git clone https://github.com/MirrorDNA-Reflection-Protocol/chetana-browser
   cd chetana-browser
   ```
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked**
5. Select the `extension/` directory inside the repo
6. Pin the Chetana icon from the Extensions menu

No build step required. The extension is plain MV3 — no bundler, no compile.

---

## Optional: Local Ollama Backend (Deep Analysis)

The local backend runs phi4-mini via Ollama for on-device deep analysis. Without it, the extension falls back to the cloud API or the offline local gate.

**Requirements:** Ollama installed, ~3GB disk for phi4-mini.

```bash
# 1. Create the model
ollama create chetana-guard-fast -f models/chetana-guard-fast.Modelfile

# 2. Start the FastAPI backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8799

# Verify
curl http://localhost:8799/health
```

Backend listens on `localhost:8799`. The extension detects it automatically — no config needed.

---

## Architecture

```
Browser Request
      │
      ▼
┌─────────────────────┐
│ 1. Domain Cache     │  Hit? Return cached score instantly (24h TTL)
└────────┬────────────┘
         │ Miss
         ▼
┌─────────────────────┐
│ 2. Ollama Local     │  phi4-mini at localhost:8799 — full page analysis
│    (FastAPI)        │  Returns structured trust score + reason
└────────┬────────────┘
         │ Unavailable
         ▼
┌─────────────────────┐
│ 3. Cloud API        │  chetana.activemirror.ai/api/scan/full
│    (ActiveMirror)   │  Requires internet, higher latency
└────────┬────────────┘
         │ Unavailable
         ▼
┌─────────────────────┐
│ 4. Local Gate       │  10 India-specific regex/pattern rules
│    (offline)        │  Zero latency, zero network dependency
└─────────────────────┘
```

---

## What It Catches

Patterns tuned for Indian threat landscape:

| Category | Examples |
|---|---|
| UPI fraud | Fake payment links, QR code redirect scams |
| Digital arrest | Fake CBI/ED/police notices demanding payment |
| OTP theft | Fake OTP verification pages, SIM swap lures |
| Lottery / prize scams | "You won KBC/BSNL lottery" pages |
| Deepfake links | Video call scam landing pages |
| WhatsApp scams | Job offers, investment groups, forward chains |
| Telegram scams | Forwarded fraud messages, fake channel impersonation |

The offline local gate covers the most common 10 pattern classes without any network call.

---

## File Structure

```
chetana-browser/
├── extension/          # Chrome MV3 extension (load this)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── sidepanel/
│   └── icons/
├── backend/            # FastAPI server (optional, port 8799)
│   ├── main.py
│   └── requirements.txt
├── models/
│   └── chetana-guard-fast.Modelfile   # phi4-mini Ollama model def
└── README.md
```

---

## Legal

Advisory tool. Scores are probabilistic — not legal determinations. Not affiliated with any government body, law enforcement agency, or financial regulator.

Built by **ActiveMirror / N1 Intelligence OPC Pvt Ltd**, Bengaluru/Goa, India.
Part of the ActiveMirror / MirrorDNA ecosystem.

GitHub: https://github.com/MirrorDNA-Reflection-Protocol/chetana-browser

MIT License.
