# 🧅 OnionC2Implant – Modular Tor-based C2 Infrastructure

**OnionC2Implant** is a modular Command & Control (C2) infrastructure designed for research, red teaming, and ethical malware development.  
It consists of three main components:

1. **C++ Agent** – Lightweight implant communicating over HTTP(S)
2. **Redirector** – Programmable Python-based redirector using FastAPI
3. **C2 Server** – PHP backend hosted on a `.onion` hidden service via Tor

---

## 🔗 Architecture Overview

```txt
[C++ AGENT] → [REDIRECTOR (FastAPI)] → [C2 SERVER (PHP/.onion)]
