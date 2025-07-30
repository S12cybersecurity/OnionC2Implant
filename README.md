# 🧅 OnionC2Implant – Modular Tor-based C2 Infrastructure

**OnionC2Implant** is a modular Command & Control (C2) infrastructure designed for research, red teaming, and ethical malware development.  
It consists of three main components:

1. **C++ Agent** – Lightweight implant communicating over HTTP(S)
2. **Redirector** – Programmable Python-based redirector using FastAPI
3. **C2 Server** – PHP backend hosted on a `.onion` hidden service via Tor

> 🛠️ **Initial implementation goal:**  
> The first working version will be limited to transferring a `.txt` file (command or payload) from the PHP C2 server to the C++ agent through the redirector. This serves as a functional proof of concept and provides a solid foundation for further expansion.

---

## 🔗 Architecture Overview

```txt
[C++ AGENT] → [REDIRECTOR (FastAPI)] → [C2 SERVER (PHP/.onion)]
