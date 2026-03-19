# 🔥 Elite Recon Scanner

Advanced asynchronous network reconnaissance tool built in Python.
Designed for **fast, scalable, and safe infrastructure auditing**.

---

## 🚀 Features

### ⚡ High-Speed Scanning

* Async-based concurrent scanning
* Optimized performance (low error rate)
* Multi-IP & CIDR support

---

### 🔍 Service Detection

* Automatic identification of:

  * HTTP / HTTPS
  * SSH
  * FTP
  * RDP
  * RTSP (cameras)
* Banner grabbing for deeper insights

---

### 🧠 OS Fingerprinting

* Detects probable operating systems:

  * Linux / Unix
  * Windows
  * Cisco devices

---

### 🌐 Web Fingerprinting

* Detects:

  * nginx / Apache / IIS
  * PHP / ASP.NET
* Basic CMS detection (WordPress)
* HTTP header analysis

---

### 📷 Camera Detection (RTSP)

* Identifies exposed RTSP services
* Flags potential camera endpoints
* Safe detection (no stream access)

---

### ☁️ Infrastructure Detection

* Identifies reverse proxies / CDN hints
* Cloud / protection layer indicators (e.g., Cloudflare patterns)

---

### 🌍 DNS & Domain Support

* Scan domains directly:

```bash
python main.py example.com
```

* Automatic DNS resolution

---

### ⚠️ Risk Analysis

Flags potentially dangerous exposures:

* Telnet (23)
* FTP (21)
* RDP (3389)
* RTSP (554)

---

### 💾 JSON Export

Structured output for:

* SIEM integration
* Security audits
* Automation pipelines

---

## 📦 Installation

### Requirements

* Python 3.8+

Install dependencies:

```bash
pip install aiohttp
```

---

## 🛠 Usage

### Scan a network

```bash
python main.py 192.168.1.0/24
```

### Scan a single host

```bash
python main.py 192.168.1.1
```

### Scan a domain

```bash
python main.py example.com
```

---

## 📊 Example Output

```
[+] 192.168.1.10:22 → SSH (Linux)
    └─ SSH-2.0-OpenSSH_8.2

[+] 192.168.1.15:80 → HTTP (Linux)
    └─ Server: nginx

⚠️ Risk: RDP exposed
```

---

## 📁 Output File

Results are saved in:

```
elite_scan.json
```

Structure:

```json
{
  "ip": "192.168.1.1",
  "port": 80,
  "service": "HTTP",
  "os": "Linux",
  "risk": "",
  "banner": "..."
}
```

---

## ⚠️ Disclaimer

This tool is intended for:

* Authorized security testing
* Internal audits
* Educational purposes

**Do not scan networks without permission.**

---

## 🧠 Roadmap (Future Enhancements)

* Subdomain enumeration
* Advanced OS fingerprinting
* Vulnerability detection modules
* Reporting (HTML / PDF)
* Distributed scanning

---

## 👨‍💻 Author

Elite Recon Project
Built for advanced network visibility and security auditing.

---

## ⭐ Contribute

Pull requests are welcome.
For major changes, open an issue first.

---

## 📜 License

MIT License
