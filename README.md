# WebStrike Studio 🚀

**WebStrike Studio** is a multi-threaded asynchronous security orchestration engine built in Python/Tkinter. It unifies industry-standard reconnaissance, vulnerability assessment, TLS auditing, injection parsing, and dictionary-driven content discovery binaries into a single, high-performance tactical interface.

The application acts as a centralized engineering workbench to eliminate terminal fragmentation, streamline telemetry capture, and enforce structural sanity during high-tempo web-security assessments.

---

## 🛡️ Core Architectural Features

* **Asynchronous Subprocess Engine:** Built on top of a non-blocking thread pool combined with a thread-safe event queue (`queue.Queue`), ensuring the UI stays completely fluid and responsive even while streaming intensive high-volume output logs.
* **Targeted Matrix Grid Layout:** Features a multi-column visual grouping layout separating active recon nodes from dictionary fuzzers. The rightmost operational column is dedicated exclusively to content discovery binaries.
* **Granular Contextual Wordlists:** Supports highly specific custom payload arrays. Analysts can route a small directory list to `dirb`, an extensive API payload mapping list to `ffuf`, and custom file extensions to `feroxbuster` concurrently within a single target scan cycle.
* **Global Fallback Hierarchy:** If tool-specific wordlist pathways are omitted, the engine automatically passes target parameters through a validated global dictionary baseline fallback framework.
* **Defensive Archival Versioning:** Includes automated collision safeguards. The application interrogates the targeted tracking folder and dynamically applies incremental indices matching `base_name_{counter}.txt` schemas to prevent data loss or log regression overwrites.
* **Raw HTTP Injection Hooks:** Natively ingests post-data matrices and raw HTTP session capture request files for targeted verification arrays via `sqlmap` and `commix`.

---

## 📊 Integrated Security Suite Matrix

WebStrike Studio automatically audits system environment structures on initialization. If a native library is missing from your system `$PATH`, the matching node safely disables to protect runtime stability.

| Discipline | Core Binaries | Target Scope |
| :--- | :--- | :--- |
| **Active Reconnaissance** | `nmap`, `naabu`, `whatweb`, `wafw00f`, `katana` | Fingerprinting perimeter exposure, port status loops, firewall boundaries, and dynamic spidering hooks. |
| **Vulnerability Assessment** | `nuclei`, `nikto`, `wapiti`, `owasp-zap` | Fingerprint signature matching, CVE verification, and non-destructive surface misconfiguration parsing. |
| **Targeted Injection** | `sqlmap`, `commix` | Automated parameter parsing, parameter verification, and automated shell interaction validation. |
| **TLS / SSL Audits** | `sslscan`, `testssl.sh` | Protocol suite parsing, handshake validation, and cipher misconfiguration mapping. |
| **Content Discovery** | `dirb`, `gobuster`, `ffuf`, `feroxbuster` | Multi-threaded URI brute-forcing, file resource discovery, and endpoint identification. |

---

## 🛠️ Prerequisites

Before launching the controller, the host system must satisfy specific underlying operating system hooks, standard utility tools, and Python runtime modules:
* **Operating System:** Linux (Kali Linux, Parrot OS, or Ubuntu/Debian highly recommended)
* **Python Runtime:** Python `v3.8+` with the `tkinter` library tracking enabled.

---

## ⚡ Quick Start (Terminal Copy-and-Paste)

Run the following commands sequentially in your terminal to clone the repository, automate dependency configuration, and initialize the WebStrike Studio workspace:

```bash
# 1. Clone the repository down to your local testing environment
git clone [https://github.com/hackersroot/WebStrike-Studio.git](https://github.com/hackersroot/WebStrike-Studio.git)

# 2. Navigate into the root workspace directory
cd WebStrike-Studio

# 3. Provision executable permissions to the dependency installation engine
chmod +x install_dependencies.sh

# 4. Execute the installation controller with elevated privileges 
#    (Installs all required system binaries, Go packages, and Python modules)
sudo ./install_dependencies.sh

# 5. Initialize the WebStrike Studio asynchronous graphical dashboard
python3 WebStrike_Studio.py
