# Package Security Scanner

Supply chain attack detection tool for Python (PyPI) and npm packages. Inspired by real-world incidents including the litellm 1.82.8 attack (CVE 2026-03-24), event-stream, ua-parser-js, and node-ipc compromises.

## 🎯 Scanner Overview & Detection Capabilities

### Python Package Scanner (`pkg_scan.sh`)

**Purpose**: Scans Python packages from PyPI for malicious code patterns without installation. Downloads the package tarball, extracts it, and performs 12-step static analysis to detect supply chain attacks.

**How it works**:
1. Downloads package via `pip download` (no installation)
2. Extracts wheel (.whl) or tarball (.tar.gz)
3. Scans all Python files for 50+ malicious patterns
4. Generates severity-scored report (CRITICAL/HIGH/MEDIUM/LOW)

**12-Step Detection Coverage**:

| Step | Category | What It Checks |
|------|----------|---|
| **1** | Download | Fetches package from PyPI registry safely |
| **2** | Extraction | Unpacks wheel or tarball for analysis |
| **3** | .pth Backdoors | Detects auto-executing .pth files (litellm attack vector) |
| **4** | Obfuscation | Base64 decode chains, `exec()`, `compile()`, `marshal`, `pickle`, `zlib` compression |
| **5** | Subprocess & Network | `subprocess.Popen`, `os.system`, `curl` POST, HTTP exfiltration |
| **6** | Credential Harvesting | SSH keys, AWS/GCP/Azure/Docker credentials, crypto wallets, browser auth tokens |
| **7** | Encryption & Staging | RSA/AES encryption, tar archive creation (pre-exfil staging) |
| **8** | Install Hooks | `setup.py` abuse, `pyproject.toml` hooks, RECORD file tampering |
| **9** | Reverse Shell & Persistence | Socket+subprocess combos, PTY allocation, cron jobs, systemd services, Windows registry Run keys |
| **10** | Import Hook Abuse | `sys.meta_path` hijacking, `__builtins__` tampering, `ctypes` native code execution, `sys.settrace` spying |
| **11** | Surveillance | Keyloggers (pynput), screen/webcam capture, microphone recording, browser profile theft, clipboard access, Discord/Telegram exfil |
| **12** | Anti-Analysis & Evasion | Debugger detection, VM/sandbox detection, time-bombs, geofencing, probabilistic execution, ROT13 obfuscation |

---

### npm Package Scanner (`npm_scan.sh`)

**Purpose**: Scans npm packages from the registry for malicious code patterns without installation. Downloads the tarball, extracts it, and performs 13-step static analysis to detect supply chain attacks in Node.js/JavaScript packages.

**How it works**:
1. Downloads package via `npm pack` (no installation, ignores scripts)
2. Extracts tarball contents
3. Analyzes `package.json` lifecycle hooks
4. Scans all JS/TS source files for 60+ malicious patterns
5. Generates severity-scored report (CRITICAL/HIGH/MEDIUM/LOW)

**13-Step Detection Coverage**:

| Step | Category | What It Checks |
|------|----------|---|
| **1** | Download | Fetches package from npm registry safely via `npm pack` |
| **2** | Extraction | Unpacks tarball for analysis |
| **3** | Lifecycle Hooks | `preinstall`, `install`, `postinstall`, `prepare`, `prepublish` scripts (primary npm attack vector) |
| **4** | Obfuscation | `eval()`, `Function()` constructor, `Buffer.from(...,'base64')`, JSFuck patterns, charcode obfuscation |
| **5** | child_process & Shell | `child_process.exec/spawn`, `os.system`, `shelljs`, `execa` (shell execution) |
| **6** | Network Exfiltration | HTTP clients (axios, got, node-fetch), POST requests, hardcoded IPs, WebSocket, DNS tunneling |
| **7** | Credential Harvesting | SSH keys, AWS/GCP/Azure/Docker credentials, `.npmrc` tokens, GitHub tokens, crypto wallets |
| **8** | Native Addons | Compiled `.node` binaries (opaque to source analysis) in unconventional paths |
| **9** | Metadata Red Flags | Missing repository links, typosquatting detection, fresh versions with no history |
| **10** | Prototype Pollution & Injection | `__proto__` mutation, `constructor.prototype` abuse, dynamic `require()` with user input, XSS sinks, path traversal, unsafe YAML/serialization |
| **11** | Reverse Shell & Persistence | `net.Socket` creation, socket-to-spawn piping, interactive shell strings, cron/scheduler libraries, Windows registry, `pm2 startup` |
| **12** | Electron/Browser Exploitation | Dangerous Electron configs (`nodeIntegration:true`, `contextIsolation:false`), `electron.remote.require()`, browser profile theft, clipboard access |
| **13** | Cryptomining, Bots & Anti-Analysis | Mining pools (xmrig, coinhive), Discord/Telegram/Slack bot exfil, Ethereum wallets, debugger detection, VM detection, CI environment evasion, time-bombs, probabilistic execution |

## 📦 Prerequisites

- **Python 3.6+** (for Python package scanning)
- **Node.js & npm** (for npm package scanning)
- **bash** (see platform-specific setup below)

### Platform-Specific Requirements

#### Windows
Install **one** of the following:
1. **Git for Windows** (recommended) — Includes Git Bash
   - Download: https://git-scm.com/download/win
   - During installation, select "Use Git and optional Unix tools from the Command Prompt"

2. **Windows Subsystem for Linux (WSL)**
   - Open PowerShell as Administrator
   - Run: `wsl --install`
   - Restart your computer

#### macOS
- bash is pre-installed ✓
- Ensure you have Python 3 and/or Node.js installed via Homebrew:
  ```bash
  brew install python3 node
  ```

#### Linux
- bash is pre-installed ✓
- Install Python 3 and/or Node.js via your package manager:
  ```bash
  # Debian/Ubuntu
  sudo apt install python3 python3-pip nodejs npm
  
  # RHEL/Fedora
  sudo dnf install python3 python3-pip nodejs npm
  ```

## 🚀 Usage

### Option 1: Universal Python Launcher (Recommended)

The easiest way to use the scanner on **any platform**:

```bash
python scan.py
```

Or on some systems:
```bash
python3 scan.py
```

This will present a menu to select Python or npm scanner.

---

### Option 2: Platform-Specific Launchers

#### **Windows**

Double-click or run from Command Prompt:
```cmd
windows\scan-python-pkg.bat
```
```cmd
windows\scan-npm-pkg.bat
```

Or from PowerShell:
```powershell
.\windows\scan-python-pkg.bat
.\windows\scan-npm-pkg.bat
```

#### **macOS**

First, make the launcher executable (one-time setup):
```bash
chmod +x macos/scan-python-pkg.sh
chmod +x macos/scan-npm-pkg.sh
```

Then run:
```bash
./macos/scan-python-pkg.sh
```
```bash
./macos/scan-npm-pkg.sh
```

#### **Linux**

Make executable (one-time setup):
```bash
chmod +x main_script/pkg_scan.sh
chmod +x main_script/npm_scan.sh
```

Run directly:
```bash
./main_script/pkg_scan.sh
```
```bash
./main_script/npm_scan.sh
```

---

### Option 3: Direct Execution (Advanced)

If you have bash in your PATH, you can run the scripts directly:

```bash
bash main_script/pkg_scan.sh      # Python scanner
bash main_script/npm_scan.sh      # npm scanner
```

## 📋 How It Works

1. **No Installation Required** — Downloads package tarball directly from registry
2. **Static Analysis Only** — Extracts and inspects source code without executing
3. **Pattern Matching** — Detects known malicious patterns from real attacks
4. **Severity Scoring** — CRITICAL / HIGH / MEDIUM / LOW findings
5. **Auto Cleanup** — Temporary files removed automatically

### Example: Scanning a Python Package

```
$ python scan.py
╔══════════════════════════════════════════════════════════╗
║       Package Security Scanner - Launcher               ║
╚══════════════════════════════════════════════════════════╝

Select scanner type:
  1. Python Package Scanner (PyPI)
  2. npm Package Scanner (npm/Node.js)
  3. Exit

Enter choice (1-3): 1

Starting Python Package Scanner...
============================================================

  ____  _  _______ ____   ____    _    _   _
 |  _ \| |/ / ____/ ___| / ___|  / \  | \ | |
 | |_) | ' /|  _| \___ \| |     / _ \ |  \| |
 |  __/| . \| |___ ___) | |___ / ___ \| |\  |
 |_|   |_|\_\_____|____/ \____/_/   \_\_| \_|

  Python Package Malicious Code Scanner
  Supply Chain Attack Detection Tool
  ─────────────────────────────────────────────

Package name (e.g. litellm): requests
Version to check (leave blank for latest): 
Operating system [macos/linux/windows]: windows
```

## 🔍 Interpreting Results

### Severity Levels

- **🔴 CRITICAL** — High-confidence supply chain attack indicators
  - **Action**: DO NOT INSTALL. Rotate all credentials if already installed.
  
- **🟠 HIGH** — Suspicious patterns that require investigation
  - **Action**: Manual review required before installation.
  
- **🟡 MEDIUM** — Potentially legitimate but worth verifying
  - **Action**: Review in context of package purpose.
  
- **🔵 LOW** — Low-risk observations
  - **Action**: Informational only.

### Zero Findings ≠ Safe

Static analysis has limitations:
- Cannot detect time-bombs or conditional logic
- Cannot analyze compiled native code (.node, .so, .pyd)
- Cannot detect zero-day techniques
- Always verify package source and maintainer reputation

## 📁 Project Structure

```
package-scanner/
├── main_script/
│   ├── pkg_scan.sh          # Python package scanner (core)
│   └── npm_scan.sh          # npm package scanner (core)
├── windows/
│   ├── scan-python-pkg.bat  # Windows launcher for Python scanner
│   └── scan-npm-pkg.bat     # Windows launcher for npm scanner
├── macos/
│   ├── scan-python-pkg.sh   # macOS launcher for Python scanner
│   └── scan-npm-pkg.sh      # macOS launcher for npm scanner
├── scan.py                  # Universal cross-platform launcher
└── README.md                # This file
```

## 🔧 Troubleshooting

### "bash not found" on Windows
- Install Git for Windows or WSL (see Prerequisites above)
- Restart your terminal after installation
- Verify installation: `bash --version`

### "Permission denied" on macOS/Linux
- Make scripts executable: `chmod +x macos/*.sh main_script/*.sh`

### "pip/npm not found"
- Install Python: https://www.python.org/downloads/
- Install Node.js: https://nodejs.org/
- Restart terminal after installation

### Script shows "No suspicious patterns" for known malicious package
- This tool uses pattern matching, not AI/ML
- New attack techniques may not be covered
- Always combine with:
  - `npm audit` / `pip-audit`
  - GitHub repository review
  - Package maintainer reputation check
  - Community feedback

## 📚 Additional Security Tools

Complement this scanner with:

- **Python**: `pip-audit`, `safety`, `bandit`
- **npm**: `npm audit`, `socket.dev`, `snyk`
- **General**: Dependabot, Renovate Bot, SBOM analysis

## ⚖️ License

Open source. Use at your own risk. This tool is for security research and defense purposes only.

## 🤝 Contributing

Found a new attack pattern? PRs welcome! Please include:
1. Reference to real-world incident (CVE, blog post, etc.)
2. Pattern detection logic
3. Test case

---

**⚠️ Disclaimer**: This tool provides best-effort static analysis. It is not a substitute for comprehensive security practices, code review, or runtime monitoring. Always verify package authenticity through multiple channels.
