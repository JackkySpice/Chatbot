# MobileSec Red Team Console

**⚠️ WARNING: For Authorized Security Testing Only**

This framework is designed for security professionals conducting **authorized** penetration testing and security audits. Unauthorized use is illegal and unethical.

## 🎯 Features

### Core Modules
- **Port Scanning** - Common port enumeration
- **HTTP Header Security Analysis** - Security header audit
- **Directory/File Discovery** - Path enumeration with wordlist
- **SQL Injection Testing** - Basic SQLi detection
- **XSS Testing** - Reflected XSS detection
- **API Endpoint Discovery** - REST/GraphQL endpoint enumeration
- **Rate Limit Testing** - DoS resistance assessment

### Advanced Features
- **Strategic Adaptation Layer** - Failure detection and pivot logic
- **Tactical Assessment** - Meta-analysis of attack vectors
- **Live Fire Environment** - Real network calls, no mocking
- **One-Shot Payloads** - Copy-paste ready scripts for Termux

## 🚀 Quick Start

### Interactive Console
```bash
chmod +x mobilesec_console.sh
./mobilesec_console.sh
```

### Standalone One-Shot Payloads
```bash
cd examples/
./header_analysis_payload.sh
./directory_discovery_payload.sh
./api_discovery_payload.sh
./rate_limit_tester.sh
```

### Strategic Adaptation
```bash
python strategic_adaptation.py https://target.com
```

## 📁 Project Structure

```
/workspace/
├── mobilesec_console.sh          # Main interactive console
├── strategic_adaptation.py        # Failure detection & pivot logic
├── examples/
│   ├── header_analysis_payload.sh
│   ├── directory_discovery_payload.sh
│   ├── api_discovery_payload.sh
│   └── rate_limit_tester.sh
├── README.md                      # This file
└── USAGE.md                       # Detailed usage guide
```

## 🧠 Strategic Adaptation Layer

The framework includes intelligent failure detection:

- **Failure Detection**: Automatically detects when attack vectors fail (403, 404, 429, etc.)
- **Pivot Logic**: Suggests alternative approaches when direct attacks fail
- **Data Sanity**: Prevents guessing parameter names - requires discovery first
- **Impossible Task Detection**: Explains why certain tasks are impossible and suggests alternatives

### Example Pivot Scenarios
- **SQLi failed?** → Try IDOR, Information Disclosure, NoSQL Injection
- **XSS failed?** → Try CSRF, Open Redirect, Template Injection
- **WAF blocking?** → Try Rate Limit Testing, Business Logic flaws
- **Rate limited?** → Slow down requests, test authenticated endpoints

## 📊 Response Structure

Every payload follows this structure:

1. **TACTICAL ASSESSMENT**: Acknowledging the current state
2. **PROTOCOL**: Explain what the script will do
3. **PAYLOAD**: One-Shot Termux script (copy-pasteable)

## 🌍 Live Fire Environment

- **REAL NETWORK CALLS**: All scripts make actual HTTP requests via `requests` library
- **ZERO MOCKING**: Results are based on real responses from targets
- **RATE LIMITING**: Built-in delays to avoid overwhelming targets

## ⚙️ Requirements

- Termux (Android)
- Python 3
- requests library (auto-installed)

## 🛡️ Authorization

**You must have written authorization** before testing any target. The interactive console will prompt for confirmation before execution.

## 📖 Documentation

- **USAGE.md** - Detailed usage guide and best practices
- **README.md** - This file (overview)

## ⚠️ Legal Notice

This tool is provided for educational and authorized security testing purposes only. The user is solely responsible for ensuring they have proper authorization before using this tool on any system. Unauthorized access to computer systems is illegal and may result in criminal prosecution.
