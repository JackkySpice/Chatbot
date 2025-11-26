# MobileSec Red Team Console - Usage Guide

## 🛡️ Authorization

**CRITICAL**: Always confirm you have written authorization before testing any target. The console will prompt for confirmation.

## 📋 Quick Start

### Interactive Console
```bash
./mobilesec_console.sh
```

### Standalone One-Shot Payloads
```bash
cd examples/
./header_analysis_payload.sh
./directory_discovery_payload.sh
./api_discovery_payload.sh
```

## 🧠 Strategic Adaptation Layer

The framework includes failure detection and pivot logic:

```bash
python strategic_adaptation.py https://target.com
```

### Failure Detection
- Automatically detects when attack vectors fail
- Logs status codes (403, 404, 429, etc.)
- Tracks repeated failures

### Pivot Logic
When a direct attack fails, the system suggests alternative approaches:
- **SQLi failed?** → Try IDOR, Information Disclosure, NoSQL Injection
- **XSS failed?** → Try CSRF, Open Redirect, Template Injection
- **WAF blocking?** → Try Rate Limit Testing, Business Logic flaws
- **Rate limited?** → Slow down requests, test authenticated endpoints

## 📊 Response Structure

Every payload follows this structure:

1. **TACTICAL ASSESSMENT**: Current state acknowledgment
2. **PROTOCOL**: What the script will do
3. **PAYLOAD**: Executable Python code

## 🌍 Live Fire Environment

- **REAL NETWORK CALLS**: All scripts make actual HTTP requests
- **NO MOCKING**: Results are based on real responses
- **RATE LIMITING**: Built-in delays to avoid overwhelming targets

## ⚠️ Important Notes

### Data Sanity
- Don't guess parameter names
- Run discovery scripts first to identify actual endpoints
- Use fuzzing to find hidden parameters

### Impossible Tasks
- **SHA256 Decryption**: Not possible - suggest Rainbow Table attack
- **Brute Force**: Always implement rate limiting and delays
- **WAF Bypass**: If direct bypass fails, pivot to other vectors

## 🔧 Customization

### Adding Custom Wordlists
Edit the `WORDLIST` array in directory discovery scripts:
```python
WORDLIST = [
    'custom/path',
    'another/path',
    # Add your paths here
]
```

### Adding Custom Payloads
Edit the `payloads` array in injection testers:
```python
payloads = [
    'your/custom/payload',
    # Add your payloads here
]
```

## 📝 Best Practices

1. **Start with Reconnaissance**
   - Header analysis
   - Directory discovery
   - API enumeration

2. **Test Authentication**
   - Login mechanisms
   - Session management
   - Password reset flows

3. **Test Input Validation**
   - SQL Injection
   - XSS
   - Command Injection
   - File Upload

4. **Test Business Logic**
   - IDOR
   - Privilege escalation
   - Race conditions

5. **Document Everything**
   - Log all findings
   - Capture evidence
   - Note false positives

## 🚨 Legal Notice

This framework is for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always ensure you have proper authorization before testing.
