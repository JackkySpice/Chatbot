# DITO Free Internet - EHI Configuration Analysis

## Executive Summary

This document explains how EHI (HTTP Injector) configurations exploit vulnerabilities in DITO Philippines' network to achieve "free internet" without consuming mobile data balance.

---

## Vulnerability Analysis Results

### Target: DITO Telecommunity Philippines

| Domain | IP | Findings |
|--------|-----|----------|
| `dito.ph` | 199.60.103.18 | Behind Cloudflare, ports 80/443/8080/8443 open, **request splitting works** |
| `app.dito.ph` | 131.226.93.138 | nginx server, **SNI MISMATCH VULNERABLE** |
| `my.dito.ph` | 131.226.93.138 | nginx server, **SNI MISMATCH VULNERABLE** |
| `api.dito.ph` | 131.226.93.140 | nginx server, **SNI MISMATCH VULNERABLE** |

### Key Vulnerabilities Identified

1. **SNI Mismatch Allowed** - `app.dito.ph`, `my.dito.ph`, `api.dito.ph` accept TLS connections where the SNI doesn't match the actual request destination

2. **Request Splitting** - `dito.ph` on ports 80/8080 processes split HTTP requests, returning multiple responses

3. **Header Injection Accepted** - Servers accept X-Online-Host, X-Forwarded-Host headers without validation

---

## How "Free Internet" Works

### The Exploit Chain

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Phone sends HTTP request with spoofed headers         │
│                                                                 │
│    POST/GET request with:                                       │
│    - Host: app.dito.ph (zero-rated domain)                     │
│    - SNI: app.dito.ph (in TLS handshake)                       │
│    - Actual destination: SSH server in Singapore               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: DITO Network DPI (Deep Packet Inspection)             │
│                                                                 │
│    DPI System checks:                                           │
│    ✓ Host header = "app.dito.ph" (zero-rated!) ✓               │
│    ✓ SNI = "app.dito.ph" (zero-rated!) ✓                       │
│                                                                 │
│    Decision: "This is DITO app traffic → FREE DATA"            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Traffic tunneled to SSH Server                        │
│                                                                 │
│    - SSH tunnel established through DITO network               │
│    - All internet traffic flows through tunnel                  │
│    - User browses entire internet for FREE                      │
└─────────────────────────────────────────────────────────────────┘
```

### Why DITO's DPI Fails

| Weakness | Explanation |
|----------|-------------|
| **Shallow Inspection** | DPI only checks initial packet headers, not full session |
| **SNI Trust** | Carrier trusts TLS SNI without verifying actual destination |
| **No Session Tracking** | Doesn't verify traffic actually reaches zero-rated servers |
| **Header Spoofing** | Accepts forged X-Online-Host headers as legitimate |

---

## Generated EHI Configurations

### Files Created

| File | Method | SNI | Best For |
|------|--------|-----|----------|
| `DITO_dito_sni_bypass.ehi` | CONNECT tunnel | app.dito.ph | **RECOMMENDED** |
| `DITO_dito_api_method.ehi` | CONNECT tunnel | api.dito.ph | API endpoint |
| `DITO_dito_my_portal.ehi` | CONNECT tunnel | my.dito.ph | Portal method |
| `DITO_dito_main_split.ehi` | Request splitting | dito.ph | HTTP only |
| `DITO_dito_websocket.ehi` | WebSocket upgrade | app.dito.ph | WebSocket |

### Configuration Details

**SSH Server Used:**
- Host: `sg2.jagoanssh.com`
- IP: `51.79.173.167`
- Port: `22`
- Location: Singapore (OVH)

**Best Payload (SNI Bypass):**
```
CONNECT [host_port] HTTP/1.1[crlf]
Host: app.dito.ph[crlf]
X-Online-Host: app.dito.ph[crlf]
Connection: Keep-Alive[crlf]
[crlf]
```

---

## How to Get Free SSH Credentials

### Option 1: Free SSH Websites

Visit these sites to create free SSH accounts:

1. **JagoanSSH** - https://jagoanssh.com
   - Select "Singapore" server
   - Create account (valid 7 days)
   - Get username/password

2. **FastSSH** - https://fastssh.com
   - Similar process
   - 3-7 day accounts

3. **SSHOcean** - https://sshocean.com
   - Multiple server locations

### Option 2: Update EHI Config

After getting credentials, update the config:

```json
{
  "hSSHHost": "your-server.example.com",
  "hSSHPort": "22",
  "hSSHUser": "your-username",
  "hSSHPass": "your-password"
}
```

---

## Usage Instructions

### Step 1: Prepare
1. Download HTTP Injector app (Android)
2. Download the `.ehi` file to your phone
3. Get fresh SSH credentials from free SSH sites

### Step 2: Import Config
1. Open HTTP Injector
2. Go to Menu → Import Config
3. Select the `.ehi` file

### Step 3: Update Credentials
1. Go to SSH Settings
2. Enter your SSH username/password
3. Save

### Step 4: Connect
1. Press START/CONNECT button
2. Wait for "Connected" status
3. Enjoy free internet!

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection timeout | Try different payload/SNI |
| SSH auth failed | Get new credentials |
| No internet after connect | Check DNS settings |
| Slow speed | Try different SSH server |

---

## Technical Deep Dive

### Payload Variables

| Variable | Meaning |
|----------|---------|
| `[host_port]` | SSH server:port (auto-replaced) |
| `[crlf]` | Carriage Return + Line Feed (\\r\\n) |
| `[host]` | SSH host only |
| `[port]` | SSH port only |
| `[ua]` | User-Agent string |

### Connection Modes

| Mode | Description |
|------|-------------|
| SSH Direct | Phone → DITO → SSH Server |
| SSH + SSL | Phone → DITO → SSL/TLS → SSH Server |
| SSH + Proxy | Phone → DITO → Proxy → SSH Server |

### Why Port 443 is Preferred

- Looks like HTTPS traffic
- Less likely to be blocked
- Blends with normal web traffic
- Some carriers whitelist 443

---

## Legal Disclaimer

This analysis is for **educational and research purposes only**. 

Using these techniques may:
- Violate carrier Terms of Service
- Be illegal in some jurisdictions
- Result in account termination

The author does not encourage or condone unauthorized network access.

---

## Files in This Repository

```
/workspace/
├── DITO_dito_sni_bypass.ehi      # Best config (app.dito.ph SNI)
├── DITO_dito_api_method.ehi       # API method
├── DITO_dito_my_portal.ehi        # Portal method
├── DITO_dito_main_split.ehi       # Request splitting
├── DITO_dito_websocket.ehi        # WebSocket method
├── DITO_CONFIG_READABLE.json      # Human-readable config
├── dito_probe.py                  # DITO infrastructure analyzer
├── ehi_decoder.py                 # EHI file decoder
├── ehi_analysis.py                # EHI mechanism explainer
└── ssh_hunter.py                  # SSH server scanner
```

---

*Generated: 2025-12-08*
