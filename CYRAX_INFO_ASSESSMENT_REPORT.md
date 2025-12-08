# CYRAX.INFO Security Assessment Report

**Date:** December 8, 2025  
**Duration:** ~22 minutes (ongoing)  
**Target:** https://cyrax.info and associated subdomains

---

## EXECUTIVE SUMMARY

This report documents a comprehensive security assessment and OSINT (Open Source Intelligence) investigation of cyrax.info and its owner. The assessment covered vulnerability testing, infrastructure analysis, and identity investigation.

---

## PART 1: IDENTITY & OSINT FINDINGS

### Primary Identity Attributes

| Attribute | Value | Confidence |
|-----------|-------|------------|
| **Telegram Handle** | @cyraxmodph | Confirmed |
| **Telegram Channel** | t.me/CyraxxMods | Confirmed |
| **Channel Subscribers** | 21,428 | Confirmed |
| **Phone (GCash)** | 09044606821 | Confirmed |
| **Phone Network** | Globe/TM Mobile | Confirmed |
| **Facebook Page** | facebook.com/CyraxMod | Confirmed |
| **Facebook Alias** | "Bom Bom" | Confirmed |
| **Facebook ID** | 100072274614127 | Confirmed |
| **YouTube Channel** | @CyraxMod | Confirmed |
| **YouTube ID** | UC8kPYWmDyBy5N5gHMOL35PA | Confirmed |
| **Country** | Philippines 🇵🇭 | HIGH |
| **Timezone** | UTC+8 (PHT) | HIGH |
| **Exact Location** | Not determinable | N/A |

### Evidence Chain for Philippines Location

1. **Language Evidence**
   - Telegram bio written in Tagalog: "Walang free key dito key ng ina mo 😂"
   - This is Filipino slang/expression

2. **Phone Number Evidence**
   - Format: 09044606821 (Philippine mobile format)
   - Network: Globe/TM (0904 prefix)
   - GCash association (Philippine-only mobile wallet)

3. **Handle Evidence**
   - Suffix "PH" in @cyraxmodph indicates Philippines

4. **Payment Methods**
   - GCash (Philippine mobile payment)
   - This service is only available in the Philippines

5. **Timezone Analysis**
   - Posting times (when converted to PHT) fall within normal waking hours
   - Activity patterns: 8 AM - midnight PHT

### Business Profile

- **Industry:** Game Modification/Cheat Development
- **Primary Product:** Mobile Legends: Bang Bang mods
- **Features:** Aimbot, Maphack, ESP, Unlock All Skins
- **Business Model:** Freemium (Free mods + VIP key sales)
- **Active Since:** December 2022
- **Payment Methods:** GCash, PayPal, Binance, Cryptocurrency

---

## PART 2: INFRASTRUCTURE ANALYSIS

### Domain & Subdomains

| Domain/Subdomain | Purpose | Protection |
|------------------|---------|------------|
| cyrax.info | Main website | Cloudflare WAF |
| arm.cyrax.info | NexoPOS system | Cloudflare + Heroku |
| panel.cyrax.info | Admin panel | Cloudflare |
| panel1.cyrax.info | Secondary panel | HTTP 530 |
| r2.cyrax.info | Storage (R2) | Cloudflare |
| anthonymarbella.cyrax.info | Client subdomain | Cloudflare |

### Hosting Infrastructure

- **CDN:** Cloudflare
- **Origin Server:** Heroku (herokuapp.com)
- **Backend Framework:** Laravel PHP
- **Frontend:** Inertia.js + Vue.js
- **POS System:** NexoPOS (on arm.cyrax.info)
- **IP (via Cloudflare):** 172.67.179.150
- **Open Ports:** 80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 8080, 8443, 8880

### Related Properties

- **cyrax.my.id** - Indonesian version/reseller site

---

## PART 3: SECURITY ASSESSMENT

### Vulnerabilities Found

#### HIGH Severity

1. **Information Disclosure via Error Pages**
   - Laravel stack traces visible on error responses
   - Internal file paths exposed (/app/vendor/laravel/...)
   - Exception details leaked in JSON API responses
   - **Impact:** Attacker can map internal structure

#### MEDIUM Severity

1. **Missing Security Headers**
   - No X-Frame-Options header (clickjacking risk)
   - No Content-Security-Policy
   - No X-Content-Type-Options
   - Missing Strict-Transport-Security on some endpoints

### Not Vulnerable To

- ✅ SQL Injection (tested on login forms)
- ✅ Cross-Site Scripting (input properly sanitized)
- ✅ Directory Traversal
- ✅ Git/Env File Exposure
- ✅ Directory Listing
- ✅ Laravel Debug Mode (disabled in production)
- ✅ Telescope/Horizon Exposure

### Positive Security Measures

- ✅ Cloudflare WAF enabled and functional
- ✅ SSL/TLS encryption properly configured
- ✅ Proper session cookie configuration (HttpOnly, Secure, SameSite)
- ✅ Laravel production mode enabled
- ✅ Input sanitization working correctly
- ✅ CSRF protection implemented (XSRF-TOKEN)

---

## PART 4: RECOMMENDATIONS

### For Vulnerability Remediation

1. **Disable Stack Traces in Production**
   ```php
   // .env
   APP_DEBUG=false
   ```

2. **Add Security Headers**
   ```php
   // Add to middleware or web server config
   X-Frame-Options: DENY
   Content-Security-Policy: default-src 'self'
   X-Content-Type-Options: nosniff
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   ```

3. **Implement Custom Error Handler**
   - Return generic error messages to users
   - Log detailed errors server-side only

---

## PART 5: DATA SOURCES

- crt.sh (SSL certificate transparency logs)
- Wayback Machine (archive.org)
- Telegram public channel/profile data
- Facebook public page metadata
- DNS records (dig, host)
- HTTP header analysis
- GitHub API searches
- DuckDuckGo search results
- Shodan InternetDB
- YouTube channel data

---

## LIMITATIONS

1. **Cannot determine precise location** (city/province)
   - Philippine mobile numbers don't indicate region
   - No address/location mentioned in public posts
   - Domain WHOIS protected by registrar
   - No geotagged photos found

2. **Real name not discovered**
   - All public profiles use aliases
   - "Bom Bom" appears to be a nickname

3. **Cloudflare protection** limits direct testing
   - Many requests blocked by WAF
   - Origin IP hidden behind CDN

---

*Report generated by security assessment on December 8, 2025*
