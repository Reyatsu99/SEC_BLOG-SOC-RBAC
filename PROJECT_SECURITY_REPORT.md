# Secure Blogging Platform Report

## 1. Project Overview

This project is a secure blogging platform built to demonstrate how core network and application security controls can be applied to a real web application. The goal was not only to provide standard blog functionality such as registration, login, post creation, editing, deletion, and visibility control, but also to show how the platform can be hardened against common weaknesses seen in existing blogging applications.

The implemented application includes:

- User registration and login
- Role-based access control with `user` and `admin`
- Public and private post visibility
- Audit logging
- Password hashing
- Rate limiting and login challenge flow
- HTTPS support and secure cookies
- Browser security headers
- Session timeout enforcement
- Post integrity hashing and RSA-based digital signatures

Main implementation files:

- [app.py](./app.py)
- [README.md](./README.md)
- [templates/base.html](./templates/base.html)
- [templates/login.html](./templates/login.html)

## 2. How To Run The Project Locally

### 2.1 Prerequisites

Make sure these are available on your system:

- `python3`
- `openssl`
- a modern browser such as Chrome, Edge, or Safari

### 2.2 Setup

Run the following from the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2.3 Run In HTTP Mode

For basic local testing:

```bash
source .venv/bin/activate
unset ENFORCE_HTTPS
unset SSL_CERT
unset SSL_KEY
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

### 2.4 Run In HTTPS Mode

This is the recommended demo mode because it lets you verify TLS-related controls and HSTS.

#### Step 1: create a local certificate

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"
```

#### Step 2: export the environment variables

```bash
source .venv/bin/activate
export PORT=5000
export ENFORCE_HTTPS=true
export SSL_CERT=$(pwd)/certs/cert.pem
export SSL_KEY=$(pwd)/certs/key.pem
export SESSION_IDLE_MINUTES=1
export SESSION_ABSOLUTE_MINUTES=5
```

#### Step 3: start the app

```bash
python app.py
```

Open:

```text
https://127.0.0.1:5000
```

If the browser shows a warning, that is normal for a self-signed local certificate. Proceed manually in the browser.

### 2.5 Basic Usage Flow

After the app starts:

1. Open `/register`
2. Create an account
3. Open `/login`
4. Log in
5. Open `/posts`
6. If logged in, create a post from `+ New Entry`

## 3. How To Verify The Security Features

### 3.1 Security Headers

Open browser DevTools:

1. Press `F12`
2. Open the `Network` tab
3. Refresh the page
4. Click a request such as `/posts` or `/login`
5. Inspect the response headers

You should see:

- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cache-Control: no-store`
- `Strict-Transport-Security` when using HTTPS

These controls are applied in [app.py](./app.py).

### 3.2 Session Expiration

With:

- `SESSION_IDLE_MINUTES=1`
- `SESSION_ABSOLUTE_MINUTES=5`

do the following:

1. Log in
2. Stay idle for more than one minute
3. Refresh `/posts`

Expected result:

- the app redirects you to login
- you see a session expiry message

### 3.3 Brute Force Protection And Challenge

1. Open `/login`
2. Enter the wrong password three times
3. A challenge question appears
4. Continue failing until lockout triggers

Expected result:

- challenge is shown after repeated failures
- lockout message appears after threshold is crossed

### 3.4 Integrity And Digital Signature Verification

1. Create a post
2. Open the post detail page

Expected result:

- `Integrity check passed`
- `Digital signature verified`

### 3.5 Audit Logging

If using an `admin` account:

1. Open `/admin/audit`
2. Review log entries

Expected result:

- login/logout events
- create/edit/delete events
- integrity or signature failure events if triggered

## 4. Security Enhancements Implemented In This App

This section summarizes the security controls built into the application and the problem each one solves.

### 4.1 Transport And Browser-Side Security

- HTTPS support with certificate-based local TLS
- HTTPS enforcement through `ENFORCE_HTTPS`
- secure session cookies
- browser security headers including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy

Why this matters:

- prevents downgrade to insecure transport
- reduces clickjacking risk
- reduces some XSS and content injection risk
- protects cookies during HTTPS sessions

### 4.2 Authentication And Session Hardening

- salted PBKDF2 password hashing
- session-based login
- idle timeout and absolute session lifetime
- CSRF protection on form submissions
- login challenge after repeated failures
- IP-based and username-based lockout

Why this matters:

- makes stolen password databases harder to crack
- limits brute-force login attacks
- reduces risk of forgotten or stolen sessions being reused
- blocks forged cross-site requests

### 4.3 Authorization

- role-based access control
- public/private visibility enforcement
- ownership checks on edit and delete flows

Why this matters:

- reduces broken access control risk
- ensures users only see or modify content they are allowed to access

### 4.4 Integrity And Non-Repudiation

- SHA-256 content hashing
- RSA digital signatures for post content
- version history storage
- audit logs with actor, target, timestamp, and IP

Why this matters:

- detects content tampering
- provides traceability for changes
- helps demonstrate who performed what action and when

### 4.5 Input And Database Safety

- parameterized SQL queries
- bounded input sizes
- Jinja escaped rendering

Why this matters:

- reduces SQL injection risk
- reduces XSS risk
- reduces malformed input abuse and memory pressure

### 4.6 End-to-End Encrypted Messaging

- client-side AES-256 encryption via CryptoJS
- no plaintext message storage in the server database
- live cryptographic inspection to demonstrate MITM defense

Why this matters:

- defeats man-in-the-middle attacks even if TLS is unwrapped or compromised
- ensures database breaches do not expose private communication
- enforces trustless intermediary design pattern

## 5. Shortcomings In Existing Blogging Apps That This Project Addresses

Many current blogging platforms in the market already implement some security controls. However, real-world deployments still commonly suffer from incomplete hardening, especially when the app is self-hosted, extended with plugins, or deployed without secure defaults.

The most common shortcomings are:

- HTTPS exists, but browser security headers are missing or weak
- sessions remain active too long
- brute-force protection is inconsistent
- access control logic is not enforced uniformly
- content tampering is not independently verifiable
- audit trails are incomplete or absent
- third-party components introduce new attack surfaces

This project addresses those gaps in a compact prototype by combining transport security, browser-level hardening, access control, rate limiting, session expiry, integrity verification, and auditability in one application.

## 6. Current Market Examples And Their Relevant Security Gaps

The point here is not that a product is insecure by design. The point is that even popular platforms and plugins continue to deal with the same classes of risk this project tries to address.

### 6.1 WordPress Ecosystem

WordPress itself explicitly states that security concerns extend beyond core into plugins, themes, and the wider ecosystem. The official security page says vulnerabilities may exist in core, plugins, themes, or the wider WordPress ecosystem:

- [WordPress Security](https://wordpress.org/about/security/)

That matters because many self-hosted blogging deployments rely heavily on plugins to add security hardening that is not consistently present out of the box.

Examples:

- The official WordPress plugin page for `WPVulnerability` says a security vulnerability was fixed in version `4.2.2.1`, and all previous versions `3.3.0` through `4.2.1` were affected. Its changelog for `2026-01-16` says the fix addressed an authorization vulnerability in REST API endpoints that allowed low-privileged users to access sensitive vulnerability data:
  - [WPVulnerability plugin page](https://wordpress.org/plugins/wpvulnerability/)

- The official WordPress plugin page for `W3 Total Cache` shows in changelog version `2.9.2` that it patched broken access control for Image Service AJAX operations and also patched an `mfunc` security vulnerability:
  - [W3 Total Cache plugin page](https://wordpress.org/plugins/w3-total-cache/)

Why this is relevant to our app:

- our app includes route-level authorization checks
- our app uses CSRF protection
- our app adds browser security headers
- our app adds session timeout and login throttling

These measures address the same broad risk classes: broken access control, abuse of authenticated endpoints, and insecure browser/runtime behavior.

### 6.2 Ghost

Ghost’s official security documentation shows that modern blogging platforms still need active defenses against SQL injection, CSRF, XSS, brute force attacks, and permissions issues:

- [Ghost Security Docs](https://docs.ghost.org/security)

Ghost also explicitly notes a browser-domain separation issue: if the front-end and admin area share the same domain, trusted-user XSS can still become dangerous. Their recommendation is to split admin and public surfaces across different domains.

Why this is relevant to our app:

- our app uses escaped rendering and CSP to reduce script injection risk
- our app uses secure cookies and HTTPS enforcement
- our app uses integrity hashing and signatures for post tampering detection
- our app logs sensitive operations for post-incident review

This does not mean our prototype fully solves every Ghost-class problem. It means the app directly addresses the same attack families that official Ghost guidance highlights.

## 7. Mapping Existing Weaknesses To This App’s Fixes

### Weakness: broken access control

Seen in market examples:

- authorization bugs in plugin endpoints
- AJAX endpoints exposing protected operations

Implemented fix in this app:

- role checks
- ownership checks
- explicit route guards

### Weakness: XSS and content injection

Seen in market examples:

- plugin/theme rendering issues
- trusted-user content injection concerns

Implemented fix in this app:

- escaped rendering
- CSP header
- `X-Content-Type-Options`
- `X-Frame-Options`

### Weakness: brute-force and login abuse

Seen in market examples:

- public login endpoints exposed to repeated automated guessing

Implemented fix in this app:

- IP lockout
- username lockout
- challenge flow after repeated failures

### Weakness: weak browser/session hardening

Seen in market examples:

- missing security headers
- long-lived sessions

Implemented fix in this app:

- secure cookie flags
- session idle timeout
- absolute session lifetime
- HSTS under HTTPS

### Weakness: lack of tamper evidence

Seen in market examples:

- content may be modified without independent verification

Implemented fix in this app:

- SHA-256 post hashing
- RSA content signatures
- audit trail
- version history

## 8. Limitations Of This Prototype

This project materially improves security, but it is still a prototype and not a full production-grade platform.

Important limitations:

- pre-seeded admin account is used for initial setup, which should be disabled in production
- signing keys are stored locally, not in a KMS or HSM
- audit logs are in the same database, not in immutable external storage
- the login challenge is useful for demonstration but weaker than enterprise CAPTCHA or risk-based bot detection
- SQLite is fine for a project demo, but PostgreSQL with stricter role separation would be stronger for production

## 9. Recommended Next Improvements

If this project is extended further, the best next steps are:

1. Implement an Admin Panel UI to easily manage user roles without database intervention
2. Move signing keys to external key management
3. Ship logs to append-only external storage
4. Add MFA for all users
5. Use PostgreSQL and separate DB roles
6. Add reverse-proxy deployment guidance using Nginx or Caddy

## 10. Conclusion

This project demonstrates that secure blogging requires more than just login and HTTPS. Existing blogging platforms in the market, especially self-hosted and plugin-heavy deployments, still face risks such as broken access control, XSS, weak session handling, brute-force abuse, and poor tamper visibility.

The secure blogging app built here addresses those shortcomings by combining:

- HTTPS enforcement
- browser security headers
- session hardening
- role-based authorization
- brute-force resistance
- content integrity checks
- digital signatures
- audit logging

That makes it a practical prototype for demonstrating how network security and application security controls can be enforced together in a blogging system.

## 11. Sources

- [WordPress Security](https://wordpress.org/about/security/)
- [WPVulnerability plugin page](https://wordpress.org/plugins/wpvulnerability/)
- [W3 Total Cache plugin page](https://wordpress.org/plugins/w3-total-cache/)
- [Ghost Security Docs](https://docs.ghost.org/security)
