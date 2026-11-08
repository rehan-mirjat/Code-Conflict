<div align="center">

# `{Code} & Conflict`

**An interactive cybersecurity education website: threats, news and defense guides in one place.**

![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap&logoColor=white)
![Backend](https://img.shields.io/badge/backend-Flask%20%2B%20SQLite-brightgreen)
![Unit%20Tests](https://img.shields.io/badge/unit%20tests-11%20passing-2ecc71)
![E2E%20Tests](https://img.shields.io/badge/e2e%20checks-54%20passing-2ecc71)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Pages](#pages)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)
- [Author](#author)

## About

**Code & Conflict** is a static, front-end website that teaches cybersecurity and cyber warfare awareness. It covers common attack types, current security news and practical prevention guides. It was built as a university assignment at the **University of Sindh, Jamshoro** (Department of Information Technology).

> The site structure idea was taken from Deepseek.

## Features

- **Live Threat Feed:** a simulated, real-time feed on the homepage with severity badges, pause/resume and animated counters.
- **Interactive learning:** a phishing quiz with an explanation modal, and a security posture checklist.
- **Threat library:** guides on malware, phishing, password attacks, ransomware and social engineering.
- **Prevention guides:** email, mobile, network, data privacy and secure browsing.
- **News section:** latest threats, security patches, industry news and an event calendar.
- **Smart search:** navbar search with suggestions that jumps to the matching page.
- **Accounts (demo):** signup with a live password-strength meter and captcha, login, logout and a password-reset page. The session is kept in the browser.
- **Contact form:** validation, a random captcha and a success toast.
- **Modern UI:** dark theme, scroll progress bar, back-to-top button, reveal-on-scroll cards, toasts, responsive layout and `prefers-reduced-motion` support.

## Pages

| Section | Pages |
|---|---|
| Core | `index`, `about_us`, `contact`, `login`, `signup`, `password-reset` |
| Threats | `threats_view` (dashboard), `malware`, `phishing`, `password_attacks`, `ransomware`, `social_engineering` |
| News | `latest_threats`, `security_patches`, `industry_news`, `event_calendar` |
| Prevention | `data_privacy`, `email_security`, `mobile_security`, `network_security`, `secure_browsing` |

## Tech Stack

- **HTML5, CSS3 and vanilla JavaScript.** There is no build step and no framework.
- [Bootstrap 5.3.0](https://getbootstrap.com/) and [Bootstrap Icons 1.10.0](https://icons.getbootstrap.com/).
- [Animate.css 4.1.1](https://animate.style/).
- Some pages also load FullCalendar (event calendar) and Chart.js (threat dashboard) from a CDN.

All libraries load from CDNs, so an internet connection is needed for the full experience.

## Getting Started

### 1. Running the Full Stack (Flask Backend + Static Frontend)

```bash
# Clone the repository
git clone <your-repository-url>
cd Code-Conflict

# Install dependencies
pip install -r backend/requirements.txt

# Run the Flask backend server
python3 backend/app.py
```
Open **http://127.0.0.1:5000** in your browser. The server serves all frontend pages and handles authentication, password reset, rate-limited contact forms, and security feeds via SQLite.

### 2. Running Frontend Only (Static Mode)

The frontend features progressive enhancement and automatic fallback. If served purely statically, it operates using client-side storage:

```bash
python3 -m http.server 8000
```
Open **http://localhost:8000** or open `index.html` directly in any web browser.

---

## Backend API Specification

| Method | Endpoint | Description | Payload / Notes |
|---|---|---|---|
| `GET` | `/api/health` | Health & database status check | `{ ok: true, status: "healthy", timestamp: ... }` |
| `POST` | `/api/register` | Register new university account | `{ email, password, pgp? }` (`.edu.pk` enforced) |
| `POST` | `/api/login` | Authenticate user & start session | `{ email, password }` (Rate limited: 5/min) |
| `POST` | `/api/logout` | Terminate session | Clears session cookie |
| `GET` | `/api/me` | Fetch active authenticated user | Current user or `null` |
| `POST` | `/api/password-reset/request` | Request time-limited reset token | `{ email }` (15-min TTL, rate limited) |
| `POST` | `/api/password-reset/confirm` | Reset password using secret token | `{ token, new_password }` |
| `POST` | `/api/contact` | Store validated contact message | `{ name, email, subject, message }` (Rate limited) |
| `GET` | `/api/feed/next` | Live threat feed stream simulation | Returns random threat item |

---

## Testing

### Backend Unit Test Suite (11 Tests)
Covers registration validation, login authentication, password reset cryptographic flow, contact forms, rate limiting, and HTTP security headers:
```bash
python3 -m unittest discover -s tests -p "*test.py"
```

### End-to-End Browser Test Suite (54 Checks)
Headless Chromium & Selenium automated browser testing for all 21 pages, interactive widgets, quiz, search routing, signup/login flows, and contact forms:
```bash
python3 tests/e2e_test.py
```

## Security & Architecture Features

- **Hardened SQLite Engine**: Configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`), `synchronous=NORMAL`, foreign keys enforcement, and `busy_timeout=5000` to prevent database locks under concurrent access.
- **Defensive Rate Limiting**: In-memory sliding-window throttlers with automatic stale-key eviction protect `/api/login`, `/api/register`, `/api/password-reset/*`, and `/api/contact` from credential stuffing, spamming, and memory exhaustion DoS.
- **Cryptographic Security**: Passwords hashed with pbkdf2/sha256 through Werkzeug; time-limited password reset tokens generated via `secrets.token_urlsafe(32)` and hashed in storage.
- **Production HTTP Headers**: Automatic injection of `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Permissions-Policy`, and anti-caching headers on all API routes.
- **Resilient Progressive Enhancement**: Full hybrid support: works seamlessly with the backend API or completely offline/static.

## Roadmap

- [x] Backend for real authentication, password reset, and contact inbox (Flask + SQLite)
- [x] Rate limiting, cryptographic reset tokens, and security headers
- [x] Automated test suites (Unit tests + Selenium E2E tests)
- [x] Live external threat intelligence API integration (`/api/threat-intel/feed` aggregating CISA KEV & NVD security advisories)
- [x] Share the navbar and footer through server-side includes and modular templates (`/templates/navbar.html`, `/templates/footer.html`)
- [x] Light / Dark theme toggle with persistent preference state and accessible high-contrast palette
- [x] Production Docker containerization (`Dockerfile` and `docker-compose.yml`)

## License

Released under the [MIT License](LICENSE).

## Author

**Rehan Raza** (ITE/107/2K23), University of Sindh, Jamshoro.
GitHub: [@rehan-mirjat](https://github.com/rehan-mirjat)

---

<div align="center">

Made for learning, and to help people stay safe online.

</div>
