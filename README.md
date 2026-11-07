<div align="center">

# `{Code} & Conflict`

**An interactive cybersecurity education website: threats, news and defense guides in one place.**

![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap&logoColor=white)
![Tests](https://img.shields.io/badge/e2e%20checks-54%20passing-2ecc71)
![Backend](https://img.shields.io/badge/backend-none%20(static)-lightgrey)
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

```bash
# 1. Get the project
git clone <your-repository-url>
cd Code-Conflict

# 2. Serve it locally (any static server works)
python3 -m http.server 8000

# 3. Open it in your browser
#    http://localhost:8000
```

You can also open `index.html` directly in a browser.

## Project Structure

```text
Code-Conflict/
├── assets/
│   ├── css/customized.css   # Shared styles, animations and UI enhancements
│   ├── js/main.js           # Search, auth, toasts, scroll effects, live feed
│   └── imgs/                # Icons, team photos, event logos, banners
├── news/                    # latest_threats, security_patches, industry_news, event_calendar
├── prevention/              # data_privacy, email_security, mobile_security,
│                            # network_security, secure_browsing
├── threats/                 # malware, phishing, password_attacks, ransomware,
│                            # social_engineering, threats_view
├── tests/e2e_test.py        # End-to-end browser tests
├── index.html
├── about_us.html
├── contact.html
├── login.html
├── signup.html
├── password-reset.html
└── README.md
```

## Testing

The end-to-end suite drives a headless Chromium browser against a local server. It runs 54 checks:

- every page loads without JavaScript errors or failed local requests
- the live feed, counters, pause/resume and back-to-top button
- search routing
- the signup, login and logout flow, including bad passwords, duplicate emails and wrong captchas
- the contact form and the password-reset page

Requirements: Python 3, `selenium`, Chromium and `chromedriver`.

```bash
python3 tests/e2e_test.py
```

When run offline, the CDN libraries cannot load. The suite ignores the resulting "not defined" errors for Bootstrap, FullCalendar and Chart.js.

## Limitations

This is a front-end project, so some things are demos:

- **Authentication is not secure.** Accounts live in the browser's `localStorage`. Passwords are salted and SHA-256 hashed, but there is no server. Do not use real credentials.
- **Contact messages are stored locally** in `localStorage` and are never sent anywhere.
- **Threat feed, statistics and news items are sample data**, not live intelligence.
- The navbar and footer are repeated in each HTML file.

## Roadmap

- [ ] Backend for real authentication and a contact inbox (Node/Express or Firebase)
- [ ] Load threat and news data from a real feed or JSON API
- [ ] Share the navbar and footer through a template or include
- [ ] Add a light theme
- [ ] Add screenshots and a live demo link to this README

## License

Released under the [MIT License](LICENSE).

## Author

**Rehan Raza** (ITE/107/2K23), University of Sindh, Jamshoro.
GitHub: [@rehan-mirjat](https://github.com/rehan-mirjat)

---

<div align="center">

Made for learning, and to help people stay safe online.

</div>
