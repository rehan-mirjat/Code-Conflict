# Using Bootstrap 5.3.7

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-LN+7fdVzj6u52u30Kp6M/trliBMCMKTyK833zpbD+pXdCLuTusPj697FH4R/5mcr" crossorigin="anonymous">

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js" integrity="sha384-ndDqU0Gzau9qJ1lfW4pNLlhNTkCfHzAVBReH9diLvGRem5+R9g2FzA8ZGN954O5Q" crossorigin="anonymous"></script>

<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-I7E8VVD/ismYTF4hNIPjVp/Zjvgyol6VFvRkX/vR+Vc4jQkC+hVqc2pM8ODewa9r" crossorigin="anonymous"></script>



# Site Structure Idea is Taking from Deepseek
# I hope it will not effect my marks sir !

Code & Conflict/
├── index.html                  # Homepage (BS5 Hero + Threat Feed)
├── about.html                  # Mission/Team (BS5 Cards)
├── contact.html                # Secure Form (BS5 + reCAPTCHA)
├── glossary.html               # Interactive Term Finder
├── resources.html              # BS5 List Group with Filters
├── threats/                    # BS5 Card Grids
│   ├── malware.html            # Accordion Attack Breakdown
│   ├── phishing.html           # Embedded Phishing Simulator
│   ├── ransomware.html         # Timeline Component
│   ├── social-engineering.html # Case Study Carousel
│   └── password-attacks.html   # Password Strength Meter
├── prevention/                 # BS5 Steps Components
│   ├── secure-browsing.html    # Extension Badges
│   ├── email-security.html     # Header Analyzer Tool
│   ├── mobile-security.html    # QR Code Scanner Demo
│   ├── network-security.html   # Wi-Fi Security Checklist
│   └── data-privacy.html       # GDPR Interactive Guide
├── news/                       # BS5 Card Layouts
│   ├── latest-threats.html     # Severity Tagged Cards
│   ├── security-patches.html   # Version Comparison Tables
│   ├── industry-news.html      # Media Object Layout
│   ├── events.html             # Calendar View
│   └── case-studies.html       # Tabbed Case Studies
├── css/
│   ├── custom.scss             # BS5 Overrides
│   ├── theme-dark.css          # Optional Dark Mode
│   └── print.css               # Print Optimization
├── js/
│   ├── bootstrap.bundle.min.js # BS5 Components
│   ├── custom.js               # Vanilla JS Enhancements
│   └── security-tools.js       # Interactive Modules
└── assets/
    ├──assets/imgs/
        ├── cyber-security-hero.jpg       # Main hero image
        ├── ransomware-attack.jpg         # Ransomware threat card
        ├── phishing-email.jpg            # Phishing threat card
        ├── log4j-vulnerability.jpg       # Vulnerability card
        ├── phishing-sample-full.jpg      # Detailed phishing example
        ├── microsoft-logo.png            # For email sample
        ├── ransomware-icon.png           # Stats section
        ├── clock-icon.png                # Stats section
        ├── hacker-icon.png               # Stats section
        ├── shield-icon.png               # Stats section
        ├── cyber-security-logo.png       # Footer logo
        └── cyber-security-badge.png      # Certification badge