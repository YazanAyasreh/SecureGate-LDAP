# 🛡️ SecureGate-LDAP
> **An Enterprise-Grade Multi-Factor Authentication Bridge**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-black?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![MongoDB](https://img.shields.io/badge/Database-MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

---

## 📖 Executive Summary
In modern enterprise environments, legacy **LDAP** and **Active Directory** systems are often vulnerable to credential harvesting and brute-force attacks. **SecureGate-LDAP** acts as a hardened proxy layer. It doesn't just check a password; it validates the **Humanity** (reCAPTCHA), the **Identity** (LDAP), and the **Presence** (TOTP) of the user before a session is ever created.



---

## 🛠️ Core Architecture & Logic

### 1. The Triple-Lock Auth Flow
The application follows a strict sequential verification process:
* **Layer 1: Bot Mitigation** 🤖
    * Utilizes Google reCAPTCHA v2 to ensure requests originate from a physical user, neutralizing automated credential stuffing.
* **Layer 2: Primary Directory Check** 🔑
    * Authenticates against `ldap3` servers. If LDAP is unavailable, the system safely falls back to a **Bcrypt-hashed** local database.
* **Layer 3: Cryptographic MFA** 📱
    * Generates a unique `Base32` secret for every user. Verification is handled via Time-based One-Time Passwords (TOTP) compatible with Google Authenticator.

### 2. Security Hardening (Deep Dive)
<details>
<summary><b>Click to view Technical Security Specs</b></summary>

* **Rate Limiting:** Implements a custom MongoDB-backed tracker. After 5 failed attempts, the account enters a `LOCKOUT_DURATION` state.
* **Session Integrity:** * `HttpOnly`: Prevents JavaScript from accessing session cookies (Mitigates XSS).
    * `SameSite=Lax`: Prevents cookies from being sent in cross-site requests (Mitigates CSRF).
* **Header Protection:** Enforces `Strict-Transport-Security` (HSTS) to ensure all traffic stays over HTTPS.
</details>

---

## 🎨 UI/UX Philosophy
Inspired by **macOS and SaaS minimalism**, the interface focuses on clarity and trust. 
* **Layout:** Centered 400px containers with 85% fluid application windows.
* **Visuals:** Clean borders, subtle shadows, and high-contrast primary charcoal (`#111827`) buttons.
* **Feedback:** Real-time flash messages for "Invalid OTP" or "Account Locked" to guide the user safely.

---

## 🚀 Deployment & Installation

### 📋 Prerequisites
* **Python:** Version 3.8 or higher.
* **Database:** MongoDB Compass or Atlas running locally.
* **Secrets:** A valid `.env` file (see below).

### ⌨️ Installation Steps
```bash
# 1. Clone the project
git clone [https://github.com/YourUsername/SecureGate-LDAP.git](https://github.com/YourUsername/SecureGate-LDAP.git)

# 2. Setup Virtual Environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Run the Secure Server
python app.py

## 🔐 Environment Configuration (.env)

The application requires a `.env` file in the root directory to manage sensitive credentials. **Never commit your actual `.env` file to version control.** Create a file named `.env` and populate it with the following:

```env
# Flask Security
SECRET_KEY=generate_a_secure_hex_string_here

# Google reCAPTCHA v2 (Get keys at: [google.com/recaptcha/admin](https://google.com/recaptcha/admin))
RECAPTCHA_PUBLIC_KEY=your_site_key_here
RECAPTCHA_PRIVATE_KEY=your_secret_key_here

# Database Configuration
MONGO_URI=mongodb://localhost:27017/
MONGO_DB_NAME=mfa_app

# LDAP / Active Directory Configuration
LDAP_SERVER=ldap://127.0.0.1
LDAP_BASE_DN=dc=example,dc=com

---

### 2. The Repository Anatomy Section
This is best placed near the bottom of the README. It acts as a "map" for your code. Use a "Code Block" with the `text` language tag to keep the alignment perfect.

```markdown
## 📂 Repository Anatomy

A modular breakdown of the project structure and the purpose of each directory:

```text
SecureGate-LDAP/
├── static/              # Assets: CSS styles and generated MFA QR codes
├── templates/           # UI Layer: Hardened HTML5 templates (Base, Login, MFA, QR)
├── .env                 # The Vault: Private API keys and secrets (Local only)
├── .gitignore           # The Filter: Prevents sensitive files from being uploaded
├── app.py               # The Brain: Main Flask application logic and routing
├── requirements.txt     # The Manifest: List of all Python dependencies
└── README.md            # The Manual: Project documentation and setup guide

---

### 💡 Pro-Tip: The `.env.example` file
In professional repositories, we usually create a file actually named `.env.example` and upload it to GitHub. It contains the exact text I gave you above but with empty values. 

This way, when someone clones your project, they see exactly what they need to fill in.

**Would you like me to generate a "Security Checklist" section for your README to show that you've tested for common vulnerabilities?**

