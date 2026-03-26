<div align="center">
  <img src="http://googleusercontent.com/image_collection/image_retrieval/6300876683287901470_0" alt="SecureGate-LDAP Banner" width="100%" style="border-radius: 10px; margin-bottom: 20px;">

  <h1>🛡️ SecureGate-LDAP</h1>
  <p><strong>Enterprise-Grade MFA Gateway for Active Directory & LDAP</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Flask-2.0-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
    <img src="https://img.shields.io/badge/MongoDB-4.4+-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB">
    <img src="https://img.shields.io/badge/Security-Hardened-success?style=for-the-badge" alt="Security">
  </p>
</div>

---

## 📖 Overview
**SecureGate-LDAP** is a hardened authentication proxy designed for the **Pearson BTEC IT System** curriculum. It introduces a **Zero-Trust** architecture to legacy infrastructure by requiring three independent factors: **Directory Credentials**, **reCAPTCHA Verification**, and **TOTP Tokens**.

---

## 💎 Project Advantages
This implementation offers several key improvements over standard authentication systems, specifically focusing on **Enterprise-Grade** security.

| Advantage | SecureGate-LDAP Solution | Standard Login System |
| :--- | :--- | :--- |
| **Credential Safety** | **MFA (TOTP)** ensures stolen passwords are useless without the physical device. | Vulnerable to single-point-of-failure if password is leaked. |
| **Bot Mitigation** | **Google reCAPTCHA v2** prevents automated "Credential Stuffing" attacks. | Open to brute-force scripts and automated bot logins. |
| **Identity Source** | **LDAP/Active Directory** integration allows for centralized corporate management. | Uses isolated local databases that are hard to sync at scale. |
| **Brute Force Guard** | **MongoDB Rate Limiting** locks accounts automatically after 5 failed attempts. | Often allows unlimited attempts, risking account takeover. |
| **Session Security** | **Hardened Headers (HSTS/CSP)** and Secure Cookies prevent MiTM attacks. | Often lacks modern security headers, leaving users at risk. |
| **Data Privacy** | **Environment Isolation** ensures no API keys or secrets are stored in the code. | Hardcoded secrets often lead to accidental data leaks on GitHub. |

---

---

## 🛠️ System Architecture

### 🛡️ The Triple-Lock Security Flow
1. **Identity Lock:** Validates credentials against **Active Directory** or **LDAP3**.
2. **Integrity Lock:** Uses **Google reCAPTCHA v2** to neutralize automated bot attacks.
3. **Ownership Lock:** Verifies a 6-digit **TOTP** token (Google Authenticator) generated from a unique Base32 secret stored in **MongoDB**.

---

## ✨ Features
* **Rate Limiting:** Automated account lockout after 5 failed attempts.
* **Cryptographic Safety:** Passwords hashed with `Bcrypt` (Salted).
* **Hardened Headers:** Protection against XSS, Clickjacking, and MiTM (HSTS).
* **Minimalist UI:** A clean, macOS-inspired interface designed for professional SaaS environments.

---

## 🚀 Installation & Setup

### ⌨️ Commands
```bash
# 1. Clone the repository
git clone [https://github.com/Yazan-Ayasrah/SecureGate-LDAP.git](https://github.com/Yazan-Ayasrah/SecureGate-LDAP.git)
cd SecureGate-LDAP

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure .env (See below)

# 4. Run the application
python app.py
```
---

## 🛠️ Future Roadmap & Planned Upgrades
To further harden the system and prepare it for global production, the following modules are scheduled for development:

| Phase | Feature | Technical Objective | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **OAuth2 / OpenID** | Integrate "Sign in with Google/GitHub" for modern SSO. | ⏳ Planned |
| **Phase 2** | **SMS Gateway** | Add Twilio integration for SMS-based 2FA codes. | ⏳ Planned |
| **Phase 3** | **Hardware Keys** | Support for FIDO2/WebAuthn (Yubico/Biometrics). | 🚀 In-Research |
| **Phase 4** | **Admin Dashboard** | A macOS-styled UI to manage users and view live attack logs. | ⏳ Planned |
| **Phase 5** | **Dockerization** | Containerize the app for seamless deployment via Kubernetes. | 🛠️ Development |
| **Phase 6** | **SQL Migration** | Support for PostgreSQL alongside MongoDB for ACID compliance. | ⏳ Planned |

---