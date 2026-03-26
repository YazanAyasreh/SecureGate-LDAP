# 🛡️ SecureGate-LDAP 
> **Enterprise-Grade MFA Bridge for Active Directory & LDAP**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0+-000000?style=for-the-badge&logo=flask&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4.4+-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

---

## 🌌 Overview
**SecureGate-LDAP** is a high-security authentication gateway designed to modernize legacy infrastructure. It acts as a secure "Front Door" that bridges traditional **LDAP/Active Directory** credentials with modern **Zero-Trust** requirements.



## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| **Dual-Factor Auth** | Primary LDAP/AD login + secondary TOTP (Google Authenticator). |
| **Bot Defense** | Integrated Google reCAPTCHA v2 to neutralize automated attacks. |
| **Brute-Force Guard** | Smart rate-limiting and account lockout via MongoDB tracking. |
| **Hardened Sessions** | HSTS, X-Frame-Options, and Secure/HttpOnly cookie enforcement. |
| **Bcrypt Hashing** | Industry-standard adaptive hashing for local fallback security. |

---

## 🛠️ System Architecture

1. **Authentication:** Validates identity against the organization's Directory Service.
2. **Verification:** Challenges the user with a Time-based One-Time Password (TOTP).
3. **Audit:** Records success/failure metrics in MongoDB for security monitoring.
4. **Encryption:** All secrets are managed via isolated environment variables.

---

## 🚀 Quick Start Guide

### 1. Environment Configuration
Create a `.env` file in the root directory (never commit this!):
```env
SECRET_KEY=your_secure_hex_string
RECAPTCHA_PUBLIC_KEY=your_key
RECAPTCHA_PRIVATE_KEY=your_secret
MONGO_URI=mongodb://localhost:27017/