# SecureGate-LDAP: MFA-Enabled Enterprise Auth Bridge
SecureGate-LDAP is a security-focused Flask web application that demonstrates how to implement a multi-layered authentication system. It integrates Active Directory/LDAP for primary credentials with TOTP (Time-based One-Time Password) for Multi-Factor Authentication, backed by MongoDB.

# 🛡️ Security Features
* Multi-Layered Auth: Combines LDAP/AD credential verification with Google Authenticator (TOTP).

* Brute-Force Protection: Built-in rate limiting and account lockout mechanisms (5 attempts, 5-minute lockout).

* Bot Prevention: Integrated Google reCAPTCHA v2 to prevent automated login attempts.

* Hardened Headers: Implements X-Frame-Options, X-Content-Type-Options, and HSTS to mitigate common web attacks.

* Secure Sessions: Uses HttpOnly, SameSite=Lax, and Secure cookie flags.

* Data Integrity: Passwords (local fallback) are hashed using Bcrypt with a unique salt.

# 🚀 Tech Stack
* Backend: Python (Flask)

* Database: MongoDB (using PyMongo)

* Identity: LDAP3 (Active Directory integration)

* MFA: PyOTP & QRCode

* Validation: Flask-WTF & Google reCAPTCHA

# 🛠️ Installation & Setup
1. Prerequisites
* Python 3.8+

* MongoDB (Local instance or Atlas)

* Google reCAPTCHA API Keys ([Get them here](https://www.google.com/recaptcha/admin/))

2. Clone and Install
Bash
git clone https://github.com/your-username/SecureGate-LDAP.git
cd SecureGate-LDAP
pip install -r requirements.txt
3. Configuration
Open app.py and update the following variables:

app.config['RECAPTCHA_PUBLIC_KEY']: Your Site Key.

app.config['RECAPTCHA_PRIVATE_KEY']: Your Secret Key.

LDAP_SERVER: Your organization's LDAP URL.

4. Run the Application
Bash
python app.py
The app will be available at http://localhost:5000.

📖 Usage Flow
Registration: New users register and are presented with a QR Code. Scan this with Google Authenticator or Authy.

Primary Login: User enters LDAP/AD credentials and solves the reCAPTCHA.

MFA Challenge: Upon successful primary auth, the user is redirected to the MFA page to enter the 6-digit TOTP code.

Access Granted: A secure session is established only after both factors are verified.

📝 Requirements (requirements.txt)
Ensure your requirements.txt includes:

Plaintext
Flask
Flask-WTF
pymongo
bcrypt
pyotp
qrcode
ldap3
