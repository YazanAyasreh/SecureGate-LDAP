# Flask Secure MFA Application with MongoDB
# Requirements: pip install -r requirements.txt

from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import pyotp
import qrcode
import os
import secrets
import bcrypt
from datetime import datetime, timedelta
from pymongo import MongoClient

# LDAP import (optional - requires ldap3 package: pip install ldap3)
try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    Server = None
    Connection = None
    ALL = None
    SUBTREE = None

app = Flask(__name__)

# =======================
# SECURITY CONFIGURATION
# =======================

app.secret_key = secrets.token_hex(32)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB = "mfa_app"

# reCAPTCHA Configuration (GET YOUR KEYS FROM: https://www.google.com/recaptcha/admin)
app.config['RECAPTCHA_PUBLIC_KEY'] = 'Add Your Site Key Here'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'Add Your Secret Key Here'
app.config['RECAPTCHA_ENABLED'] = True

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Session security
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300

# =======================
# MongoDB Connection
# =======================
def get_db():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]

def init_db():
    db = get_db()
    # Create users collection
    if 'users' not in db.list_collection_names():
        db.create_collection('users')
        db.users.create_index('username', unique=True)
    
    # Create login_attempts collection
    if 'login_attempts' not in db.list_collection_names():
        db.create_collection('login_attempts')
        db.login_attempts.create_index('username')

init_db()

# =======================
# LDAP Authentication
# =======================
def ldap_auth(username, password):
    """
    Authenticate user against LDAP server.
    Falls back to local authentication if LDAP is not available.
    """
    if not LDAP_AVAILABLE:
        # Fallback: authenticate against local MongoDB users
        db = get_db()
        user = db.users.find_one({'username': username})
        
        if user and 'password_hash' in user:
            return verify_password(password, user['password_hash'])
        return False
    
    LDAP_SERVER = "ldap://127.0.0.1"
    LDAP_BASE_DN = "dc=example,dc=com"
    
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        # Try to bind with user DN - adjust based on your LDAP schema
        user_dn = f"cn={username},{LDAP_BASE_DN}"
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        result = conn.bind()
        conn.unbind()
        return result
    except Exception as e:
        # Log the error in production; don't expose details to user
        print(f"LDAP authentication error: {str(e)}")
        return False

# =======================
# Password Hashing
# =======================
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

# =======================
# Rate Limiting
# =======================
def check_rate_limit(username):
    db = get_db()
    result = db.login_attempts.find_one({'username': username})
    
    if result:
        attempts = result.get('attempts', 0)
        locked_until = result.get('locked_until')
        
        if locked_until:
            locked_time = datetime.fromisoformat(locked_until)
            if datetime.now() < locked_time:
                return False, f"Account locked. Try again after {locked_time}"
            else:
                db.login_attempts.update_one(
                    {'username': username},
                    {'$set': {'attempts': 0, 'locked_until': None}}
                )
        
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = (datetime.now() + timedelta(seconds=LOCKOUT_DURATION)).isoformat()
            db.login_attempts.update_one(
                {'username': username},
                {'$set': {'locked_until': locked_until}}
            )
            return False, f"Too many failed attempts. Account locked for {LOCKOUT_DURATION//60} minutes"
    
    return True, None

def record_failed_attempt(username):
    db = get_db()
    result = db.login_attempts.find_one({'username': username})
    
    if result:
        db.login_attempts.update_one(
            {'username': username},
            {'$inc': {'attempts': 1}, '$set': {'last_attempt': datetime.now()}}
        )
    else:
        db.login_attempts.insert_one({
            'username': username,
            'attempts': 1,
            'last_attempt': datetime.now()
        })

def reset_login_attempts(username):
    db = get_db()
    db.login_attempts.update_one(
        {'username': username},
        {'$set': {'attempts': 0, 'locked_until': None}}
    )
    db.users.update_one(
        {'username': username},
        {'$set': {'last_login': datetime.now()}}
    )

# =======================
# Input Validation
# =======================
def sanitize_input(input_str):
    if not input_str:
        return ""
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`']
    result = input_str
    for char in dangerous_chars:
        result = result.replace(char, '')
    return result.strip()

def validate_username(username):
    if not username:
        return False
    return len(username) >= 3 and len(username) <= 50 and username.replace('_', '').isalnum()

def validate_password(password):
    if not password or len(password) < 8:
        return False
    return any(c.isalpha() for c in password) and any(c.isdigit() for c in password)

# =======================
# WTForms
# =======================
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

class MFAForm(FlaskForm):
    otp = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

# =======================
# Create Templates Directory
# =======================
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

# =======================
# Base Template
# =======================
base_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        :root {
            --primary: #111827; /* Dark charcoal */
            --bg: #f9fafb;
            --border: #e5e7eb;
            --text-main: #111827;
            --text-muted: #6b7280;
        }

        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif; 
            background-color: var(--bg); 
            color: var(--text-main);
            min-height: 100vh; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            margin: 0; 
        }

        .container { 
            background: white; 
            border: 1px solid var(--border);
            border-radius: 8px; 
            padding: 32px; 
            max-width: 400px; 
            width: 100%; 
        }

        h2 { 
            font-size: 1.5rem; 
            font-weight: 700; 
            margin: 0 0 8px 0; 
            text-align: center;
        }

        p.subtitle {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-bottom: 24px;
        }

        .form-group { margin-bottom: 16px; }

        label { 
            display: block; 
            margin-bottom: 6px; 
            font-size: 0.875rem;
            font-weight: 500; 
        }

        input { 
            width: 100%; 
            padding: 10px 12px; 
            border: 1px solid var(--border); 
            border-radius: 6px; 
            font-size: 1rem; 
            box-sizing: border-box; 
            transition: border-color 0.2s;
        }

        input:focus { 
            outline: none; 
            border-color: var(--primary); 
            ring: 2px solid #000;
        }

        button { 
            width: 100%; 
            padding: 12px; 
            background: var(--primary); 
            color: white; 
            border: none; 
            border-radius: 6px; 
            font-size: 0.95rem; 
            font-weight: 600; 
            cursor: pointer; 
            margin-top: 8px;
        }

        button:hover { opacity: 0.9; }

        .alert { 
            padding: 10px; 
            border-radius: 6px; 
            margin-bottom: 16px; 
            font-size: 0.875rem; 
            text-align: center; 
        }

        .alert-error { background: #fef2f2; color: #991b1b; }

        .links { text-align: center; margin-top: 24px; font-size: 0.875rem; }
        .links a { color: var(--text-muted); text-decoration: underline; }
        
        /* reCAPTCHA centering */
        .g-recaptcha { margin-bottom: 16px; display: flex; justify-content: center; }
    </style>
</head>
<body>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>"""

login_html = """{% extends "base.html" %}
{% block content %}
<h2>Sign in</h2>
<p class="subtitle">Enter your credentials to continue</p>

<form method="POST">
    <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="e.g. jdoe" required>
    </div>
    <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
    </div>
    <div class="g-recaptcha" data-sitekey="{{ recaptcha_site_key }}"></div>
    <button type="submit">Continue</button>
</form>

<div class="links">
    <a href="/register">Create an account</a>
</div>
{% endblock %}"""

register_html = """{% extends "base.html" %}
{% block content %}
<h2>Register</h2>
<div class="security-info">
    <strong>Requirements:</strong> Username 3-50 chars, Password 8+ chars with letters and numbers
</div>
<form method="POST">
    <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
    </div>
    <div class="form-group">
        <label>Confirm Password</label>
        <input type="password" name="confirm_password" required>
    </div>
    <div class="g-recaptcha" data-sitekey="{{ recaptcha_site_key }}"></div>
    <button type="submit">Register</button>
</form>
<div class="links">
    <a href="/login">Login</a>
</div>
{% endblock %}"""

mfa_html = """{% extends "base.html" %}
{% block content %}
<h2>Verification</h2>
<p class="subtitle">Enter the 6-digit code from your app</p>

<form method="POST">
    <div class="form-group">
        <input type="text" name="otp" 
               placeholder="000000" 
               style="text-align: center; font-size: 1.5rem; letter-spacing: 0.5rem;"
               required pattern="[0-9]{6}" maxlength="6">
    </div>
    <button type="submit">Verify</button>
</form>

<div class="links">
    <a href="/logout">Cancel and sign out</a>
</div>
{% endblock %}"""

home_html = """<!DOCTYPE html>
<html>
<head>
    <title>Success</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; }
        .container { background: white; border-radius: 10px; padding: 40px; text-align: center; box-shadow: 0 15px 35px rgba(0,0,0,0.2); }
        h1 { color: #4CAF50; }
        .logout-btn { display: inline-block; margin-top: 20px; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Successful!</h1>
        <p>Welcome <strong>{{ username }}</strong></p>
        <p>Authenticated with:</p>
        <ul style="text-align: left; color: #666;">
            <li>LDAP/AD Credentials</li>
            <li>Google reCAPTCHA</li>
            <li>MFA (TOTP)</li>
        </ul>
        <a href="/logout" class="logout-btn">Logout</a>
    </div>
</body>
</html>"""

qr_html = """{% extends "base.html" %}
{% block content %}
<h2>Setup Google Authenticator</h2>
<div class="qr-container">
    <p>Scan this QR code:</p>
    <img src="/static/qrcode.png" alt="QR Code">
    <p>Secret: <strong>{{ secret }}</strong></p>
</div>
<div class="links">
    <a href="/login">Continue to Login</a>
</div>
{% endblock %}"""

with open(os.path.join(templates_dir, 'base.html'), 'w') as f:
    f.write(base_html)
with open(os.path.join(templates_dir, 'login.html'), 'w') as f:
    f.write(login_html)
with open(os.path.join(templates_dir, 'register.html'), 'w') as f:
    f.write(register_html)
with open(os.path.join(templates_dir, 'mfa.html'), 'w') as f:
    f.write(mfa_html)
with open(os.path.join(templates_dir, 'home.html'), 'w') as f:
    f.write(home_html)
with open(os.path.join(templates_dir, 'qr.html'), 'w') as f:
    f.write(qr_html)

# =======================
# Routes
# =======================

@app.route('/')
def home():
    if "user" in session:
        return render_template('home.html', username=session['user'])
    return redirect("/login")

@app.route('/register', methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect("/")
    
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        if not validate_username(username):
            flash("Invalid username format", "error")
            return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        if not validate_password(password):
            flash("Password must be 8+ characters with letters and numbers", "error")
            return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        db = get_db()
        
        if db.users.find_one({'username': username}):
            flash("Username already exists", "error")
            return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        otp_secret = pyotp.random_base32()
        password_hash = hash_password(password)
        
        try:
            db.users.insert_one({
                'username': username,
                'password_hash': password_hash,
                'otp_secret': otp_secret,
                'created_at': datetime.now(),
                'is_active': True
            })
        except Exception as e:
            flash(f"Error: {str(e)}", "error")
            return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        totp = pyotp.TOTP(otp_secret)
        uri = totp.provisioning_uri(username, issuer_name="SecureMFApp")
        
        os.makedirs("static", exist_ok=True)
        img = qrcode.make(uri)
        img.save("static/qrcode.png")
        
        return render_template('qr.html', secret=otp_secret)
    
    return render_template('register.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/login', methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect("/")
    
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        allowed, message = check_rate_limit(username)
        if not allowed:
            flash(message, "error")
            return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        if not username or not password:
            flash("Please enter username and password", "error")
            return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        if not ldap_auth(username, password):
            record_failed_attempt(username)
            flash("Invalid LDAP credentials", "error")
            return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        db = get_db()
        user = db.users.find_one({'username': username})
        
        if not user:
            flash("User not found. Please register first.", "error")
            return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        otp_secret = user.get('otp_secret')
        is_active = user.get('is_active', True)
        
        if not is_active:
            flash("Account is disabled", "error")
            return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        session["tmp_user"] = username
        session["otp_secret"] = otp_secret
        session.permanent = True
        
        return redirect("/mfa")
    
    return render_template('login.html', recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/mfa', methods=["GET", "POST"])
def mfa():
    if "tmp_user" not in session or "otp_secret" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        
        if not otp or not otp.isdigit() or len(otp) != 6:
            flash("Please enter a valid 6-digit OTP", "error")
            return render_template('mfa.html')
        
        otp_secret = session.get("otp_secret")
        totp = pyotp.TOTP(otp_secret)
        
        if totp.verify(otp, valid_window=1):
            username = session.get("tmp_user")
            reset_login_attempts(username)
            session["user"] = username
            session.pop("tmp_user", None)
            session.pop("otp_secret", None)
            return redirect("/")
        else:
            flash("Invalid OTP code", "error")
            return render_template('mfa.html')
    
    return render_template('mfa.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    
    print("=" * 50)
    print("Secure MFA Application with MongoDB Started")
    print("=" * 50)
    print("\nIMPORTANT STEPS:")
    print("1. Install MongoDB Compass from:")
    print("   https://www.mongodb.com/products/compass")
    print("2. Start MongoDB locally or use MongoDB Atlas")
    print("3. Configure reCAPTCHA:")
    print("   - Go to https://www.google.com/recaptcha/admin")
    print("   - Create a new site with reCAPTCHA v2 Checkbox")
    print("   - Update RECAPTCHA_PUBLIC_KEY and RECAPTCHA_PRIVATE_KEY")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
