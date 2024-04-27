import sqlite3
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from flask import Flask, request, g, jsonify, make_response
from flask_wtf import CSRFProtect
import secrets
import jwt

# Create Flask app and setup CSRF protection
app = Flask(__name__)
csrf = CSRFProtect(app)

# Generate a secure secret key for JWT encoding and CSRF protection
secret_key = secrets.token_urlsafe(16)
app.config['SECRET_KEY'] = secret_key

# Configure cookie security
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

SECRET = secret_key

def get_user_with_credentials(email, password):
    """Retrieve user from the database by email and verify password."""
    con = sqlite3.connect('bank.db')
    cur = con.cursor()
    cur.execute('SELECT email, name, password FROM users where email=?', (email,))
    row = cur.fetchone()
    con.close()
    user_found = (row is not None)
    password_correct = user_found and pbkdf2_sha256.verify(password, row[2])
    if user_found and password_correct:
        return {"email": row[0], "name": row[1], "token": create_token(row[0])}
    else:
        # Provide a generic error message to prevent user enumeration
        return None

def logged_in():
    """Check if the user's auth token is valid."""
    token = request.cookies.get('auth_token')
    try:
        data = jwt.decode(token, SECRET, algorithms=['HS256'])
        g.user = data['sub']
        return True
    except jwt.InvalidTokenError:
        return False

def create_token(email):
    """Create a JWT token for authenticated users."""
    try:
        now = datetime.utcnow()
        payload = {'sub': email, 'iat': now, 'exp': now + timedelta(minutes=60)}
        return jwt.encode(payload, SECRET, algorithm='HS256')
    except Exception as e:
        # Error handling for token creation
        return {"error": str(e), "status": 500}
