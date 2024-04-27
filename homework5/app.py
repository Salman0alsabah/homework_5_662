from flask import Flask, request, make_response, redirect, render_template, g, abort
from user_service import get_user_with_credentials, logged_in
from account_service import get_balance, do_transfer
from flask_wtf.csrf import CSRFProtect, generate_csrf
import secrets
import time

app = Flask(__name__)
# Generate a URL-safe text string, which is crucial for securing the Flask app's secret key.
secret_key = secrets.token_urlsafe(16)  # Adjust the number of bytes as needed.
app.config['SECRET_KEY'] = secret_key
csrf = CSRFProtect(app)  # Initialize CSRF protection for the Flask app.

@app.route("/", methods=['GET'])
def home():
    # Redirect to login if the user is not logged in, preventing unauthorized access.
    if not logged_in():
        return render_template("login.html")
    return redirect('/dashboard')

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    user = get_user_with_credentials(email, password)
        
    # Simulate a delay to prevent timing attacks which can be used for user enumeration.
    time.sleep(1)

    if not user:
        # Render the same login page with a generic error to avoid leaking user existence.
        return render_template("login.html", error="Invalid credentials")
    response = make_response(redirect("/dashboard"))
    # Set secure cookies to prevent XSS attacks and ensure cookies are transmitted over HTTPS only.
    response.set_cookie("auth_token", user["token"], httponly=True, secure=True)
    return response, 303

@app.route("/dashboard", methods=['GET'])
def dashboard():
    if not logged_in():
        return redirect('/login')  # Redirect to login page if not logged in
    return render_template("dashboard.html", email=g.user)

@app.route("/details", methods=['GET'])
def details():
    if not logged_in():
        return render_template("login.html")
    account_number = request.args.get('account')
    balance = get_balance(account_number, g.user)
    return render_template("details.html", user=g.user, account_number=account_number, balance=balance)

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not logged_in():
        return render_template("login.html")

    if request.method == "POST":
        source = request.form.get("from")
        to_email = request.form.get("to_email")  # New input field for email
        to_account = request.form.get("to_account")  # New input field for account number
        amount = request.form.get("amount")

        # Validate that all required fields are provided to prevent incomplete form submissions.
        if not source or not to_email or not to_account or not amount:
            abort(400, "All fields are required for the transfer")

        try:
            amount = int(amount)  # Ensure amount is a valid integer to prevent type errors.
        except ValueError:
            abort(400, "Invalid amount format")

        if amount < 0:
            abort(400, "Amount cannot be negative")  # Validate that the amount is non-negative.

        if amount > 1000:
            abort(400, "Transfer amount exceeds maximum limit")  # Enforce a maximum transfer limit.

        source_balance = get_balance(source, g.user)
        target_balance = get_balance(to_account, to_email)

        if source_balance is None or target_balance is None:
            abort(404, "Source or target account not found")  # Validate existence of accounts.

        if amount > source_balance:
            abort(400, "Insufficient balance for transfer")  # Check for sufficient funds.

        success = do_transfer(source, to_account, amount)

        if success:
            message = f"Transfer of {amount} units from account {source} to account {to_account} was successful."
            return render_template("dashboard.html", message=message)
        else:
            abort(500, "Internal Server Error")

    return render_template("transfer.html")

@app.route("/logout", methods=['GET'])
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie('auth_token')  # Securely log out by deleting the authentication token.
    return response, 303

@app.before_request
def before_request():
    # Generate a CSRF token for each request to mitigate CSRF attacks.
    g.csrf_token = generate_csrf()

if __name__ == "__main__":
    app.run(debug=True)  # Enable debugging mode for development purposes.
