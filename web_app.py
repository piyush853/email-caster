from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import openai
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth
import requests
import os
from dotenv import load_dotenv


# Load environment variables
load_dotenv()
# Initialize Firebase Admin SDK
cred = credentials.Certificate("config/emailcaster-c199c-firebase-adminsdk-fbsvc-1f6b1f673e.json")  # Replace with your Firebase Admin SDK JSON file
firebase_admin.initialize_app(cred)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-key")  # Use environment variable for production

# Configure OpenAI API Key
openai.api_key = os.environ.get("OPENAI_API_KEY")  # Use environment variable for API key

FIREBASE_API_KEY = os.environ.get("FIREBASE_KEY")

# Enable CORS for Chrome extension
CORS(app)
def send_verification_email(user_id_token):
    """Send email verification link using Firebase Authentication REST API"""
    try:
        verification_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
        data = {
            "requestType": "VERIFY_EMAIL",
            "idToken": user_id_token,
        }
        response = requests.post(verification_url, json=data)
        if response.status_code == 200:
            return True
        else:
            error_message = response.json().get("error", {}).get("message", "An error occurred.")
            flash(f"Failed to send verification email: {error_message}", "danger")
            return False
    except Exception as e:
        flash(f"Error sending verification email: {e}", "danger")
        return False
@app.route('/')
def home():

    user_email = session.get('user_email')

    return render_template('index.html', user_email=user_email)



@app.route('/suggest', methods=['GET', 'POST'])
def suggest():
    user_email = session.get('user_email')
    suggested_subject = None
    suggested_body = None
    error_message = None

    if request.method == 'POST':
        # Check if the request is from the Chrome extension (application/json)
        if request.content_type == "application/json":
            data = request.get_json()
            subject = data.get("subject")
        else:
            # Default form request for the website
            subject = request.form.get('subject')

        if not subject:
            error_message = "Subject is required."
            if request.content_type == "application/json":
                return jsonify({"error": error_message}), 400
        else:
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system",
                         "content": "You are an AI that generates professional emails in HTML format."},
                        {"role": "user",
                         "content": f"Generate a professional email for the subject: {subject}.User proper HTML formatting and don't show '''html and return only the email content without additional text or instruction and don't alter the html css formating of page."}
                    ],
                    max_tokens=500,
                    temperature=0.7
                )
                gpt_response = response.choices[0].message["content"]

                suggested_subject = f"Re: {subject}"  # Default subject
                suggested_body = gpt_response.strip()

                # Return JSON response for API requests
                if request.content_type == "application/json":
                    return jsonify({"suggested_subject": suggested_subject, "suggested_body": suggested_body}), 200
            except Exception as e:
                error_message = f"Failed to fetch email format: {str(e)}"
                if request.content_type == "application/json":
                    return jsonify({"error": error_message}), 500


    # Render the suggest.html template for website users
    return render_template(
        'suggest.html',
        user_email=user_email,
        suggested_subject=suggested_subject,
        suggested_body=suggested_body,
        error_message=error_message
    )


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup and sends email verification."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Create user in Firebase
            user = auth.create_user(email=email, password=password)

            # Use Firebase REST API to get ID token
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
            data = {
                "email": email,
                "password": password,
                "returnSecureToken": True,
            }
            response = requests.post(login_url, json=data)
            response_data = response.json()

            if "idToken" in response_data:
                id_token = response_data["idToken"]
                send_verification_email(id_token)  # Send email verification link
                flash(
                    "Signup successful! A verification email has been sent. Please verify your email before logging in.",
                    "success")
                return redirect(url_for('verify_prompt'))
            else:
                flash("Error signing up. Please try again.", "danger")
        except firebase_admin.auth.EmailAlreadyExistsError:
            flash("Email already exists. Please log in instead.", "danger")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

    return render_template('signup.html')


@app.route('/verify_prompt')
def verify_prompt():
    """Renders a prompt asking users to verify their email."""
    return render_template('verify_prompt.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and password reset."""
    if request.method == 'POST':
        if 'reset_password' in request.form:
            # Handle forgot password
            email = request.form.get('email')
            if not email:
                flash("Please provide an email address to reset your password.", "danger")
            else:
                try:
                    # Send password reset email using Firebase Authentication REST API
                    reset_password_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
                    data = {
                        "requestType": "PASSWORD_RESET",
                        "email": email,
                    }
                    response = requests.post(reset_password_url, json=data)
                    response_data = response.json()

                    if response.status_code == 200:
                        flash("Password reset email sent successfully. Please check your inbox.", "success")
                    else:
                        error_message = response_data.get("error", {}).get("message", "An error occurred.")
                        flash(f"Failed to send password reset email: {error_message}", "danger")
                except Exception as e:
                    flash(f"An unexpected error occurred: {e}", "danger")

            return redirect(url_for('login'))

        # Handle login
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Simulate user login (Firebase Admin SDK doesn't handle passwords directly)
            user = auth.get_user_by_email(email)
            if not user.email_verified:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for('verify_prompt'))
            # Placeholder: Use Firebase REST API to verify the password (implement this in production)
            session['user_email'] = user.email
            flash("Login successful!", "success")
            return redirect(url_for('suggest'))
        except auth.UserNotFoundError:
            flash("User not found. Please check your email or sign up.", "danger")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "danger")

    return render_template('login.html')

@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    """Resend verification email upon request."""
    
    email = session.get('unverified_email')  # ✅ Retrieve email from session
    if not email:
        flash("No email found. Please sign up again.", "danger")
        return redirect(url_for('signup'))

    try:
        # ✅ Get Firebase user by email
        user = auth.get_user_by_email(email)

        # ✅ Use Firebase REST API to get ID token (temporary login to resend verification)
        login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        data = {
            "email": email,
            "password": session.get('unverified_password', ''),  # Store password temporarily for login
            "returnSecureToken": True,
        }
        response = requests.post(login_url, json=data)
        response_data = response.json()

        if "idToken" in response_data:
            id_token = response_data["idToken"]

            # ✅ Send verification email
            verification_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_API_KEY}"
            verification_data = {
                "requestType": "VERIFY_EMAIL",
                "idToken": id_token,  # Use ID token for authentication
            }
            verification_response = requests.post(verification_url, json=verification_data)
            verification_result = verification_response.json()

            if verification_response.status_code == 200:
                flash("Verification email resent. Please check your inbox.", "info")
            else:
                error_message = verification_result.get("error", {}).get("message", "An error occurred.")
                flash(f"Failed to resend verification email: {error_message}", "danger")
        else:
            flash("Error logging in to resend verification email. Please try again.", "danger")

    except firebase_admin.auth.UserNotFoundError:
        flash("User not found. Please sign up again.", "danger")
        return redirect(url_for('signup'))
    except Exception as e:
        flash(f"Error resending verification email: {e}", "danger")

    return redirect(url_for('verify_prompt'))


@app.route('/logout')
def logout():
    """Logs out the user."""
    session.pop('user_email', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
