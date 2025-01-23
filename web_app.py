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

@app.route('/')
def home():
    user_email = session.get('user_email')
    return render_template('index.html', user_email=user_email)

@app.route('/suggest', methods=['GET', 'POST'])
def suggest():
    """Handles suggestions for both website and Chrome extension."""
    user_email = session.get('user_email')
    suggested_subject = None
    suggested_body = None
    error_message = None

    if request.method == 'POST':
        # Check content type to differentiate between form submission and JSON request
        if request.content_type == "application/json":
            # JSON request from Chrome extension
            data = request.get_json()
            subject = data.get("subject")
        else:
            # Form-encoded request from the website
            subject = request.form.get('subject')

        if not subject:
            error_message = "Subject is required."
            if request.content_type == "application/json":
                return jsonify({"error": error_message}), 400
        else:
            try:
                # Call OpenAI API to generate both subject and body
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo-16k",  # Use "gpt-4" or "gpt-3.5-turbo"
                    messages=[
                        {"role": "system",
                         "content": "You are an AI assistant that generates professional emails in HTML format."},
                        {"role": "user",
                         "content": f"Generate a professional email for the subject: {subject}. Use proper HTML formatting and don't show ''' html  and return only the email content without additional text or instructions."}
                    ],
                    max_tokens=500,
                    temperature=0.7
                )

                # Extract the content from the response
                gpt_response = response.choices[0].message["content"]

                # Split the response into subject and body
                if "Subject:" in gpt_response:
                    parts = gpt_response.split("Subject:", 1)
                    suggested_subject = parts[1].split("\n", 1)[0].strip()
                    suggested_body = parts[1].split("\n", 1)[1].strip()
                else:
                    # Fallback if the response does not include a clear "Subject:"
                    suggested_subject = f"Re: {subject}"  # Default subject if not parsed
                    suggested_body = gpt_response.strip()

                # Return JSON if the request is from the Chrome extension
                if request.content_type == "application/json":
                    return jsonify({"suggested_subject": suggested_subject, "suggested_body": suggested_body}), 200

            except openai.error.OpenAIError as e:
                error_message = f"Failed to fetch email format: {str(e)}"
                if request.content_type == "application/json":
                    return jsonify({"error": error_message}), 500
            except Exception as e:
                error_message = f"Unexpected error: {str(e)}"
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
            # Placeholder: Use Firebase REST API to verify the password (implement this in production)
            session['user_email'] = user.email
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        except auth.UserNotFoundError:
            flash("User not found. Please check your email or sign up.", "danger")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "danger")

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user signup using Firebase Authentication."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Create a new user in Firebase
            user = auth.create_user(email=email, password=password)
            session['user_email'] = email
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('home'))
        except firebase_admin.auth.EmailAlreadyExistsError:
            flash("Email already exists. Please log in instead.", "danger")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "danger")
    return render_template('signup.html')


@app.route('/logout')
def logout():
    """Logs out the user."""
    session.pop('user_email', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)


