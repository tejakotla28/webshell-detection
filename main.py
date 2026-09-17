import os
import hashlib
import requests
import shutil
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from flask import session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import g
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_login import current_user, login_required

from config import VIRUSTOTAL_API_KEY
from flask_mysqldb import MySQL

VT_URL = "https://www.virustotal.com/api/v3/files/"
UPLOAD_FOLDER = "uploads"
QUARANTINE_FOLDER = "quarantine"
HISTORY_FILE = "history.json"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = '9a6e3f2c8bde42a8bfa1a3e7f1c4d790'
# Simulated user DB (replace with real DB later)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Change if different
app.config['MYSQL_PASSWORD'] = 'Wizard@12'  # Add your password here
app.config['MYSQL_DB'] = 'virus_scanner'
mysql = MySQL(app)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def calculate_file_hash(filepath, hash_type='sha256'):
    h = hashlib.new(hash_type)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def move_to_quarantine(file_path):
    filename = os.path.basename(file_path)
    dest_path = os.path.join(QUARANTINE_FOLDER, filename)
    shutil.move(file_path, dest_path)
    print(f"Malicious file moved to quarantine: {dest_path}")

from flask_login import current_user

def save_scan_history(filename, file_hash, result):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    result_json = json.dumps(result)
    
    if current_user.is_authenticated:
        user_email = current_user.email
    else:
        user_email = "anonymous"  # or handle accordingly
    
    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO scans (user_email, timestamp, filename, file_hash, result)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_email, timestamp, filename, file_hash, result_json))
    mysql.connection.commit()
    cursor.close()


def check_file_with_virustotal(file_path):
    file_hash = calculate_file_hash(file_path)
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(f"{VT_URL}{file_hash}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        analysis_results = data["data"]["attributes"]["last_analysis_results"]

        virus_details = []
        for engine, result in analysis_results.items():
            if result["category"] in ("malicious", "suspicious"):
                virus_details.append({"engine": engine, "type": result['result']})

        if stats["malicious"] > 0:
            move_to_quarantine(file_path)

        result = {
            "malicious": stats['malicious'],
            "harmless": stats['harmless'],
            "suspicious": stats['suspicious'],
            "undetected": stats['undetected'],
            "virus_details": virus_details,
            "message": f"Scan results found for file."
        }
    elif response.status_code == 404:
        with open(file_path, "rb") as f:
            upload_response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={"file": f}
            )
        result = {
            "malicious": 0,
            "virus_details": [],
            "message": "File uploaded to VirusTotal for scanning. Check back later for results."
        }
    else:
        result = {
            "malicious": 0,
            "virus_details": [],
            "message": f"Error communicating with VirusTotal: {response.status_code}"
        }

    save_scan_history(os.path.basename(file_path), file_hash, result)
    return result


#login and all routes
class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

    @staticmethod
    def get_by_email(email):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id, email, password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            return User(user[0], user[1], user[2])
        return None

    @staticmethod
    def get_by_id(id):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id, email, password FROM users WHERE id=%s", (id,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            return User(user[0], user[1], user[2])
        return None
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)



@app.route('/')
def home():
    return render_template('home.html')
@app.route("/scan")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    result = check_file_with_virustotal(filepath)
    if os.path.exists(filepath):
        os.remove(filepath)

    return jsonify(result)

@app.route("/history")
@login_required
def history():
    email = current_user.email
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT timestamp, filename, file_hash, result FROM scans WHERE user_email = %s ORDER BY timestamp DESC", (email,))
    rows = cursor.fetchall()
    cursor.close()

    history = []
    for row in rows:
        history.append({
            "timestamp": row[0],
            "filename": row[1],
            "file_hash": row[2],
            "result": json.loads(row[3])
        })

    return render_template("history.html", history=history)



@app.route('/dashboard')
@login_required
def dashboard():
    email = current_user.email
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT filename, timestamp, result FROM scans WHERE user_email = %s ORDER BY timestamp DESC", (email,))
    rows = cursor.fetchall()
    cursor.close()

    total_scans = len(rows)
    malicious_count = 0
    recent_scans = []

    for row in rows:
        filename = row[0]
        timestamp = row[1].strftime('%Y-%m-%d %H:%M:%S') if row[1] else ""
        result = json.loads(row[2])
        if result.get("malicious", 0) > 0:
            malicious_count += 1
        if len(recent_scans) < 5:
            recent_scans.append({
                "filename": filename,
                "timestamp": timestamp,
                "result": result
            })

    harmless_count = total_scans - malicious_count

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        malicious_count=malicious_count,
        harmless_count=harmless_count,
        recent_scans=recent_scans
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.get_by_email(email)
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if not email or not password or not confirm:
            error = "Please fill all fields."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            existing = cursor.fetchone()
            if existing:
                error = "Email already registered."
            else:
                hashed = generate_password_hash(password)
                cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed))
                mysql.connection.commit()
                cursor.close()
                flash("Registered successfully! Please login.")
                return redirect(url_for("login"))
    return render_template("register.html", error=error)

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        # Example: update user info logic here, e.g. password change, email, etc.
        flash("Settings updated!", "success")
        return redirect(url_for("profile"))
    return render_template("settings.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
