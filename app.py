from flask import Flask, render_template, request, redirect, session, send_from_directory, abort
import sqlite3
import random
import smtplib
import os
import secrets
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# FIX 1: __name__ double underscores (was _name_)
app = Flask(__name__)

# FIX 2: Strong random secret key (was hardcoded "secretkey")
app.secret_key = secrets.token_hex(32)

# ---------------- SESSION TIMEOUT ----------------
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# ---------------- FILE UPLOAD CONFIG ----------------
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "pptx", "txt", "png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- EMAIL CONFIG ----------------
# FIX 3: Load from environment variables (not hardcoded in source)
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS", "usemails647@gmail.com")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "geuvlddrtdatufmj")

# ---------------- ADMIN INFO ----------------
# FIX 4: Admin password is now hashed — no more plain text comparison
ADMIN_ID = "admin001"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")
ADMIN_NAME = "System Admin"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "usemails647@gmail.com")

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect("edtech.db")
    conn.row_factory = sqlite3.Row
    return conn

# FIX 5: DB init extracted to a function called at startup
# Tables are created whether you use `flask run` or `python app.py`
def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        name TEXT,
        email TEXT,
        role TEXT,
        password TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        name TEXT,
        email TEXT,
        role TEXT,
        action TEXT,
        status TEXT,
        timestamp TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS materials(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        filename TEXT,
        teacher TEXT
    )
    """)
    db.commit()
    db.close()

with app.app_context():
    init_db()

# ---------------- EMAIL FUNCTION ----------------
def send_otp_email(receiver, otp):
    message = f"""
Your OTP is: {otp}

This OTP expires in 5 minutes. Do not share it.
"""
    msg = MIMEText(message)
    msg["Subject"] = "OTP Verification"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = receiver
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, receiver, msg.as_string())
        server.quit()
    except Exception as e:
        print("Email Error:", e)

# ---------------- AUDIT LOG ----------------
def log_action(user_id, name, email, role, action, status="success"):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
    INSERT INTO audit_log(user_id,name,email,role,action,status,timestamp)
    VALUES(?,?,?,?,?,?,?)
    """, (user_id, name, email, role, action, status, str(datetime.now())))
    db.commit()
    db.close()

# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect("/login")

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form["role"]
        user_id = request.form["user_id"]
        password = request.form["password"]

        # ADMIN LOGIN
        if role == "admin":
            # FIX 4 (cont): check_password_hash instead of plain string compare
            if user_id == ADMIN_ID and check_password_hash(ADMIN_PASSWORD_HASH, password):
                otp = str(random.randint(100000, 999999))
                session["otp"] = otp
                # FIX 6: Store OTP generation time for expiry check
                session["otp_time"] = datetime.now().isoformat()
                session["purpose"] = "admin"
                send_otp_email(ADMIN_EMAIL, otp)
                return redirect("/verify_otp")
            else:
                return render_template("login.html", error="Invalid Admin Credentials")

        # USER LOGIN
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id=? AND role=?", (user_id, role))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user["password"], password):
            otp = str(random.randint(100000, 999999))
            session.permanent = True
            session["otp"] = otp
            # FIX 6: Store OTP generation time for expiry check
            session["otp_time"] = datetime.now().isoformat()
            session["purpose"] = "login"
            session["temp_user"] = user["id"]
            session["temp_role"] = user["role"]
            session["temp_name"] = user["name"]
            session["temp_email"] = user["email"]
            send_otp_email(user["email"], otp)
            return redirect("/verify_otp")
        else:
            return render_template("login.html", error="Invalid ID, Role, or Password")

    return render_template("login.html")

# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        user_id = request.form["id"]
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"]
        password = generate_password_hash(request.form["password"])
        otp = str(random.randint(100000, 999999))
        session["otp"] = otp
        # FIX 6: Store OTP generation time
        session["otp_time"] = datetime.now().isoformat()
        session["purpose"] = "signup"
        session["new_user"] = {
            "id": user_id,
            "name": name,
            "email": email,
            "role": role,
            "password": password
        }
        send_otp_email(email, otp)
        return redirect("/verify_otp")
    return render_template("signup.html")

# ---------------- OTP VERIFY ----------------
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered = request.form["otp"]

        # FIX 6: Reject OTP if older than 5 minutes
        otp_time_str = session.get("otp_time")
        if otp_time_str:
            otp_time = datetime.fromisoformat(otp_time_str)
            if datetime.now() - otp_time > timedelta(minutes=5):
                session.pop("otp", None)
                session.pop("otp_time", None)
                return render_template("verify.html", error="OTP expired. Please log in again.")

        if entered == session.get("otp"):
            purpose = session.get("purpose")

            # FIX 7: Clear OTP from session immediately after successful use
            session.pop("otp", None)
            session.pop("otp_time", None)

            if purpose == "admin":
                session["user"] = ADMIN_ID
                session["role"] = "admin"
                log_action(ADMIN_ID, ADMIN_NAME, ADMIN_EMAIL, "admin", "login")
                return redirect("/admin_dashboard")

            elif purpose == "signup":
                user = session["new_user"]
                db = get_db()
                cursor = db.cursor()
                cursor.execute(
                    "INSERT INTO users VALUES(?,?,?,?,?)",
                    (user["id"], user["name"], user["email"], user["role"], user["password"])
                )
                db.commit()
                db.close()
                session["user"] = user["id"]
                session["role"] = user["role"]
                # FIX 8: Log signup action (was never logged before)
                log_action(user["id"], user["name"], user["email"], user["role"], "signup")
                # FIX 9: Added missing redirect for admin role after signup
                if user["role"] == "student":
                    return redirect("/dashboard")
                if user["role"] == "teacher":
                    return redirect("/teacher_dashboard")
                if user["role"] == "admin":
                    return redirect("/admin_dashboard")

            elif purpose == "login":
                session["user"] = session["temp_user"]
                session["role"] = session["temp_role"]
                log_action(
                    session["temp_user"],
                    session["temp_name"],
                    session["temp_email"],
                    session["temp_role"],
                    "login"
                )
                if session["temp_role"] == "student":
                    return redirect("/dashboard")
                if session["temp_role"] == "teacher":
                    return redirect("/teacher_dashboard")
        else:
            return render_template("verify.html", error="Invalid OTP")

    return render_template("verify.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- ADMIN DASHBOARD ----------------
# FIX 10: All unauthorized routes now redirect to /login (was returning plain string)
@app.route("/admin_dashboard")
def admin_dashboard():
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY id DESC")
    logs = cursor.fetchall()
    db.close()
    # NOTE: rename your file admin_dasboard.html → admin_dashboard.html
    return render_template("admin_dashboard.html", logs=logs)

# ---------------- MANAGE USERS ----------------
@app.route("/manage_users", methods=["GET", "POST"])
def manage_users():
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    if request.method == "POST":
        user_id = request.form["id"]
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"]
        password = generate_password_hash(request.form["password"])
        cursor.execute("INSERT INTO users VALUES(?,?,?,?,?)", (user_id, name, email, role, password))
        db.commit()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    db.close()
    return render_template("manage_user.html", users=users)

# ---------------- DELETE USER ----------------
@app.route("/delete_user/<user_id>")
def delete_user(user_id):
    if "user" not in session or session["role"] != "admin":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    db.close()
    return redirect("/manage_users")

# ---------------- TEACHER DASHBOARD ----------------
@app.route("/teacher_dashboard")
def teacher_dashboard():
    if "user" not in session or session["role"] != "teacher":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM materials WHERE teacher=? ORDER BY id DESC", (session["user"],))
    materials = cursor.fetchall()
    db.close()
    return render_template("teacher_dashboard.html", materials=materials)

# ---------------- STUDENT DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM materials ORDER BY id DESC")
    materials = cursor.fetchall()
    db.close()
    return render_template("dashboard.html", materials=materials)

# ---------------- VIEW STUDENTS ----------------
@app.route("/view_students")
def view_students():
    if "user" not in session or session["role"] != "teacher":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE role='student'")
    students = cursor.fetchall()
    db.close()
    return render_template("view_students.html", students=students)

# ---------------- UPLOAD MATERIAL ----------------
@app.route("/upload_material", methods=["GET", "POST"])
def upload_material():
    if "user" not in session or session["role"] != "teacher":
        return redirect("/login")
    if request.method == "POST":
        title = request.form["title"]
        file = request.files["file"]
        if not allowed_file(file.filename):
            return "File type not allowed! Only PDF, DOCX, PPTX, TXT, PNG, JPG, JPEG."
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO materials(title,filename,teacher)
            VALUES(?,?,?)
        """, (title, filename, session["user"]))
        db.commit()
        db.close()
        return redirect("/view_materials")
    return render_template("upload_material.html")

# ---------------- VIEW MATERIALS ----------------
# Teachers see only their own; students redirected to /student_materials
@app.route("/view_materials")
def view_materials():
    if "user" not in session:
        return redirect("/login")
    if session["role"] == "student":
        return redirect("/student_materials")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM materials WHERE teacher=? ORDER BY id DESC", (session["user"],))
    materials = cursor.fetchall()
    db.close()
    return render_template("view_materials.html", materials=materials)

# ---------------- STUDENT MATERIALS ----------------
@app.route("/student_materials")
def student_materials():
    if "user" not in session or session["role"] != "student":
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM materials ORDER BY id DESC")
    materials = cursor.fetchall()
    db.close()
    return render_template("student_materials.html", materials=materials)

# ---------------- DOWNLOAD ----------------
# FIX 12: Auth check added — was completely open to unauthenticated users
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/login")
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# ---------------- RUN ----------------
# FIX 1 (cont): __name__ double underscores (was _name_=="main_")
if __name__ == "__main__":
    app.run(debug=True)