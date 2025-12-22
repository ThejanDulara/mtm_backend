import os
import datetime
import pymysql
from flask import Blueprint, request, jsonify, g, current_app as app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token, set_access_cookies, unset_jwt_cookies,
    jwt_required, get_jwt_identity
)
from .emailer import send_mail
from .otp import create_otp, verify_otp, mark_otp_used
from .config import Config

auth_bp = Blueprint("auth", __name__)

# ✅ Helper function: Fetch user by email
def get_user_by_email(email):
    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cur.fetchone()
    conn.close()
    return user

# ✅ SIGN UP (User registration – pending admin approval)
@auth_bp.post("/signup")
def signup():
    data = request.form
    file = request.files.get("profile_pic")

    required = ["first_name", "last_name", "email", "password"]
    for r in required:
        if not data.get(r):
            return jsonify({"error": f"{r} is required"}), 400

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM user WHERE email=%s", (data["email"],))
        if cur.fetchone():
            conn.close()
            return jsonify({"error": "Email already registered"}), 409

        pic_path = None
        if file:
            fname = f'{int(datetime.datetime.utcnow().timestamp())}_{file.filename}'
            save_dir = os.path.join(app.static_folder, "uploads")
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, fname)
            file.save(save_path)
            pic_path = f"/static/uploads/{fname}"

        cur.execute("""
            INSERT INTO user(first_name, last_name, designation, email, password_hash, profile_pic, is_admin, is_approved)
            VALUES (%s,%s,%s,%s,%s,%s,0,0)
        """, (
            data["first_name"], data["last_name"], data.get("designation"),
            data["email"], generate_password_hash(data["password"]), pic_path
        ))
    conn.close()

    return jsonify({
        "status": "pending",
        "message": "Your account is pending admin approval."
    }), 201


# ✅ SIGN IN
@auth_bp.post("/signin")
def signin():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    u = get_user_by_email(email)
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not u["is_approved"]:
        return jsonify({"error": "Account pending approval"}), 403

    # ✅ Fix: use user_id as identity, rest as claims
    token = create_access_token(
        identity=str(u["id"]),
        additional_claims={
            "email": u["email"],
            "first_name": u["first_name"],
            "is_admin": u["is_admin"],
            "can_update_data": u["can_update_data"]
        }
    )

    print("✅ LOGIN SUCCESS — cookie about to be set for:", u["email"])
    print("🔑 JWT Token (truncated):", token[:50])

    resp = jsonify({
        "id": u["id"],
        "email": u["email"],
        "first_name": u["first_name"],
        "is_admin": u["is_admin"]
    })
    set_access_cookies(resp, token)
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Origin"] = app.config.get("FRONTEND_BASE", "http://localhost:5173")
    return resp, 200


# ✅ SIGN OUT
@auth_bp.post("/signout")
def signout():
    resp = jsonify({"message": "signed out"})
    unset_jwt_cookies(resp)
    return resp


@auth_bp.get("/me")
@jwt_required(optional=False)
def me():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, first_name, last_name, email, designation, is_admin, can_update_data, profile_pic 
            FROM user WHERE id=%s
        """, (user_id,))
        u = cur.fetchone()
    conn.close()

    return jsonify(u), 200

# ✅ FORGOT PASSWORD – Send OTP
@auth_bp.post("/forgot")
def forgot_password():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "No account found with this email"}), 404

    # Generate OTP and store it
    otp_code = create_otp(user["id"])  # ✅ use the user_id instead of email

    # Send email
    subject = "MTM Group – Password Reset OTP"
    body = f"Your OTP to reset password is: {otp_code}\n\nThis code will expire in 10 minutes."
    try:
        send_mail(email, subject, body)
    except Exception as e:
        print("⚠️ OTP email sending failed:", str(e))
        return jsonify({
            "error": "Unable to send OTP email at the moment. Please try again later."
        }), 500

    return jsonify({"message": "OTP sent to your email"}), 200


# ✅ RESET PASSWORD – Verify OTP and change password
@auth_bp.post("/reset")
def reset_password():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")

    if not all([email, otp, new_password]):
        return jsonify({"error": "All fields are required"}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ✅ Verify OTP using user_id
    if not verify_otp(user["id"], otp):
        return jsonify({"error": "Invalid or expired OTP"}), 400

    hashed_pw = generate_password_hash(new_password)

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )
    with conn.cursor() as cur:
        cur.execute("UPDATE user SET password_hash=%s WHERE email=%s", (hashed_pw, email))
    conn.close()

    # ✅ Mark OTP as used
    mark_otp_used(user["id"])

    return jsonify({"message": "Password updated successfully"}), 200
