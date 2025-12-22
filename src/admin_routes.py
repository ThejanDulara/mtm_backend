import pymysql
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from .config import Config
from .emailer import send_mail

admin_bp = Blueprint("admin", __name__)

# ✅ Helper: ensure user is admin
def _ensure_admin():
    identity = get_jwt_identity()  # this is now user_id (string)
    claims = get_jwt()             # contains extra info like is_admin
    if not identity or not claims.get("is_admin"):
        return False
    return True


# ✅ Get all users or pending users
@admin_bp.get("/users")
@jwt_required()
def list_users():
    if not _ensure_admin():
        return jsonify({"error": "Admin access required"}), 403

    status = request.args.get("status")

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as cur:
        if status == "pending":
            cur.execute("SELECT * FROM user WHERE is_approved=0")
        else:
            cur.execute("SELECT * FROM user")
        users = cur.fetchall()
    conn.close()
    return jsonify(users), 200


# ✅ Approve a user
@admin_bp.post("/approve")
@jwt_required()
def approve_user():
    if not _ensure_admin():
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

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
        cur.execute("UPDATE user SET is_approved=1 WHERE id=%s", (user_id,))
        cur.execute("SELECT email, first_name FROM user WHERE id=%s", (user_id,))
        user = cur.fetchone()
    conn.close()

    if user:
        html = f"""
        <p>Hello {user['first_name']},</p>
        <p>Your account has been approved! 🎉</p>
        <p>You can now log in and access the MTM Group Portal by clicking the link below:</p>
        <p><a href="https://www.mtmgroup.agency/signin" target="_blank">Click here to access the portal</a></p>
        <p>Welcome aboard,<br>Team MTM</p>
        """
        try:
            send_mail(
                user["email"],
                "Account Approved - MTM Group Portal",
                html
            )
        except Exception as e:
            print("⚠️ Email sending failed:", str(e))

    # ✅ THIS LINE FIXES EVERYTHING
    return jsonify({"message": "User approved"}), 200



# ✅ Reject a user (remove + send rejection email)
@admin_bp.post("/reject")
@jwt_required()
def reject_user():
    if not _ensure_admin():
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

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
        # Fetch user info before deletion
        cur.execute("SELECT email, first_name FROM user WHERE id=%s", (user_id,))
        user = cur.fetchone()

        if user:
            # Send rejection email
            html = f"""
                <p>Dear {user['first_name']},</p>
                <p>We appreciate your interest in joining the <b>ThirdShift Portal</b>.</p>
                <p>However, your account registration request has been <b>rejected</b> by the administrator.</p>
                <p>If you believe this was an error or would like to reapply, please contact our admin team.</p>
                <p><a href="https://www.mtmgroup.agency" target="_blank">Click here to contact admin</a></p>
                <p>— MTM Group — </p>
            """
            try:
                send_mail(
                    user["email"],
                    "Account Rejected - MTM Group Portal",
                    html
                )
            except Exception as e:
                print("⚠️ Email sending failed (reject):", e)

            # Delete user record
            cur.execute("DELETE FROM user WHERE id=%s", (user_id,))
            conn.close()
            return jsonify({"message": "User rejected, removed, and notified"}), 200
        else:
            conn.close()
            return jsonify({"error": "User not found"}), 404

# ✅ Delete a user (and notify by email)
@admin_bp.delete("/users/<int:user_id>")
@jwt_required()
def delete_user(user_id):
    if not _ensure_admin():
        return jsonify({"error": "Admin access required"}), 403

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

    # Fetch user details before deletion (for email)
    with conn.cursor() as cur:
        cur.execute("SELECT email, first_name FROM user WHERE id=%s", (user_id,))
        user = cur.fetchone()

        # If user exists, delete them
        if user:
            cur.execute("DELETE FROM user WHERE id=%s", (user_id,))
            conn.close()

            # Send email notification
            html = f"""
                <p>Dear {user['first_name']},</p>
                <p>Your account on the <b>MTM Group Portal</b> has been deleted by an administrator.</p>
                <p>If you believe this was a mistake, please contact the admin team.</p>
                <p><a href="https://www.mtmgroup.agency" target="_blank">Click here to contact admin</a></p>
                <p>— MTM Group — </p>
            """
            try:
                send_mail(
                    user["email"],
                    "Account Deleted - MTM Group Portal",
                    html
                )
            except Exception as e:
                print("⚠️ Email sending failed (delete):", e)

            return jsonify({"message": "User deleted and notified"}), 200
        else:
            conn.close()
            return jsonify({"error": "User not found"}), 404
