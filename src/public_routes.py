from flask import Blueprint, request, jsonify
import pymysql
from .config import Config
from .emailer import send_mail

public_bp = Blueprint("public", __name__)

@public_bp.post("/contact-admin")
def contact_admin():
    data = request.get_json()
    email = data.get("email")
    phone = data.get("phone", "")
    message = data.get("message")

    if not email or not message:
        return jsonify({"error": "email and message are required"}), 400

    # Fetch all admin emails
    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )

    with conn.cursor() as cur:
        cur.execute("SELECT email, first_name FROM user WHERE is_admin=1 AND is_approved=1")
        admins = cur.fetchall()
    conn.close()

    if not admins:
        return jsonify({"error": "No admins available"}), 404

    # Compose email content
    html = f"""
    <h3>New Contact Message from MTM Group Portal</h3>
    <p><b>From:</b> {email}</p>
    <p><b>Phone:</b> {phone or 'N/A'}</p>
    <p><b>Message:</b></p>
    <blockquote>{message}</blockquote>
    """

    # Send to all admins
    for a in admins:
        send_mail(a["email"], "New Contact Message - MTM Group Portal", html)

    return jsonify({"message": "Message sent to admin(s)"}), 200
