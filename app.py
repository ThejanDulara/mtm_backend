from flask import Flask, request
from flask_jwt_extended import JWTManager
from src.db import init_db
from src.auth_routes import auth_bp
from src.user_routes import user_bp
from src.admin_routes import admin_bp
from src.config import Config
from src.public_routes import public_bp
import os

def create_app():
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.from_object(Config)

    # --- JWT Setup ---
    jwt = JWTManager(app)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_COOKIE_DOMAIN"] = "mtmbackend-production.up.railway.app"  # ✅ share across all subdomains
    app.config["JWT_COOKIE_SECURE"] = True  # ✅ always true in production
    app.config["JWT_COOKIE_SAMESITE"] = "None"  # ✅ required for cross-domain cookie
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False
    app.config["JWT_ACCESS_COOKIE_PATH"] = "/"

    # --- JWT Error Handlers (for debugging 422 etc.) ---
    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        print("❌ Unauthorized or missing JWT")
        return {"error": "Missing or invalid JWT"}, 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        print("❌ Invalid JWT token:", error)
        return {"error": "Invalid token"}, 422

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        print("⚠️ Token expired for user:", jwt_payload)
        return {"error": "Token expired"}, 401

    # --- ✅ CORS Setup (Allow cookies from all TSM subdomains) ---
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        allowed_origins = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://www.mtmgroup.agency",
            "https://copt.mtmgroup.agency",
            "https://opt.mtmgroup.agency",
            "https://tmrp.mtmgroup.agency",
            "https://mo.mtmgroup.agency",
            "https://mmmr.mtmgroup.agency",
            "https://cts.mtmgroup.agency",
            "https://pbi.mtmgroup.agency",
            "https://pm.mtmgroup.agency",
            "https://fe.mtmgroup.agency",
            "https://bp.mtmgroup.agency",
        ]
        # ✅ Dynamically handle future subdomains
        if origin and origin.endswith(".mtmgroup.agency"):
            response.headers["Access-Control-Allow-Origin"] = origin
        elif origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin

        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response

    # --- Initialize DB + Routes ---
    init_db(app)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(user_bp, url_prefix="/api/user")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(public_bp, url_prefix="/api/public")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
