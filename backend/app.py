"""
SecureVault - Academic Password & Document Management System
=============================================================

A comprehensive demonstration of cybersecurity concepts including:
- Encryption (AES-256-CBC)
- Digital Signatures (RSA-PSS)
- Multi-Factor Authentication (OTP)
- Role-Based Access Control (RBAC)
- Password Hashing (PBKDF2-SHA256)
- Encoding (Base64)

Course: 23CSE313 - Foundations of Cyber Security
Lab Evaluation 1

Usage:
    python app.py
    
Server runs on http://127.0.0.1:5000

Demo Accounts:
    admin / admin123 (Administrator)
    faculty1 / faculty123 (Faculty)
    student1 / student123 (Student)
"""

from flask import Flask, jsonify
from flask_cors import CORS
from models import init_db, seed_demo_users
from utils.crypto import hash_password
from routes.auth import auth_bp
from routes.passwords import passwords_bp
from routes.resources import resources_bp
from routes.admin import admin_bp

# =============================================================================
# APP INITIALIZATION
# =============================================================================

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Enable CORS for frontend
    CORS(app, resources={
        r"/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(admin_bp)
    
    # Root endpoint
    @app.route('/')
    def index():
        return jsonify({
            'name': 'SecureVault API',
            'version': '1.0.0',
            'description': 'Academic Password & Document Management System',
            'security_features': [
                'AES-256-CBC Encryption',
                'RSA-PSS Digital Signatures',
                'PBKDF2-SHA256 Password Hashing',
                'JWT Authentication',
                'Multi-Factor Authentication (OTP)',
                'Role-Based Access Control'
            ],
            'endpoints': {
                'auth': '/auth/*',
                'passwords': '/passwords/*',
                'resources': '/resources/*',
                'admin': '/admin/*'
            }
        })
    
    # Health check
    @app.route('/health')
    def health():
        return jsonify({'status': 'healthy'})
    
    return app


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🔐 SecureVault - Academic Password Manager")
    print("=" * 60)
    print("Course: 23CSE313 - Foundations of Cyber Security")
    print("=" * 60 + "\n")
    
    # Initialize database
    print("📦 Initializing database...")
    init_db()
    
    # Seed demo users
    print("\n👤 Seeding demo users...")
    seed_demo_users(hash_password)
    
    # Create app
    app = create_app()
    
    print("\n" + "=" * 60)
    print("🚀 Server starting on http://127.0.0.1:5000")
    print("=" * 60)
    print("\n📋 Demo Accounts:")
    print("   admin    / admin123    (Administrator)")
    print("   faculty1 / faculty123  (Faculty)")
    print("   student1 / student123  (Student)")
    print("\n📡 API Endpoints:")
    print("   POST /auth/register      - Create account")
    print("   POST /auth/login         - Login (sends OTP)")
    print("   POST /auth/verify-otp    - Complete MFA")
    print("   GET  /passwords          - Student password vault")
    print("   POST /resources/*        - Faculty uploads")
    print("   GET  /admin/users        - View all users")
    print("   GET  /admin/audit-logs   - Security logs")
    print("=" * 60 + "\n")
    
    # Run server
    app.run(debug=True, port=5000)
