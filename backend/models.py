"""
SecureVault Database Models
===========================
SQLite database operations for users, passwords, resources, and audit logs.

Tables:
- users: Student, Faculty, Admin accounts
- otp_codes: Multi-factor authentication
- password_vault: Student encrypted passwords
- faculty_resources: Encrypted PDFs, quiz passwords, QPs
- audit_logs: Security event tracking
- login_attempts: Rate limiting
"""

import sqlite3
from datetime import datetime, timedelta
from config import DATABASE_PATH, OTP_EXPIRY_MINUTES, MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MINUTES


def get_db_connection():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with all required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'faculty', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # OTP codes for MFA
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_used INTEGER DEFAULT 0
        )
    ''')
    
    # Student password vault (all fields encrypted)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_name_encrypted TEXT NOT NULL,
            username_encrypted TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            iv TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Faculty resources (encrypted files and passwords)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS faculty_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            faculty_id INTEGER NOT NULL,
            resource_type TEXT NOT NULL CHECK(resource_type IN ('quiz_password', 'pdf', 'question_paper')),
            subject TEXT NOT NULL,
            title TEXT NOT NULL,
            encrypted_content TEXT,
            file_path TEXT,
            signature TEXT NOT NULL,
            iv TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (faculty_id) REFERENCES users(id)
        )
    ''')
    
    # Audit logs for security tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT
        )
    ''')
    
    # Login attempts for rate limiting
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 0
        )
    ''')
    
    # WebAuthn Credentials (Passkeys)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            transports TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✓ Database initialized successfully")
    
    # Create demo accounts if they don't exist
    create_demo_accounts()


# =============================================================================
# WEBAUTHN OPERATIONS
# =============================================================================

def create_webauthn_credential(user_id, credential_id, public_key, sign_count, transports):
    """Save a new WebAuthn credential."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO webauthn_credentials 
        (user_id, credential_id, public_key, sign_count, transports)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, credential_id, public_key, sign_count, str(transports)))
    conn.commit()
    conn.close()
    return True

def get_webauthn_credentials(user_id):
    """Get all credentials for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM webauthn_credentials WHERE user_id = ?', (user_id,))
    creds = cursor.fetchall()
    conn.close()
    return [dict(c) for c in creds]

def get_credential_by_id(credential_id):
    """Get a credential by its unique ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM webauthn_credentials WHERE credential_id = ?', (credential_id,))
    cred = cursor.fetchone()
    conn.close()
    return dict(cred) if cred else None

def update_credential_counter(credential_id, sign_count):
    """Update signature counter to prevent replay attacks."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?',
        (sign_count, credential_id)
    )
    conn.commit()
    conn.close()


def create_demo_accounts():
    """Create demo accounts for testing (if they don't exist)."""
    from utils.crypto import hash_password
    
    demo_users = [
        ('admin', 'admin123', 'admin'),
        ('faculty1', 'faculty123', 'faculty'),
        ('student1', 'student123', 'student'),
    ]
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for username, password, role in demo_users:
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone() is None:
            # Hash password and create user
            password_hash, salt = hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, salt, role))
            print(f"  ✓ Demo account created: {username} / {password} ({role})")
    
    conn.commit()
    conn.close()


# =============================================================================
# USER OPERATIONS
# =============================================================================

def create_user(username, password_hash, salt, role, email=None):
    """Create a new user account."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, role))
        conn.commit()
        user_id = cursor.lastrowid
        return {'id': user_id, 'username': username, 'role': role}
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_username(username):
    """Get user by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Get user by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    """Get all users (for admin)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, role, created_at FROM users')
    users = cursor.fetchall()
    conn.close()
    return [dict(user) for user in users]


def update_user_password(username, password_hash, salt):
    """Update user's password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users SET password_hash = ?, salt = ? WHERE username = ?
    ''', (password_hash, salt, username))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success


# =============================================================================
# OTP OPERATIONS
# =============================================================================

def create_otp(username, otp_code):
    """Create a new OTP for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    expires_at = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    cursor.execute('''
        INSERT INTO otp_codes (username, otp_code, expires_at)
        VALUES (?, ?, ?)
    ''', (username, otp_code, expires_at))
    conn.commit()
    conn.close()
    return True


def verify_otp(username, otp_code):
    """Verify OTP and mark as used."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM otp_codes 
        WHERE username = ? AND otp_code = ? AND is_used = 0 AND expires_at > ?
        ORDER BY created_at DESC LIMIT 1
    ''', (username, otp_code, datetime.now()))
    otp = cursor.fetchone()
    
    if otp:
        # Mark as used
        cursor.execute('UPDATE otp_codes SET is_used = 1 WHERE id = ?', (otp['id'],))
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False


def get_latest_otp(username):
    """Get the latest unused OTP for a user (for demo display)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT otp_code, expires_at FROM otp_codes 
        WHERE username = ? AND is_used = 0 AND expires_at > ?
        ORDER BY created_at DESC LIMIT 1
    ''', (username, datetime.now()))
    otp = cursor.fetchone()
    conn.close()
    return dict(otp) if otp else None


# =============================================================================
# PASSWORD VAULT OPERATIONS (Student)
# =============================================================================

def create_password_entry(user_id, site_name_encrypted, username_encrypted, password_encrypted, iv):
    """Create a new password entry in the vault."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO password_vault (user_id, site_name_encrypted, username_encrypted, password_encrypted, iv)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, site_name_encrypted, username_encrypted, password_encrypted, iv))
    conn.commit()
    entry_id = cursor.lastrowid
    conn.close()
    return entry_id


def get_user_passwords(user_id):
    """Get all password entries for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM password_vault WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,))
    passwords = cursor.fetchall()
    conn.close()
    return [dict(p) for p in passwords]


def get_password_by_id(password_id, user_id):
    """Get a specific password entry (owned by user)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM password_vault WHERE id = ? AND user_id = ?
    ''', (password_id, user_id))
    password = cursor.fetchone()
    conn.close()
    return dict(password) if password else None


def update_password_entry(password_id, user_id, site_name_encrypted, username_encrypted, password_encrypted, iv):
    """Update a password entry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE password_vault 
        SET site_name_encrypted = ?, username_encrypted = ?, password_encrypted = ?, iv = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
    ''', (site_name_encrypted, username_encrypted, password_encrypted, iv, datetime.now(), password_id, user_id))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success


def delete_password_entry(password_id, user_id):
    """Delete a password entry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM password_vault WHERE id = ? AND user_id = ?
    ''', (password_id, user_id))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success


# =============================================================================
# FACULTY RESOURCES OPERATIONS
# =============================================================================

def create_resource(faculty_id, resource_type, subject, title, encrypted_content, file_path, signature, iv):
    """Create a new faculty resource."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO faculty_resources (faculty_id, resource_type, subject, title, encrypted_content, file_path, signature, iv)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (faculty_id, resource_type, subject, title, encrypted_content, file_path, signature, iv))
    conn.commit()
    resource_id = cursor.lastrowid
    conn.close()
    return resource_id


def get_faculty_resources(faculty_id):
    """Get all resources uploaded by a faculty member."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, u.username as faculty_name
        FROM faculty_resources r
        JOIN users u ON r.faculty_id = u.id
        WHERE r.faculty_id = ?
        ORDER BY r.created_at DESC
    ''', (faculty_id,))
    resources = cursor.fetchall()
    conn.close()
    return [dict(r) for r in resources]


def get_all_resources():
    """Get all shared resources (for students/faculty to view)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, u.username as faculty_name
        FROM faculty_resources r
        JOIN users u ON r.faculty_id = u.id
        ORDER BY r.created_at DESC
    ''')
    resources = cursor.fetchall()
    conn.close()
    return [dict(r) for r in resources]


def get_resource_by_id(resource_id):
    """Get a specific resource by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, u.username as faculty_name
        FROM faculty_resources r
        JOIN users u ON r.faculty_id = u.id
        WHERE r.id = ?
    ''', (resource_id,))
    resource = cursor.fetchone()
    conn.close()
    return dict(resource) if resource else None


def delete_resource(resource_id, faculty_id):
    """Delete a resource (only by owner)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM faculty_resources WHERE id = ? AND faculty_id = ?
    ''', (resource_id, faculty_id))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success


# =============================================================================
# AUDIT LOG OPERATIONS
# =============================================================================

def create_audit_log(user_id, username, action, resource_type=None, resource_id=None, details=None, ip_address=None):
    """Create an audit log entry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Store timestamp in ISO format for proper parsing
    timestamp = datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, user_id, username, action, resource_type, resource_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, user_id, username, action, resource_type, resource_id, details, ip_address))
    conn.commit()
    conn.close()


def get_audit_logs(limit=100):
    """Get audit logs (most recent first)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    logs = cursor.fetchall()
    conn.close()
    return [dict(log) for log in logs]


# =============================================================================
# RATE LIMITING OPERATIONS
# =============================================================================

def record_login_attempt(username, ip_address, success):
    """Record a login attempt."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_attempts (username, ip_address, success)
        VALUES (?, ?, ?)
    ''', (username, ip_address, 1 if success else 0))
    conn.commit()
    conn.close()


def is_rate_limited(username, ip_address):
    """Check if user is rate limited due to too many failed attempts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check failed attempts in the lockout window
    lockout_start = datetime.now() - timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    cursor.execute('''
        SELECT COUNT(*) as failed_count FROM login_attempts
        WHERE username = ? AND success = 0 AND attempt_time > ?
    ''', (username, lockout_start))
    
    result = cursor.fetchone()
    conn.close()
    
    return result['failed_count'] >= MAX_LOGIN_ATTEMPTS


def clear_login_attempts(username):
    """Clear login attempts after successful login."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM login_attempts WHERE username = ?', (username,))
    conn.commit()
    conn.close()


# =============================================================================
# SEED DATA
# =============================================================================

def seed_demo_users(hash_password_func):
    """Seed demo users if they don't exist."""
    demo_users = [
        ('admin', 'admin123', 'admin'),
        ('faculty1', 'faculty123', 'faculty'),
        ('student1', 'student123', 'student'),
    ]
    
    for username, password, role in demo_users:
        if not get_user_by_username(username):
            password_hash, salt = hash_password_func(password)
            create_user(username, password_hash, salt, role)
            print(f"  ✓ Created demo user: {username} ({role})")
