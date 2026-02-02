"""
SecureVault Configuration
=========================
Keys, JWT settings, and Access Control Matrix for the application.

Security Concepts:
- RSA-2048: Asymmetric encryption for digital signatures
- AES-256: Symmetric encryption for data protection
- PBKDF2: Password hashing with salt
- JWT: Stateless authentication tokens

NIST SP 800-63-2 Compliance:
- Strong password policy enforcement
- Multi-factor authentication (OTP)
- Rate limiting on login attempts
"""

import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load environment variables from .env file
load_dotenv()

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'secure_storage.db')
UPLOADS_PATH = os.path.join(os.path.dirname(__file__), 'uploads')
KEYS_PATH = os.path.join(os.path.dirname(__file__), 'keys')

# Create directories if they don't exist
os.makedirs(UPLOADS_PATH, exist_ok=True)
os.makedirs(KEYS_PATH, exist_ok=True)

# =============================================================================
# EMAIL / SMTP CONFIGURATION
# =============================================================================
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD') # Use Google App Password
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587

# =============================================================================
# KEY MANAGEMENT
# =============================================================================
RSA_PRIVATE_KEY_PATH = os.path.join(KEYS_PATH, 'private_key.pem')
RSA_PUBLIC_KEY_PATH = os.path.join(KEYS_PATH, 'public_key.pem')
AES_KEY_PATH = os.path.join(KEYS_PATH, 'aes_key.bin')


def load_or_generate_rsa_keys():
    """
    Load existing RSA keys or generate new ones.
    Keys are persisted to maintain signature validity across restarts.
    
    Returns:
        tuple: (private_key, public_key)
    """
    if os.path.exists(RSA_PRIVATE_KEY_PATH) and os.path.exists(RSA_PUBLIC_KEY_PATH):
        # Load existing keys
        with open(RSA_PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(RSA_PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        print("✓ Loaded existing RSA keys from disk")
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save keys to disk
        with open(RSA_PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(RSA_PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("✓ Generated new RSA-2048 key pair and saved to disk")
    
    return private_key, public_key


def load_or_generate_aes_key():
    """
    Load existing AES key or generate a new one.
    256-bit key for AES-256 encryption.
    
    Returns:
        bytes: 32-byte AES key
    """
    if os.path.exists(AES_KEY_PATH):
        with open(AES_KEY_PATH, 'rb') as f:
            aes_key = f.read()
        print("✓ Loaded existing AES-256 key from disk")
    else:
        aes_key = os.urandom(32)  # 256 bits
        with open(AES_KEY_PATH, 'wb') as f:
            f.write(aes_key)
        print("✓ Generated new AES-256 key and saved to disk")
    
    return aes_key


# Initialize keys
RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = load_or_generate_rsa_keys()
AES_KEY = load_or_generate_aes_key()

# =============================================================================
# JWT CONFIGURATION
# =============================================================================
# Priority given to .env SECRET_KEY
JWT_SECRET = os.getenv('SECRET_KEY', 'securevault-jwt-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24

# =============================================================================
# OTP CONFIGURATION
# =============================================================================
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5

# =============================================================================
# WEBAUTHN CONFIGURATION
# =============================================================================
RP_ID = "localhost"
RP_NAME = "SecureVault"
ORIGIN = "http://localhost:3000"

# =============================================================================
# PASSWORD POLICY (NIST SP 800-63-2)
# =============================================================================
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_SPECIAL = True
PBKDF2_ITERATIONS = 100000  # High iteration count for security

# =============================================================================
# RATE LIMITING
# =============================================================================
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# =============================================================================
# ACCESS CONTROL MATRIX (ACM)
# =============================================================================
ACCESS_CONTROL_MATRIX = {
    'student': {
        'passwords': ['create', 'read', 'update', 'delete'],
        'resources': ['read'],
        'users': [],
        'audit_logs': [],
    },
    'faculty': {
        'passwords': [],
        'resources': ['create', 'read', 'update', 'delete'],
        'users': [],
        'audit_logs': [],
    },
    'admin': {
        'passwords': [],
        'resources': ['read'],
        'users': ['read'],
        'audit_logs': ['read'],
    }
}

# =============================================================================
# SECURITY REFERENCE DOCUMENTATION
# =============================================================================
SECURITY_CONCEPTS = {
    'encoding_vs_encryption': {
        'Base64': 'Format conversion (NOT security) - anyone can decode',
        'AES-256': 'Symmetric encryption - data unreadable without key'
    },
    'hashing_vs_encryption': {
        'PBKDF2': 'One-way hash with salt, used for passwords',
        'AES': 'Two-way encryption, used for stored data'
    },
    'digital_signatures': {
        'RSA-PSS': 'Proves authenticity + integrity',
        'Purpose': 'Any tampering invalidates the signature'
    }
}

COUNTERMEASURES = [
    'Strong password policy enforcement (NIST SP 800-63-2)',
    'Multi-factor authentication (Password + OTP)',
    'Rate limiting on failed login attempts',
    'Secure session management with JWT',
    'AES-256-CBC encryption for sensitive data',
    'RSA-PSS digital signatures for integrity verification',
    'PBKDF2 with 100,000 iterations for password hashing',
    'Role-based access control (RBAC) with ACM'
]