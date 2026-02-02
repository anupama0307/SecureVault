"""
SecureVault Cryptographic Utilities
====================================
Implements all security primitives for the application.

Security Concepts:
1. Password Hashing (PBKDF2-SHA256)
   - One-way function, cannot be reversed
   - Salt prevents rainbow table attacks
   - 100,000 iterations for computational cost

2. Symmetric Encryption (AES-256-CBC)
   - Used for encrypting stored passwords and files
   - CBC mode with random IV for each encryption
   - Same key encrypts and decrypts

3. Digital Signatures (RSA-PSS)
   - Proves authenticity and integrity
   - Private key signs, public key verifies
   - Any modification invalidates signature

4. Encoding (Base64)
   - NOT encryption - just format conversion
   - Used for safe transmission of binary data
"""

import os
import base64
import secrets
import string
import hashlib
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from config import AES_KEY, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, PBKDF2_ITERATIONS


# =============================================================================
# PASSWORD HASHING (PBKDF2-SHA256)
# =============================================================================

def hash_password(password):
    """
    Hash a password using PBKDF2-SHA256 with a random salt.
    
    Args:
        password (str): Plain text password
        
    Returns:
        tuple: (password_hash, salt) both as base64 strings
    """
    # Generate a random 16-byte salt
    salt = os.urandom(16)
    
    # Hash the password with PBKDF2
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    
    # Return as base64 encoded strings for storage
    return base64.b64encode(password_hash).decode('utf-8'), base64.b64encode(salt).decode('utf-8')


def verify_password(password, stored_hash, stored_salt):
    """
    Verify a password against stored hash and salt.
    
    Args:
        password (str): Plain text password to verify
        stored_hash (str): Base64 encoded stored hash
        stored_salt (str): Base64 encoded stored salt
        
    Returns:
        bool: True if password matches
    """
    # Decode the stored values
    salt = base64.b64decode(stored_salt)
    expected_hash = base64.b64decode(stored_hash)
    
    # Hash the provided password with the same salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(password_hash, expected_hash)


# =============================================================================
# AES-256-CBC ENCRYPTION
# =============================================================================

def aes_encrypt(plaintext):
    """
    Encrypt data using AES-256-CBC.
    
    Args:
        plaintext (str): Data to encrypt
        
    Returns:
        tuple: (ciphertext_b64, iv_b64) both as base64 strings
    """
    # Generate random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return as base64 encoded strings
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')


def aes_decrypt(ciphertext_b64, iv_b64):
    """
    Decrypt data using AES-256-CBC.
    
    Args:
        ciphertext_b64 (str): Base64 encoded ciphertext
        iv_b64 (str): Base64 encoded IV
        
    Returns:
        str: Decrypted plaintext
    """
    # Decode from base64
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext.decode('utf-8')


def encrypt_file(file_data):
    """
    Encrypt file data using AES-256-CBC.
    
    Args:
        file_data (bytes): Raw file bytes
        
    Returns:
        tuple: (encrypted_data_b64, iv_b64)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the file data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')


def decrypt_file(ciphertext_b64, iv_b64):
    """
    Decrypt file data using AES-256-CBC.
    
    Args:
        ciphertext_b64 (str): Base64 encoded encrypted file
        iv_b64 (str): Base64 encoded IV
        
    Returns:
        bytes: Decrypted file data
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    file_data = unpadder.update(padded_data) + unpadder.finalize()
    
    return file_data


# =============================================================================
# RSA-PSS DIGITAL SIGNATURES
# =============================================================================

def sign_data(data):
    """
    Sign data using RSA-PSS.
    
    Args:
        data (str or bytes): Data to sign
        
    Returns:
        str: Base64 encoded signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = RSA_PRIVATE_KEY.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(data, signature_b64):
    """
    Verify a digital signature using RSA-PSS.
    
    Args:
        data (str or bytes): Original data
        signature_b64 (str): Base64 encoded signature
        
    Returns:
        bool: True if signature is valid
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        signature = base64.b64decode(signature_b64)
        RSA_PUBLIC_KEY.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# =============================================================================
# SECURE TOKEN CREATION (Combined format)
# =============================================================================

def create_secure_token(payload):
    """
    Create a secure token with encryption and signature.
    Format: Base64( IV[16] + Signature[256] + Ciphertext )
    
    Args:
        payload (str): Data to secure
        
    Returns:
        str: Complete secure token
    """
    # Encrypt the payload
    ciphertext_b64, iv_b64 = aes_encrypt(payload)
    
    # Sign the ciphertext
    signature_b64 = sign_data(ciphertext_b64)
    
    # Combine: IV + Signature + Ciphertext (all in base64, joined by |)
    token_parts = f"{iv_b64}|{signature_b64}|{ciphertext_b64}"
    
    # Encode the combined token
    return base64.b64encode(token_parts.encode('utf-8')).decode('utf-8')


def validate_secure_token(token):
    """
    Validate and decrypt a secure token.
    
    Args:
        token (str): Complete secure token
        
    Returns:
        tuple: (is_valid, payload or error_message)
    """
    try:
        # Decode the token
        token_parts = base64.b64decode(token).decode('utf-8')
        iv_b64, signature_b64, ciphertext_b64 = token_parts.split('|')
        
        # Verify signature first
        if not verify_signature(ciphertext_b64, signature_b64):
            return False, "Signature verification failed - data may have been tampered"
        
        # Decrypt the payload
        payload = aes_decrypt(ciphertext_b64, iv_b64)
        
        return True, payload
    except Exception as e:
        return False, f"Token validation failed: {str(e)}"


# =============================================================================
# SECURE PASSWORD GENERATION
# =============================================================================

def generate_secure_password(length=16):
    """
    Generate a cryptographically secure random password.
    
    Args:
        length (int): Password length (default 16)
        
    Returns:
        str: Generated password
    """
    # Character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # Ensure at least one of each required type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = lowercase + uppercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle to randomize position of required characters
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)


# =============================================================================
# PASSWORD POLICY VALIDATION
# =============================================================================

def validate_password_policy(password):
    """
    Validate password against security policy.
    
    Args:
        password (str): Password to validate
        
    Returns:
        tuple: (is_valid, list of errors)
    """
    errors = []
    
    if len(password) < 8:
        errors.append("At least 8 characters")
    
    if not any(c.isupper() for c in password):
        errors.append("At least one uppercase letter (A-Z)")
    
    if not any(c.islower() for c in password):
        errors.append("At least one lowercase letter (a-z)")
    
    if not any(c in "!@#$%^&*" for c in password):
        errors.append("At least one special character (!@#$%^&*)")
    
    return len(errors) == 0, errors
