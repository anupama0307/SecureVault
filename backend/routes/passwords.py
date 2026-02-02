"""
SecureVault Student Password Routes
====================================
Handles student password vault operations.

Endpoints:
- GET /passwords - List all passwords
- POST /passwords - Add new password
- GET /passwords/<id> - Get single password
- PUT /passwords/<id> - Update password
- DELETE /passwords/<id> - Delete password
- POST /passwords/generate - Autogenerate secure password

Security:
- All passwords are encrypted with AES-256 before storage
- Only the owner can access their passwords
- Role restricted to 'student' only
"""

from flask import Blueprint, request, jsonify, g
from models import (
    create_password_entry, get_user_passwords, get_password_by_id,
    update_password_entry, delete_password_entry, create_audit_log
)
from utils.crypto import aes_encrypt, aes_decrypt, generate_secure_password
from utils.access_control import require_auth, require_role, get_client_ip

passwords_bp = Blueprint('passwords', __name__, url_prefix='/passwords')


# =============================================================================
# LIST ALL PASSWORDS
# =============================================================================

@passwords_bp.route('', methods=['GET'])
@require_auth
@require_role('student')
def list_passwords():
    """
    Get all password entries for the authenticated student.
    Passwords are decrypted before returning.
    """
    user_id = g.user['user_id']
    
    # Get all encrypted passwords
    encrypted_passwords = get_user_passwords(user_id)
    
    # Decrypt each password entry
    passwords = []
    for entry in encrypted_passwords:
        try:
            passwords.append({
                'id': entry['id'],
                'site_name': aes_decrypt(entry['site_name_encrypted'], entry['iv']),
                'username': aes_decrypt(entry['username_encrypted'], entry['iv']),
                'password': aes_decrypt(entry['password_encrypted'], entry['iv']),
                'created_at': entry['created_at'],
                'updated_at': entry['updated_at']
            })
        except Exception as e:
            # If decryption fails, skip this entry
            print(f"Failed to decrypt password entry {entry['id']}: {e}")
    
    return jsonify({
        'success': True,
        'count': len(passwords),
        'passwords': passwords
    })


# =============================================================================
# ADD NEW PASSWORD
# =============================================================================

@passwords_bp.route('', methods=['POST'])
@require_auth
@require_role('student')
def add_password():
    """
    Add a new password entry to the vault.
    
    Request Body:
        - site_name (str): Name of site/app
        - username (str): Username for the site
        - password (str): Password to store
    """
    data = request.get_json()
    
    if not data or not all(k in data for k in ['site_name', 'username', 'password']):
        return jsonify({'error': 'Site name, username, and password are required'}), 400
    
    user_id = g.user['user_id']
    site_name = data['site_name'].strip()
    username = data['username'].strip()
    password = data['password']
    
    # Encrypt all fields with the same IV for this entry
    site_name_encrypted, iv = aes_encrypt(site_name)
    username_encrypted, _ = aes_encrypt(username)
    # Re-encrypt with the generated IV to maintain consistency
    # Actually, we need to use the same IV for all fields
    from utils.crypto import AES_KEY
    import os, base64
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Generate a single IV for all fields
    iv_bytes = os.urandom(16)
    iv_b64 = base64.b64encode(iv_bytes).decode('utf-8')
    
    def encrypt_with_iv(plaintext, iv_bytes):
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')
    
    site_name_encrypted = encrypt_with_iv(site_name, iv_bytes)
    username_encrypted = encrypt_with_iv(username, iv_bytes)
    password_encrypted = encrypt_with_iv(password, iv_bytes)
    
    # Create entry
    entry_id = create_password_entry(
        user_id, site_name_encrypted, username_encrypted, password_encrypted, iv_b64
    )
    
    # Audit log
    create_audit_log(
        user_id=user_id,
        username=g.user['username'],
        action='PASSWORD_CREATED',
        resource_type='password',
        resource_id=entry_id,
        details=f'Password added for {site_name}',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Password added successfully',
        'id': entry_id
    }), 201


# =============================================================================
# GET SINGLE PASSWORD
# =============================================================================

@passwords_bp.route('/<int:password_id>', methods=['GET'])
@require_auth
@require_role('student')
def get_password(password_id):
    """Get a single password entry by ID."""
    user_id = g.user['user_id']
    
    entry = get_password_by_id(password_id, user_id)
    
    if not entry:
        return jsonify({'error': 'Password not found'}), 404
    
    # Decrypt
    try:
        password = {
            'id': entry['id'],
            'site_name': aes_decrypt(entry['site_name_encrypted'], entry['iv']),
            'username': aes_decrypt(entry['username_encrypted'], entry['iv']),
            'password': aes_decrypt(entry['password_encrypted'], entry['iv']),
            'created_at': entry['created_at'],
            'updated_at': entry['updated_at']
        }
        
        return jsonify({
            'success': True,
            'password': password
        })
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt password'}), 500


# =============================================================================
# UPDATE PASSWORD
# =============================================================================

@passwords_bp.route('/<int:password_id>', methods=['PUT'])
@require_auth
@require_role('student')
def update_password(password_id):
    """
    Update a password entry.
    
    Request Body:
        - site_name (str): Name of site/app
        - username (str): Username for the site
        - password (str): Password to store
    """
    data = request.get_json()
    
    if not data or not all(k in data for k in ['site_name', 'username', 'password']):
        return jsonify({'error': 'Site name, username, and password are required'}), 400
    
    user_id = g.user['user_id']
    
    # Check if entry exists and belongs to user
    existing = get_password_by_id(password_id, user_id)
    if not existing:
        return jsonify({'error': 'Password not found'}), 404
    
    site_name = data['site_name'].strip()
    username = data['username'].strip()
    password = data['password']
    
    # Encrypt with new IV
    from utils.crypto import AES_KEY
    import os, base64
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    iv_bytes = os.urandom(16)
    iv_b64 = base64.b64encode(iv_bytes).decode('utf-8')
    
    def encrypt_with_iv(plaintext, iv_bytes):
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode('utf-8')
    
    site_name_encrypted = encrypt_with_iv(site_name, iv_bytes)
    username_encrypted = encrypt_with_iv(username, iv_bytes)
    password_encrypted = encrypt_with_iv(password, iv_bytes)
    
    # Update entry
    success = update_password_entry(
        password_id, user_id, site_name_encrypted, username_encrypted, password_encrypted, iv_b64
    )
    
    if not success:
        return jsonify({'error': 'Failed to update password'}), 500
    
    # Audit log
    create_audit_log(
        user_id=user_id,
        username=g.user['username'],
        action='PASSWORD_UPDATED',
        resource_type='password',
        resource_id=password_id,
        details=f'Password updated for {site_name}',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Password updated successfully'
    })


# =============================================================================
# DELETE PASSWORD
# =============================================================================

@passwords_bp.route('/<int:password_id>', methods=['DELETE'])
@require_auth
@require_role('student')
def remove_password(password_id):
    """Delete a password entry."""
    user_id = g.user['user_id']
    
    # Check if entry exists
    existing = get_password_by_id(password_id, user_id)
    if not existing:
        return jsonify({'error': 'Password not found'}), 404
    
    # Get site name for audit log before deletion
    try:
        site_name = aes_decrypt(existing['site_name_encrypted'], existing['iv'])
    except:
        site_name = 'Unknown'
    
    # Delete
    success = delete_password_entry(password_id, user_id)
    
    if not success:
        return jsonify({'error': 'Failed to delete password'}), 500
    
    # Audit log
    create_audit_log(
        user_id=user_id,
        username=g.user['username'],
        action='PASSWORD_DELETED',
        resource_type='password',
        resource_id=password_id,
        details=f'Password deleted for {site_name}',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Password deleted successfully'
    })


# =============================================================================
# GENERATE SECURE PASSWORD
# =============================================================================

@passwords_bp.route('/generate', methods=['POST'])
@require_auth
@require_role('student')
def generate_password():
    """
    Generate a cryptographically secure password.
    
    Request Body (optional):
        - length (int): Password length (default 16, max 32)
    """
    data = request.get_json() or {}
    length = min(max(data.get('length', 16), 8), 32)  # Between 8 and 32
    
    password = generate_secure_password(length)
    
    return jsonify({
        'success': True,
        'password': password,
        'length': len(password)
    })
