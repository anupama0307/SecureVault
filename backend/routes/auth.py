import json
from flask import Blueprint, request, jsonify, g, Response
from models import (
    create_user, get_user_by_username, update_user_password,
    create_otp, verify_otp, create_audit_log,
    record_login_attempt, is_rate_limited, clear_login_attempts
)
from utils.crypto import hash_password, verify_password, validate_password_policy
from utils.access_control import create_jwt_token, require_auth, get_client_ip
from utils.otp import generate_otp, send_otp_via_email, format_otp_response

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# =============================================================================
# REGISTRATION
# =============================================================================

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user account with email validation."""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'error': 'Username, password, and email are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    role = data.get('role', 'student').lower()
    email = data.get('email').strip()
    
    if role not in ['student', 'faculty']:
        return jsonify({'error': 'Role must be student or faculty'}), 400
    
    if get_user_by_username(username):
        return jsonify({'error': 'Username already exists'}), 409
    
    is_valid, errors = validate_password_policy(password)
    if not is_valid:
        return jsonify({
            'error': 'Password does not meet requirements',
            'requirements': errors
        }), 400
    
    password_hash, salt = hash_password(password)
    user = create_user(username, password_hash, salt, role, email)
    
    if not user:
        return jsonify({'error': 'Failed to create user'}), 500
    
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='USER_REGISTERED',
        details=f'New {role} account created for {email}',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': f'Account created successfully as {role}',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }), 201


# =============================================================================
# LOGIN (Step 1 - Password Verification & Email OTP)
# =============================================================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """Step 1: Verify password and send OTP to user's registered email."""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username'].strip()
    password = data['password']
    ip_address = get_client_ip()
    
    if is_rate_limited(username, ip_address):
        return jsonify({
            'error': 'Too many failed login attempts',
            'message': 'Please try again in 15 minutes'
        }), 429
    
    user = get_user_by_username(username)
    
    if not user or not verify_password(password, user['password_hash'], user['salt']):
        record_login_attempt(username, ip_address, False)
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Password correct - generate OTP
    otp = generate_otp()
    create_otp(username, otp)
    
    # Send OTP to the email stored in the database
    email_sent = send_otp_via_email(username, user.get('email'), otp)
    
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='LOGIN_PASSWORD_OK',
        details='Password verified, Email OTP sent',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'Password verified. Please check your email for the OTP.',
        'requires_otp': True,
        **format_otp_response(email_sent)
    })


# =============================================================================
# VERIFY OTP (Step 2 - Complete MFA)
# =============================================================================

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    """Step 2: Verify OTP and issue JWT."""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('otp'):
        return jsonify({'error': 'Username and OTP are required'}), 400
    
    username = data['username'].strip()
    otp_code = data['otp'].strip()
    ip_address = get_client_ip()
    
    if not verify_otp(username, otp_code):
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    user = get_user_by_username(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    clear_login_attempts(username)
    token = create_jwt_token(user['id'], user['username'], user['role'])
    
    create_audit_log(
        user_id=user['id'],
        username=username,
        action='LOGIN_SUCCESS',
        details='MFA completed via Email OTP',
        ip_address=ip_address
    )
    
    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    })


# =============================================================================
# FORGOT PASSWORD
# =============================================================================

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset via Email OTP."""
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({'error': 'Username is required'}), 400
    
    username = data['username'].strip()
    user = get_user_by_username(username)
    
    if user:
        otp = generate_otp()
        create_otp(username, otp)
        send_otp_via_email(username, user.get('email'), otp)
        
        create_audit_log(
            user_id=user['id'],
            username=username,
            action='PASSWORD_RESET_REQUESTED',
            details='Reset OTP sent to email',
            ip_address=get_client_ip()
        )
    
    return jsonify({
        'success': True,
        'message': 'If the account exists, a reset code has been sent to the registered email.'
    })


# =============================================================================
# RESET PASSWORD
# =============================================================================

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with Email OTP verification."""
    data = request.get_json()
    if not data or not all(k in data for k in ['username', 'otp', 'new_password']):
        return jsonify({'error': 'Username, OTP, and new password are required'}), 400
    
    username = data['username'].strip()
    otp_code = data['otp'].strip()
    new_password = data['new_password']
    
    if not verify_otp(username, otp_code):
        return jsonify({'error': 'Invalid or expired OTP'}), 401
    
    is_valid, errors = validate_password_policy(new_password)
    if not is_valid:
        return jsonify({'error': 'Password policy violation', 'requirements': errors}), 400
    
    password_hash, salt = hash_password(new_password)
    if update_user_password(username, password_hash, salt):
        user = get_user_by_username(username)
        create_audit_log(
            user_id=user['id'] if user else None,
            username=username,
            action='PASSWORD_RESET_SUCCESS',
            details='Password updated via Email verification',
            ip_address=get_client_ip()
        )
        return jsonify({'success': True, 'message': 'Password reset successfully!'})
    
    return jsonify({'error': 'Failed to update password'}), 500



@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    return jsonify({
        'user': {
            'id': g.user['user_id'],
            'username': g.user['username'],
            'role': g.user['role']
        }
    })


# =============================================================================
# WEBAUTHN ROUTES
# =============================================================================

from utils.webauthn_utils import (
    generate_reg_options, verify_reg_response,
    generate_auth_options, verify_auth_response,
    options_to_json
)
from models import (
    create_webauthn_credential, get_webauthn_credentials,
    get_credential_by_id, update_credential_counter, get_user_by_id
)

# Store challenges temporarily (in production use Redis/Database)
CHALLENGE_STORE = {}

@auth_bp.route('/webauthn/register/options', methods=['POST'])
@require_auth
def webauthn_register_options():
    """Step 1: Generate registration options."""
    user = get_user_by_id(g.user['user_id'])
    credentials = get_webauthn_credentials(user['id'])
    
    options = generate_reg_options(user, credentials)
    
    # Store challenge
    CHALLENGE_STORE[f"reg_{user['id']}"] = options.challenge
    
    # Parse JSON string back to dict for jsonify (needed for CORS headers)
    return jsonify(json.loads(options_to_json(options)))

@auth_bp.route('/webauthn/register/verify', methods=['POST'])
@require_auth
def webauthn_register_verify():
    """Step 2: Verify and save new credential."""
    user_id = g.user['user_id']
    challenge = CHALLENGE_STORE.get(f"reg_{user_id}")
    
    if not challenge:
        return jsonify({'error': 'Challenge expired or invalid'}), 400
        
    data = request.get_json()
    
    try:
        result = verify_reg_response(data, challenge)
        
        if result['verified']:
            create_webauthn_credential(
                user_id=user_id,
                credential_id=result['credential_id'],
                public_key=result['credential_public_key'],
                sign_count=result['sign_count'],
                transports=data.get('response', {}).get('transports', [])
            )
            del CHALLENGE_STORE[f"reg_{user_id}"]
            return jsonify({'success': True, 'message': 'Passkey registered successfully!'})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400
        
    return jsonify({'error': 'Verification failed'}), 400


@auth_bp.route('/webauthn/login/options', methods=['POST'])
def webauthn_login_options():
    """Step 1: Generate login options."""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
        
    user = get_user_by_username(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    credentials = get_webauthn_credentials(user['id'])
    if not credentials:
        return jsonify({'error': 'No passkeys found for this user'}), 404
        
    options = generate_auth_options(credentials)
    
    # Store challenge (keyed by username for simplicity in this demo)
    CHALLENGE_STORE[f"auth_{username}"] = options.challenge
    
    return jsonify(json.loads(options_to_json(options)))


@auth_bp.route('/webauthn/login/verify', methods=['POST'])
def webauthn_login_verify():
    """Step 2: Verify login signature."""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
        
    challenge = CHALLENGE_STORE.get(f"auth_{username}")
    if not challenge:
        return jsonify({'error': 'Challenge expired'}), 400
        
    user = get_user_by_username(username)
    credential_id = data.get('id')
    stored_cred = get_credential_by_id(credential_id)
    
    if not stored_cred:
        return jsonify({'error': 'Credential not found'}), 404
        
    try:
        result = verify_auth_response(
            data, 
            challenge, 
            stored_cred, 
            stored_cred['sign_count']
        )
        
        if result['verified']:
            update_credential_counter(stored_cred['credential_id'], result['sign_count'])
            del CHALLENGE_STORE[f"auth_{username}"]
            
            token = create_jwt_token(user['id'], user['username'], user['role'])
            create_audit_log(
                user_id=user['id'], 
                username=username, 
                action='LOGIN_WEBAUTHN_SUCCESS',
                details='Logged in with Passkey',
                ip_address=get_client_ip()
            )
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 400
        
    return jsonify({'error': 'Verification failed'}), 400

