"""
SecureVault Access Control
==========================
JWT token management and Role-Based Access Control (RBAC).

Security Concepts:
- JWT (JSON Web Token): Stateless authentication
- RBAC: Role-based permissions enforcement
- Decorators: @require_auth, @require_role

NIST SP 800-63-2 Compliance:
- Secure session management
- Token expiration
- Role verification
"""

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_HOURS, ACCESS_CONTROL_MATRIX, SECURITY_CONCEPTS, COUNTERMEASURES


# =============================================================================
# JWT TOKEN MANAGEMENT
# =============================================================================

def create_jwt_token(user_id, username, role):
    """
    Create a JWT token for authenticated user.
    
    Args:
        user_id (int): User's database ID
        username (str): User's username
        role (str): User's role (student, faculty, admin)
        
    Returns:
        str: JWT token
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token):
    """
    Decode and validate a JWT token.
    
    Args:
        token (str): JWT token
        
    Returns:
        tuple: (is_valid, payload or error_message)
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError as e:
        return False, f"Invalid token: {str(e)}"


# =============================================================================
# AUTHENTICATION DECORATOR
# =============================================================================

def require_auth(f):
    """
    Decorator to require authentication for a route.
    Sets g.user with the decoded token payload.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Authorization header required'}), 401
        
        # Expect format: "Bearer <token>"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({'error': 'Invalid authorization format. Use: Bearer <token>'}), 401
        
        token = parts[1]
        
        # Decode and validate
        is_valid, result = decode_jwt_token(token)
        
        if not is_valid:
            return jsonify({'error': result}), 401
        
        # Store user info in Flask's g object
        g.user = result
        
        return f(*args, **kwargs)
    
    return decorated


# =============================================================================
# ROLE-BASED ACCESS CONTROL DECORATOR
# =============================================================================

def require_role(*allowed_roles):
    """
    Decorator to require specific role(s) for a route.
    Must be used after @require_auth.
    
    Usage:
        @app.route('/admin/users')
        @require_auth
        @require_role('admin')
        def get_users():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Check if user is authenticated
            if not hasattr(g, 'user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            # Check role
            user_role = g.user.get('role')
            if user_role not in allowed_roles:
                return jsonify({
                    'error': 'Access denied',
                    'message': f'This action requires one of these roles: {", ".join(allowed_roles)}',
                    'your_role': user_role
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


# =============================================================================
# PERMISSION CHECKING
# =============================================================================

def check_permission(role, resource, action):
    """
    Check if a role has permission to perform an action on a resource.
    
    Args:
        role (str): User's role
        resource (str): Resource type (passwords, resources, users, audit_logs)
        action (str): Action type (create, read, update, delete)
        
    Returns:
        bool: True if permitted
    """
    if role not in ACCESS_CONTROL_MATRIX:
        return False
    
    role_permissions = ACCESS_CONTROL_MATRIX[role]
    
    if resource not in role_permissions:
        return False
    
    return action in role_permissions[resource]


def get_user_permissions(role):
    """
    Get all permissions for a role.
    
    Args:
        role (str): User's role
        
    Returns:
        dict: Permissions by resource
    """
    return ACCESS_CONTROL_MATRIX.get(role, {})


# =============================================================================
# ACCESS CONTROL INFORMATION (for display/documentation)
# =============================================================================

def get_access_control_info():
    """
    Get complete access control information for display.
    
    Returns:
        dict: ACM, security concepts, and countermeasures
    """
    return {
        'access_control_matrix': ACCESS_CONTROL_MATRIX,
        'security_concepts': SECURITY_CONCEPTS,
        'countermeasures': COUNTERMEASURES,
        'roles': ['student', 'faculty', 'admin'],
        'resources': ['passwords', 'resources', 'users', 'audit_logs'],
        'actions': ['create', 'read', 'update', 'delete']
    }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_client_ip():
    """Get the client's IP address from the request."""
    # Check for proxy headers first
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'
