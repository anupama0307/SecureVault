"""
SecureVault Admin Routes
========================
Admin-only endpoints for user management and audit logs.

Endpoints:
- GET /admin/users - List all users
- GET /admin/audit-logs - Get security event logs
- GET /admin/stats - Dashboard statistics
- GET /admin/access-control - View ACM documentation

Security:
- All endpoints require 'admin' role
- Comprehensive audit logging
"""

from flask import Blueprint, request, jsonify, g
from models import get_all_users, get_audit_logs, get_all_resources, create_audit_log
from utils.access_control import require_auth, require_role, get_access_control_info, get_client_ip

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# =============================================================================
# GET ALL USERS
# =============================================================================

@admin_bp.route('/users', methods=['GET'])
@require_auth
@require_role('admin')
def list_users():
    """Get all registered users."""
    users = get_all_users()
    
    # Group by role for statistics
    students = [u for u in users if u['role'] == 'student']
    faculty = [u for u in users if u['role'] == 'faculty']
    admins = [u for u in users if u['role'] == 'admin']
    
    return jsonify({
        'success': True,
        'total': len(users),
        'by_role': {
            'students': len(students),
            'faculty': len(faculty),
            'admins': len(admins)
        },
        'users': users
    })


# =============================================================================
# GET AUDIT LOGS
# =============================================================================

@admin_bp.route('/audit-logs', methods=['GET'])
@require_auth
@require_role('admin')
def list_audit_logs():
    """
    Get security event logs.
    
    Query Parameters:
        - limit (int): Number of logs to return (default 100, max 500)
    """
    limit = min(request.args.get('limit', 100, type=int), 500)
    
    logs = get_audit_logs(limit)
    
    # Group by action type for statistics
    action_counts = {}
    for log in logs:
        action = log['action']
        action_counts[action] = action_counts.get(action, 0) + 1
    
    return jsonify({
        'success': True,
        'total': len(logs),
        'action_summary': action_counts,
        'logs': logs
    })


# =============================================================================
# GET DASHBOARD STATISTICS
# =============================================================================

@admin_bp.route('/stats', methods=['GET'])
@require_auth
@require_role('admin')
def get_stats():
    """Get dashboard statistics."""
    users = get_all_users()
    resources = get_all_resources()
    logs = get_audit_logs(100)
    
    # User statistics
    students = len([u for u in users if u['role'] == 'student'])
    faculty = len([u for u in users if u['role'] == 'faculty'])
    
    # Resource statistics
    quiz_passwords = len([r for r in resources if r['resource_type'] == 'quiz_password'])
    pdfs = len([r for r in resources if r['resource_type'] == 'pdf'])
    question_papers = len([r for r in resources if r['resource_type'] == 'question_paper'])
    
    # Security statistics from logs
    login_successes = len([l for l in logs if l['action'] == 'LOGIN_SUCCESS'])
    login_failures = len([l for l in logs if l['action'] == 'LOGIN_FAILED'])
    
    return jsonify({
        'success': True,
        'users': {
            'total': len(users),
            'students': students,
            'faculty': faculty
        },
        'resources': {
            'total': len(resources),
            'quiz_passwords': quiz_passwords,
            'pdfs': pdfs,
            'question_papers': question_papers
        },
        'security': {
            'recent_login_successes': login_successes,
            'recent_login_failures': login_failures
        }
    })


# =============================================================================
# GET ACCESS CONTROL INFORMATION
# =============================================================================

@admin_bp.route('/access-control', methods=['GET'])
@require_auth
@require_role('admin')
def get_access_control():
    """Get Access Control Matrix and security documentation."""
    info = get_access_control_info()
    
    return jsonify({
        'success': True,
        **info
    })
