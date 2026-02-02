"""
SecureVault Faculty Resources Routes
=====================================
Handles faculty uploads (quiz passwords, PDFs, question papers).

Endpoints:
- POST /resources/quiz-password - Upload quiz password
- POST /resources/pdf - Upload protected PDF
- POST /resources/question-paper - Upload question paper
- GET /resources/my-uploads - Get own uploads
- DELETE /resources/<id> - Delete own upload
- GET /resources/shared - View all shared resources
- POST /resources/decrypt/<id> - Decrypt a resource (for students)
- GET /resources/verify/<id> - Verify resource integrity

Security:
- All uploads encrypted with AES-256
- Digital signatures for integrity verification
- Faculty can only manage their own uploads
- Students can only read (decrypt) shared resources
"""

import os
import base64
from flask import Blueprint, request, jsonify, g, send_file
from werkzeug.utils import secure_filename
from models import (
    create_resource, get_faculty_resources, get_all_resources,
    get_resource_by_id, delete_resource, create_audit_log
)
from utils.crypto import (
    aes_encrypt, aes_decrypt, encrypt_file, decrypt_file,
    sign_data, verify_signature
)
from utils.access_control import require_auth, require_role, get_client_ip
from config import UPLOADS_PATH

resources_bp = Blueprint('resources', __name__, url_prefix='/resources')


# =============================================================================
# UPLOAD QUIZ PASSWORD
# =============================================================================

@resources_bp.route('/quiz-password', methods=['POST'])
@require_auth
@require_role('faculty')
def upload_quiz_password():
    """
    Upload a quiz access password.
    
    Request Body:
        - subject (str): Subject/Course name
        - title (str): Quiz title
        - password (str): Password for quiz access
    """
    data = request.get_json()
    
    if not data or not all(k in data for k in ['subject', 'title', 'password']):
        return jsonify({'error': 'Subject, title, and password are required'}), 400
    
    faculty_id = g.user['user_id']
    subject = data['subject'].strip()
    title = data['title'].strip()
    password = data['password']
    
    # Encrypt the password
    encrypted_content, iv = aes_encrypt(password)
    
    # Sign the encrypted content for integrity
    signature = sign_data(encrypted_content)
    
    # Create resource
    resource_id = create_resource(
        faculty_id=faculty_id,
        resource_type='quiz_password',
        subject=subject,
        title=title,
        encrypted_content=encrypted_content,
        file_path=None,
        signature=signature,
        iv=iv
    )
    
    # Audit log
    create_audit_log(
        user_id=faculty_id,
        username=g.user['username'],
        action='RESOURCE_UPLOADED',
        resource_type='quiz_password',
        resource_id=resource_id,
        details=f'Quiz password uploaded: {title} ({subject})',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Quiz password uploaded successfully',
        'id': resource_id
    }), 201


# =============================================================================
# UPLOAD PDF
# =============================================================================

@resources_bp.route('/pdf', methods=['POST'])
@require_auth
@require_role('faculty')
def upload_pdf():
    """
    Upload a protected PDF file.
    
    Form Data:
        - subject (str): Subject/Course name
        - title (str): Document title
        - file: PDF file
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    subject = request.form.get('subject', '').strip()
    title = request.form.get('title', '').strip()
    
    if not subject or not title:
        return jsonify({'error': 'Subject and title are required'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    faculty_id = g.user['user_id']
    
    # Read and encrypt file
    file_data = file.read()
    encrypted_content, iv = encrypt_file(file_data)
    
    # Sign the encrypted content
    signature = sign_data(encrypted_content)
    
    # Create resource first to get ID
    resource_id = create_resource(
        faculty_id=faculty_id,
        resource_type='pdf',
        subject=subject,
        title=title,
        encrypted_content=encrypted_content,
        file_path=None,  # Will update after
        signature=signature,
        iv=iv
    )
    
    # Now generate filename with resource ID
    filename = secure_filename(f"{faculty_id}_{resource_id}_{file.filename}")
    file_path = os.path.join(UPLOADS_PATH, filename)
    
    # Save encrypted content to file
    with open(file_path, 'w') as f:
        f.write(encrypted_content)
    
    # Audit log
    create_audit_log(
        user_id=faculty_id,
        username=g.user['username'],
        action='RESOURCE_UPLOADED',
        resource_type='pdf',
        resource_id=resource_id,
        details=f'PDF uploaded: {title} ({subject})',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'PDF uploaded and encrypted successfully',
        'id': resource_id
    }), 201


# =============================================================================
# UPLOAD QUESTION PAPER
# =============================================================================

@resources_bp.route('/question-paper', methods=['POST'])
@require_auth
@require_role('faculty')
def upload_question_paper():
    """
    Upload a question paper.
    
    Form Data:
        - subject (str): Subject/Course name
        - title (str): Exam title
        - file: Question paper file
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    subject = request.form.get('subject', '').strip()
    title = request.form.get('title', '').strip()
    
    if not subject or not title:
        return jsonify({'error': 'Subject and title are required'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    faculty_id = g.user['user_id']
    
    # Read and encrypt file
    file_data = file.read()
    encrypted_content, iv = encrypt_file(file_data)
    
    # Sign the encrypted content
    signature = sign_data(encrypted_content)
    
    # Create resource
    resource_id = create_resource(
        faculty_id=faculty_id,
        resource_type='question_paper',
        subject=subject,
        title=title,
        encrypted_content=encrypted_content,
        file_path=None,
        signature=signature,
        iv=iv
    )
    
    # Audit log
    create_audit_log(
        user_id=faculty_id,
        username=g.user['username'],
        action='RESOURCE_UPLOADED',
        resource_type='question_paper',
        resource_id=resource_id,
        details=f'Question paper uploaded: {title} ({subject})',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Question paper uploaded and encrypted successfully',
        'id': resource_id
    }), 201


# =============================================================================
# GET MY UPLOADS (Faculty)
# =============================================================================

@resources_bp.route('/my-uploads', methods=['GET'])
@require_auth
@require_role('faculty')
def get_my_uploads():
    """Get all resources uploaded by the authenticated faculty."""
    faculty_id = g.user['user_id']
    
    resources = get_faculty_resources(faculty_id)
    
    # Don't include encrypted content in list view
    for resource in resources:
        resource.pop('encrypted_content', None)
    
    return jsonify({
        'success': True,
        'count': len(resources),
        'resources': resources
    })


# =============================================================================
# DELETE RESOURCE (Faculty - own only)
# =============================================================================

@resources_bp.route('/<int:resource_id>', methods=['DELETE'])
@require_auth
@require_role('faculty')
def remove_resource(resource_id):
    """Delete a resource (only own uploads)."""
    faculty_id = g.user['user_id']
    
    # Check if resource exists
    resource = get_resource_by_id(resource_id)
    if not resource:
        return jsonify({'error': 'Resource not found'}), 404
    
    # Check ownership
    if resource['faculty_id'] != faculty_id:
        return jsonify({'error': 'You can only delete your own uploads'}), 403
    
    # Delete
    success = delete_resource(resource_id, faculty_id)
    
    if not success:
        return jsonify({'error': 'Failed to delete resource'}), 500
    
    # Audit log
    create_audit_log(
        user_id=faculty_id,
        username=g.user['username'],
        action='RESOURCE_DELETED',
        resource_type=resource['resource_type'],
        resource_id=resource_id,
        details=f'Resource deleted: {resource["title"]}',
        ip_address=get_client_ip()
    )
    
    return jsonify({
        'success': True,
        'message': 'Resource deleted successfully'
    })


# =============================================================================
# GET SHARED RESOURCES (Students & Faculty)
# =============================================================================

@resources_bp.route('/shared', methods=['GET'])
@require_auth
@require_role('student', 'faculty', 'admin')
def get_shared_resources():
    """Get all shared resources (for students to view)."""
    resources = get_all_resources()
    
    # Remove encrypted content from list view
    for resource in resources:
        resource.pop('encrypted_content', None)
        resource.pop('signature', None)
        resource.pop('iv', None)
    
    return jsonify({
        'success': True,
        'count': len(resources),
        'resources': resources
    })


# =============================================================================
# DECRYPT RESOURCE (Students)
# =============================================================================

@resources_bp.route('/decrypt/<int:resource_id>', methods=['POST'])
@require_auth
@require_role('student', 'faculty', 'admin')
def decrypt_resource(resource_id):
    """
    Decrypt a resource (read-only access for students).
    Returns decrypted content for quiz passwords.
    For files, returns download link.
    """
    user_id = g.user['user_id']
    username = g.user['username']
    
    resource = get_resource_by_id(resource_id)
    
    if not resource:
        return jsonify({'error': 'Resource not found'}), 404
    
    # Verify signature first (integrity check)
    if not verify_signature(resource['encrypted_content'], resource['signature']):
        create_audit_log(
            user_id=user_id,
            username=username,
            action='INTEGRITY_CHECK_FAILED',
            resource_type=resource['resource_type'],
            resource_id=resource_id,
            details='Digital signature verification failed - possible tampering',
            ip_address=get_client_ip()
        )
        return jsonify({
            'error': 'Integrity verification failed',
            'message': 'The resource may have been tampered with'
        }), 400
    
    # Decrypt based on resource type
    if resource['resource_type'] == 'quiz_password':
        # Decrypt password
        try:
            decrypted = aes_decrypt(resource['encrypted_content'], resource['iv'])
            
            # Audit log
            create_audit_log(
                user_id=user_id,
                username=username,
                action='RESOURCE_ACCESSED',
                resource_type=resource['resource_type'],
                resource_id=resource_id,
                details=f'Quiz password accessed: {resource["title"]}',
                ip_address=get_client_ip()
            )
            
            return jsonify({
                'success': True,
                'resource_type': resource['resource_type'],
                'subject': resource['subject'],
                'title': resource['title'],
                'content': decrypted,
                'integrity_verified': True
            })
        except Exception as e:
            return jsonify({'error': 'Failed to decrypt resource'}), 500
    else:
        # For files (PDF, QP), decrypt and return file info
        try:
            decrypted_data = decrypt_file(resource['encrypted_content'], resource['iv'])
            
            # Audit log
            create_audit_log(
                user_id=user_id,
                username=username,
                action='RESOURCE_DOWNLOADED',
                resource_type=resource['resource_type'],
                resource_id=resource_id,
                details=f'File downloaded: {resource["title"]}',
                ip_address=get_client_ip()
            )
            
            # Return file as base64 for frontend to handle
            return jsonify({
                'success': True,
                'resource_type': resource['resource_type'],
                'subject': resource['subject'],
                'title': resource['title'],
                'file_data': base64.b64encode(decrypted_data).decode('utf-8'),
                'integrity_verified': True
            })
        except Exception as e:
            return jsonify({'error': 'Failed to decrypt file'}), 500


# =============================================================================
# VERIFY RESOURCE INTEGRITY
# =============================================================================

@resources_bp.route('/verify/<int:resource_id>', methods=['GET'])
@require_auth
@require_role('student', 'faculty', 'admin')
def verify_resource_integrity(resource_id):
    """
    Verify the integrity of a resource using digital signature.
    """
    resource = get_resource_by_id(resource_id)
    
    if not resource:
        return jsonify({'error': 'Resource not found'}), 404
    
    # Verify signature
    is_valid = verify_signature(resource['encrypted_content'], resource['signature'])
    
    return jsonify({
        'success': True,
        'resource_id': resource_id,
        'title': resource['title'],
        'integrity_valid': is_valid,
        'message': 'Signature valid - content has not been tampered' if is_valid else 'SIGNATURE INVALID - Content may have been modified!'
    })


# =============================================================================
# GET TOKEN (For Tamper Detection Demo)
# =============================================================================

@resources_bp.route('/token/<int:resource_id>', methods=['GET'])
@require_auth
@require_role('student', 'faculty', 'admin')
def get_resource_token(resource_id):
    """
    Get the full token for a resource.
    Token Format: Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )
    """
    resource = get_resource_by_id(resource_id)
    
    if not resource:
        return jsonify({'error': 'Resource not found'}), 404
    
    # Create the combined token
    iv = resource['iv']
    signature = resource['signature']
    ciphertext = resource['encrypted_content']
    
    # The token is the combination of all three
    token = f"{iv}|{signature}|{ciphertext}"
    
    return jsonify({
        'success': True,
        'resource_id': resource_id,
        'title': resource['title'],
        'resource_type': resource['resource_type'],
        'token': token,
        'token_format': 'Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )',
        'components': {
            'iv': iv[:32] + '...' if len(iv) > 32 else iv,
            'signature': signature[:32] + '...' if len(signature) > 32 else signature,
            'ciphertext': ciphertext[:32] + '...' if len(ciphertext) > 32 else ciphertext
        }
    })


# =============================================================================
# VERIFY TOKEN (For Tamper Detection Demo)
# =============================================================================

@resources_bp.route('/verify-token/<int:resource_id>', methods=['POST'])
@require_auth
@require_role('student', 'faculty', 'admin')
def verify_token(resource_id):
    """
    Verify a token that may have been modified.
    Used for tamper detection demo.
    """
    data = request.get_json()
    
    if not data or 'token' not in data:
        return jsonify({'error': 'Token required'}), 400
    
    resource = get_resource_by_id(resource_id)
    
    if not resource:
        return jsonify({'error': 'Resource not found'}), 404
    
    token = data['token']
    
    try:
        # Parse the token
        parts = token.split('|')
        if len(parts) != 3:
            return jsonify({
                'success': True,
                'valid': False,
                'message': 'Invalid token format'
            })
        
        iv, signature, ciphertext = parts
        
        # Verify the signature against the ciphertext
        is_valid = verify_signature(ciphertext, signature)
        
        # Log the verification attempt
        create_audit_log(
            user_id=g.user['user_id'],
            username=g.user['username'],
            action='TOKEN_VERIFICATION' if is_valid else 'TAMPER_DETECTED',
            resource_type=resource['resource_type'],
            resource_id=resource_id,
            details=f'Token verification {"passed" if is_valid else "FAILED - tampering detected"}',
            ip_address=get_client_ip()
        )
        
        return jsonify({
            'success': True,
            'valid': is_valid,
            'resource_id': resource_id,
            'resource_type': resource['resource_type'],
            'message': '✓ Valid - Content integrity verified' if is_valid else '✗ INVALID - Tampering detected!'
        })
    except Exception as e:
        return jsonify({
            'success': True,
            'valid': False,
            'message': f'Token verification failed: {str(e)}'
        })
