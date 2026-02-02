"""
SecureVault WebAuthn Utilities
==============================
Handlers for Passkey registration and authentication using py_webauthn v2.x
"""

import json
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
)
from config import RP_ID, RP_NAME, ORIGIN


def generate_reg_options(user, existing_credentials=None):
    """
    Generate options for registering a new credential (step 1).
    """
    if existing_credentials is None:
        existing_credentials = []

    # Build exclude list from existing credentials (simplified - no transports)
    exclude_creds = []
    for cred in existing_credentials:
        try:
            exclude_creds.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["credential_id"])
                )
            )
        except Exception:
            pass

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user['id']).encode('utf-8'),
        user_name=user['username'],
        user_display_name=user['username'],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        ),
        exclude_credentials=exclude_creds if exclude_creds else None,
    )
    return options


def verify_reg_response(credential_dict, challenge_bytes):
    """
    Verify the navigator.credentials.create() response (step 2).
    """
    verification = verify_registration_response(
        credential=credential_dict,
        expected_challenge=challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )
    
    return {
        'verified': True,
        'credential_id': bytes_to_base64url(verification.credential_id),
        'credential_public_key': bytes_to_base64url(verification.credential_public_key),
        'sign_count': verification.sign_count,
    }


def generate_auth_options(existing_credentials):
    """
    Generate options for logging in (step 1).
    """
    # Build allow list (simplified - no transports)
    allow_creds = []
    for cred in existing_credentials:
        try:
            allow_creds.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["credential_id"])
                )
            )
        except Exception:
            pass

    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=allow_creds if allow_creds else None,
    )
    return options


def verify_auth_response(credential_dict, challenge_bytes, stored_credential, current_sign_count):
    """
    Verify the navigator.credentials.get() response (step 2).
    """
    verification = verify_authentication_response(
        credential=credential_dict,
        expected_challenge=challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=base64url_to_bytes(stored_credential['public_key']),
        credential_current_sign_count=current_sign_count,
    )
    
    return {
        'verified': True,
        'sign_count': verification.new_sign_count,
    }