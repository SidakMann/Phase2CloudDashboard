"""
Authentication utilities for Phase 3
Handles JWT tokens, password hashing, and OAuth
"""
import jwt
import bcrypt
import os
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
import azure.functions as func

logger = logging.getLogger(__name__)


class AuthManager:
    """Manages authentication operations"""

    def __init__(self):
        self.jwt_secret = os.environ.get('JWT_SECRET_KEY', 'change-this-secret-key')
        self.jwt_algorithm = os.environ.get('JWT_ALGORITHM', 'HS256')
        self.jwt_expiration_hours = int(os.environ.get('JWT_EXPIRATION_HOURS', '24'))

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def generate_jwt_token(self, user_id: int, email: str) -> str:
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user_id,
            'email': email,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiration_hours)
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return token

    def decode_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None

    def hash_token(self, token: str) -> str:
        """Hash a token for storage (for session tracking)"""
        return hashlib.sha256(token.encode()).hexdigest()


def extract_token_from_request(req: func.HttpRequest) -> Optional[str]:
    """
    Extract JWT token from request headers.
    Supports: Authorization: Bearer <token>
    """
    # Try different header variations (Azure Functions may normalize headers)
    auth_header = req.headers.get('Authorization') or req.headers.get('authorization') or ''

    if auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix

    return None


def require_auth(func_handler):
    """
    Decorator to require authentication for Azure Functions endpoints.
    Usage:
        @require_auth
        def my_function(req: func.HttpRequest) -> func.HttpResponse:
            user_id = req.context.user_id
            email = req.context.email
            ...
    """
    @wraps(func_handler)
    def wrapper(req: func.HttpRequest) -> func.HttpResponse:
        token = extract_token_from_request(req)

        if not token:
            return func.HttpResponse(
                '{"error": "Unauthorized", "message": "Missing authentication token"}',
                status_code=401,
                mimetype='application/json'
            )

        auth_mgr = AuthManager()
        payload = auth_mgr.decode_jwt_token(token)

        if not payload:
            return func.HttpResponse(
                '{"error": "Unauthorized", "message": "Invalid or expired token"}',
                status_code=401,
                mimetype='application/json'
            )

        # Attach user info to request context
        if not hasattr(req, 'context'):
            req.context = type('obj', (object,), {})()

        req.context.user_id = payload.get('user_id')
        req.context.email = payload.get('email')

        # Call the actual function
        return func_handler(req)

    return wrapper


def validate_email(email: str) -> bool:
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    return True, ""


# GitHub OAuth utilities
class GitHubOAuth:
    """Handle GitHub OAuth flow"""

    def __init__(self):
        self.client_id = os.environ.get('GITHUB_CLIENT_ID')
        self.client_secret = os.environ.get('GITHUB_CLIENT_SECRET')
        self.redirect_uri = os.environ.get('GITHUB_REDIRECT_URI')

    def get_authorization_url(self, state: str = None) -> str:
        """Get GitHub OAuth authorization URL"""
        base_url = "https://github.com/login/oauth/authorize"
        params = f"client_id={self.client_id}&redirect_uri={self.redirect_uri}&scope=user:email"
        if state:
            params += f"&state={state}"
        return f"{base_url}?{params}"

    def exchange_code_for_token(self, code: str) -> Optional[str]:
        """Exchange authorization code for access token"""
        import requests

        url = "https://github.com/login/oauth/access_token"
        headers = {'Accept': 'application/json'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }

        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            result = response.json()
            return result.get('access_token')
        except Exception as e:
            logger.error(f"GitHub token exchange error: {e}")
            return None

    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get GitHub user information"""
        import requests

        url = "https://api.github.com/user"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"GitHub user info error: {e}")
            return None

    def get_user_email(self, access_token: str) -> Optional[str]:
        """Get primary email from GitHub"""
        import requests

        url = "https://api.github.com/user/emails"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            emails = response.json()

            # Find primary email
            for email_obj in emails:
                if email_obj.get('primary') and email_obj.get('verified'):
                    return email_obj.get('email')

            # Fallback to first verified email
            for email_obj in emails:
                if email_obj.get('verified'):
                    return email_obj.get('email')

            return None
        except Exception as e:
            logger.error(f"GitHub email fetch error: {e}")
            return None
