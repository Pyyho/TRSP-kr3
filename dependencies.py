import secrets
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer

from auth import fake_users_db, verify_password, get_current_user_from_token
from config import settings

security_basic = HTTPBasic()
security_bearer = HTTPBearer(auto_error=False)


def auth_user(credentials: HTTPBasicCredentials = Depends(security_basic)) -> dict:
    """
    Authentication dependency for Basic Auth
    """
    username = credentials.username
    password = credentials.password

    user = fake_users_db.get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Use compare_digest for timing attack protection
    if not secrets.compare_digest(username, user["username"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not verify_password(password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return user


def get_current_user(token: str = Depends(security_bearer)) -> dict:
    """
    Get current user from JWT token
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return get_current_user_from_token(token.credentials)


def auth_docs(credentials: HTTPBasicCredentials = Depends(security_basic)) -> bool:
    """
    Authentication for docs in DEV mode
    """
    correct_username = secrets.compare_digest(credentials.username, settings.DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, settings.DOCS_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


# RBAC dependencies
def require_role(required_role: str):
    """Dependency factory for role-based access control"""

    def role_checker(user: dict = Depends(get_current_user)) -> dict:
        user_role = user.get("role", "guest")

        # Role hierarchy: admin > user > guest
        role_hierarchy = {"admin": 3, "user": 2, "guest": 1}

        if role_hierarchy.get(user_role, 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {required_role}",
            )
        return user

    return role_checker


# Specific role checkers
require_admin = require_role("admin")
require_user = require_role("user")