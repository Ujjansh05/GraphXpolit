"""Authentication module for the demo application."""

from database import get_connection


USERS_BY_NAME = {
    "admin": {"id": 1, "username": "admin", "role": "premium"},
    "guest": {"id": 2, "username": "guest", "role": "standard"},
}


def authenticate(username: str) -> dict:
    """Return a demo user without storing credentials."""
    user = USERS_BY_NAME.get(username)
    if user:
        log_login(username)
        return user
    raise ValueError("Unknown demo user")


def get_user_role(user: dict) -> str:
    """Return the role for a demo user."""
    return user.get("role", "standard")


def log_login(username: str):
    """Log a successful demo lookup."""
