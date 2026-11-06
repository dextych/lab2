import secrets
from fastapi import Request, HTTPException

def get_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    return request.session["csrf_token"]

def verify_csrf(request: Request, form_token: str) -> None:
    session_token = request.session.get("csrf_token")
    if not session_token or not secrets.compare_digest(session_token, form_token):
        raise HTTPException(status_code=403, detail="CSRF token invalid")