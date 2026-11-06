from fastapi import Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User, WebSession

def get_current_web_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    session_id = request.session.get("session_id")
    if not session_id:
        return None
    
    ws = db.query(WebSession).filter(WebSession.session_id == session_id, WebSession.revoked_at.is_(None)).first()
    if not ws:
        request.session.clear()
        return None
    
    # Обновляем время последнего визита
    ws.last_seen_at = func.now()
    db.commit()
    
    return ws.user

def require_web_user(user: User | None = Depends(get_current_web_user)) -> User:
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/web/login"})
    return user

def require_admin_web(user: User = Depends(require_web_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    return user