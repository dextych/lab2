from fastapi import APIRouter, Request, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User, OAuthClient, AuditEvent
from app.web.deps import get_current_web_user
from app.web.templates import templates
from app.web.csrf import get_csrf_token

router = APIRouter(prefix="/web/admin", tags=["admin"])

# Проверка, что зашел именно админ
def require_admin(user: User | None = Depends(get_current_web_user)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    if not user.is_admin:
        return RedirectResponse("/web/account", status_code=303)
    return user

# --- ДАШБОРД ---
@router.get("")
def admin_dashboard(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if isinstance(user, RedirectResponse): return user
    
    users_count = db.query(User).count()
    clients_count = db.query(OAuthClient).count()
    audit_count = db.query(AuditEvent).count()

    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "users_count": users_count,
        "clients_count": clients_count,
        "audit_count": audit_count
    })

# --- ПОЛЬЗОВАТЕЛИ ---
@router.get("/users")
def admin_users(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if isinstance(user, RedirectResponse): return user
    
    users = db.query(User).order_by(User.id.desc()).all()
    
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "users": users
    })

# --- КЛИЕНТЫ ---
@router.get("/clients")
def admin_clients(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if isinstance(user, RedirectResponse): return user
    
    clients = db.query(OAuthClient).order_by(OAuthClient.id.desc()).all()
    
    return templates.TemplateResponse("admin/clients.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "clients": clients
    })

# --- АУДИТ ---
@router.get("/audit")
def admin_audit(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if isinstance(user, RedirectResponse): return user
    
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100).all()
    
    return templates.TemplateResponse("admin/audit.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "events": events
    })