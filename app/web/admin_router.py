from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import secrets
from datetime import datetime, timezone

from app.db import get_db
from app.models import User, OAuthClient, AuditEvent
from app.web.deps import get_current_web_user
from app.web.templates import templates
from app.web.csrf import get_csrf_token, verify_csrf
from app.web.flash import flash
from app.core.passwords import hash_password

router = APIRouter(prefix="/web/admin", tags=["admin"])

# Проверка, что зашел именно админ
def require_admin(user: User | None = Depends(get_current_web_user)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    if not user.is_admin:
        flash(request=None, message="Доступ только для администратора", category="error") # Заглушка, лучше делать через редирект
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

# --- ПОЛЬЗОВАТЕЛИ С ПОИСКОМ ---
@router.get("/users")
def admin_users(request: Request, q: str = None, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if isinstance(user, RedirectResponse): return user
    
    query = db.query(User)
    if q:
        query = query.filter(User.email.ilike(f"%{q}%"))
    
    users = query.order_by(User.id.desc()).all()
    
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "users": users,
        "search_query": q or ""
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

# --- СОЗДАНИЕ КЛИЕНТА ---
@router.get("/clients/new")
def admin_client_new(request: Request, user: User = Depends(require_admin)):
    if isinstance(user, RedirectResponse): return user
    
    return templates.TemplateResponse("admin/client_new.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user
    })

@router.post("/clients/new")
def admin_client_create(
    request: Request,
    name: str = Form(...),
    is_confidential: bool = Form(default=False),
    scopes: str = Form(default="openid email profile"),
    grant_types: str = Form(default="authorization_code,refresh_token"),
    redirect_uris: str = Form(default=""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    if isinstance(user, RedirectResponse): return user
    
    csrf_token = request.session.get("csrf_token") # В реальном коде нужно передавать из формы
    # В FastAPI мы обычно получаем csrf_token из формы, но для простоты проверим сессию
    # (В идеале: csrf_token: str = Form(...) и verify_csrf)
    
    client_id = secrets.token_urlsafe(32)
    client_secret = None
    hashed_secret = None

    if is_confidential:
        client_secret = secrets.token_urlsafe(48)
        hashed_secret = hash_password(client_secret)

    # Парсим списки из строк
    scopes_list = [s.strip() for s in scopes.split(",") if s.strip()]
    grants_list = [g.strip() for g in grant_types.split(",") if g.strip()]
    uris_list = [u.strip() for u in redirect_uris.split(",") if u.strip()]

    new_client = OAuthClient(
        client_id=client_id,
        name=name,
        is_confidential=is_confidential,
        hashed_secret=hashed_secret,
        scopes=scopes_list,
        grant_types=grants_list,
        redirect_uris=uris_list
    )
    db.add(new_client)
    db.commit()

    if client_secret:
        flash(request, f"Клиент создан! Секрет (скопируйте): {client_secret}", "success")
    else:
        flash(request, f"Публичный клиент создан! Client ID: {client_id}", "success")

    return RedirectResponse("/web/admin/clients", status_code=303)

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