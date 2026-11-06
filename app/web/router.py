from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import secrets

from app.db import get_db
from app.models import User, WebSession
from app.core.passwords import verify_password, hash_password, validate_policy, WeakPasswordError
from app.web.csrf import get_csrf_token, verify_csrf
from app.web.deps import get_current_web_user
from app.web.templates import templates

router = APIRouter(prefix="/web", tags=["web"])

# Вспомогательная функция, чтобы не дублировать передачу контекста в шаблоны
def render(request: Request, template_name: str, user: User | None, context: dict = None):
    if context is None:
        context = {}
    context.update({
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user
    })
    return templates.TemplateResponse(template_name, context)

# --- ЛОГИН ---
@router.get("/login")
def login_page(request: Request, next: str = None, user: User | None = Depends(get_current_web_user)):
    if user:
        return RedirectResponse("/web/account", status_code=303)
    return render(request, "login.html", user, {"next_url": next})

@router.post("/login")
def login_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(default=None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)
    user = db.query(User).filter(User.email == email).first()
    
    if not user or not verify_password(password, user.hashed_password):
        return render(request, "login.html", None, {"error": "Неверный email или пароль"})
    
    # Создаем сессию
    session_id = secrets.token_urlsafe(32)
    ws = WebSession(
        session_id=session_id, 
        user_id=user.id, 
        ip=request.client.host,
        user_agent=request.headers.get("user-agent", "Unknown")
    )
    db.add(ws)
    db.commit()
    
    request.session["session_id"] = session_id
    redirect_url = next if next else "/web/account"
    return RedirectResponse(redirect_url, status_code=303)

# --- ВЫХОД ---
@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    session_id = request.session.get("session_id")
    if session_id:
        db.query(WebSession).filter(WebSession.session_id == session_id).update({"revoked_at": datetime.now(timezone.utc)})
        db.commit()
    request.session.clear()
    return RedirectResponse("/web/login", status_code=303)

# --- ЛИЧНЫЙ КАБИНЕТ ---
@router.get("/account")
def account_page(request: Request, user: User | None = Depends(get_current_web_user)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    return render(request, "account.html", user)

# --- СПИСОК СЕССИЙ ---
@router.get("/account/sessions")
def account_sessions(request: Request, user: User | None = Depends(get_current_web_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    
    # Получаем все активные сессии пользователя
    sessions = db.query(WebSession).filter(
        WebSession.user_id == user.id, 
        WebSession.revoked_at.is_(None)
    ).all()
    
    current_session_id = request.session.get("session_id")
    
    return render(request, "sessions.html", user, {
        "sessions": sessions,
        "current_session_id": current_session_id
    })

# --- СМЕНА ПАРОЛЯ ---
@router.get("/account/security")
def security_page(request: Request, user: User | None = Depends(get_current_web_user)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    return render(request, "security.html", user)

@router.post("/account/security")
def security_action(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    csrf_token: str = Form(...),
    user: User | None = Depends(get_current_web_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    
    verify_csrf(request, csrf_token)
    
    if not verify_password(old_password, user.hashed_password):
        return render(request, "security.html", user, {"error": "Старый пароль неверен"})
        
    if new_password != new_password_confirm:
        return render(request, "security.html", user, {"error": "Пароли не совпадают"})

    try:
        validate_policy(new_password, [user.email])
    except WeakPasswordError as e:
        return render(request, "security.html", user, {"error": str(e)})

    # Меняем пароль
    user.hashed_password = hash_password(new_password)
    db.commit()

    # Разлогиниваем все остальные сессии (оставляем только текущую)
    current_id = request.session.get("session_id")
    db.query(WebSession).filter(
        WebSession.user_id == user.id,
        WebSession.session_id != current_id,
        WebSession.revoked_at.is_(None)
    ).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()

    return render(request, "security.html", user, {"success": "Пароль успешно изменен. Остальные устройства разлогинены."})

@router.post("/account/sessions/{session_id}/revoke")
def revoke_session(session_id: str, request: Request, csrf_token: str = Form(...), user: User | None = Depends(get_current_web_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    verify_csrf(request, csrf_token)
    # Можно отзывать только свои сессии
    db.query(WebSession).filter(WebSession.session_id == session_id, WebSession.user_id == user.id).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()
    return RedirectResponse("/web/account/sessions", status_code=303)