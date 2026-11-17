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
from app.web.flash import flash

router = APIRouter(prefix="/web", tags=["web"])

# Вспомогательная функция для рендера (оставили только для GET-страниц)
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
        flash(request, "Неверный email или пароль", "error")
        return RedirectResponse(f"/web/login?next={next or ''}", status_code=303)
    
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
    flash(request, "Вы успешно вошли в систему!", "success")
    
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
    flash(request, "Вы вышли из системы", "info")
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
    
    sessions = db.query(WebSession).filter(
        WebSession.user_id == user.id, 
        WebSession.revoked_at.is_(None)
    ).all()
    
    current_session_id = request.session.get("session_id")
    
    return render(request, "sessions.html", user, {
        "sessions": sessions,
        "current_session_id": current_session_id
    })

@router.post("/account/sessions/{session_id}/revoke")
def revoke_session(session_id: str, request: Request, csrf_token: str = Form(...), user: User | None = Depends(get_current_web_user), db: Session = Depends(get_db)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
    verify_csrf(request, csrf_token)
    db.query(WebSession).filter(WebSession.session_id == session_id, WebSession.user_id == user.id).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()
    flash(request, "Сессия завершена", "success")
    return RedirectResponse("/web/account/sessions", status_code=303)

# --- РЕГИСТРАЦИЯ ---
@router.get("/register")
def register_page(request: Request, user: User | None = Depends(get_current_web_user)):
    if user:
        return RedirectResponse("/web/account", status_code=303)
    return render(request, "register.html", user)

@router.post("/register")
def register_action(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)
    
    if password != password_confirm:
        flash(request, "Пароли не совпадают", "error")
        return RedirectResponse("/web/register", status_code=303)

    if db.query(User).filter(User.email == email).first():
        flash(request, "Email уже занят", "error")
        return RedirectResponse("/web/register", status_code=303)

    try:
        validate_policy(password, [email])
    except WeakPasswordError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/web/register", status_code=303)

    new_user = User(
        email=email,
        hashed_password=hash_password(password),
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    session_id = secrets.token_urlsafe(32)
    ws = WebSession(session_id=session_id, user_id=new_user.id, ip=request.client.host, user_agent=request.headers.get("user-agent"))
    db.add(ws)
    db.commit()

    request.session["session_id"] = session_id
    flash(request, "Добро пожаловать! Аккаунт успешно создан.", "success")
    
    return RedirectResponse("/web/account", status_code=303)

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
        flash(request, "Старый пароль неверен", "error")
        return RedirectResponse("/web/account/security", status_code=303)
        
    if new_password != new_password_confirm:
        flash(request, "Пароли не совпадают", "error")
        return RedirectResponse("/web/account/security", status_code=303)

    try:
        validate_policy(new_password, [user.email])
    except WeakPasswordError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/web/account/security", status_code=303)

    # Меняем пароль
    user.hashed_password = hash_password(new_password)
    db.commit()

    # Разлогиниваем все остальные сессии
    current_id = request.session.get("session_id")
    db.query(WebSession).filter(
        WebSession.user_id == user.id,
        WebSession.session_id != current_id,
        WebSession.revoked_at.is_(None)
    ).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()

    flash(request, "Пароль успешно изменен. Остальные устройства разлогинены.", "success")
    return RedirectResponse("/web/account/security", status_code=303)