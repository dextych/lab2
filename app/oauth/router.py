#Главный OAuth-роутер: собирает все oauth-эндпоинты

from fastapi import APIRouter

from app.oauth.authorize import router as authorize_router
from app.oauth.discovery import router as discovery_router
from app.oauth.jwks import router as jwks_router
from app.oauth.token import router as token_router
from app.oauth.revoke import router as revoke_router
from app.oauth.introspect import router as introspect_router
from app.oauth.userinfo import router as userinfo_router 

router = APIRouter()
router.include_router(authorize_router)
router.include_router(jwks_router)
router.include_router(discovery_router)
router.include_router(token_router)
router.include_router(revoke_router)
router.include_router(introspect_router)
router.include_router(userinfo_router)