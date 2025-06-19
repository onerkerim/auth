from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import CredentialsException, PermissionDeniedException, TokenExpiredException, InvalidTokenException
from app.core.security import verify_token
from app.db.session import get_db
from app.models.user import User, Role
from app.schemas.token import TokenPayload

# OAuth2 şeması için token URL'si
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

# Veritabanı bağımlılığı
def get_db_dependency() -> Generator:
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()

# Mevcut kullanıcıyı alma bağımlılığı
def get_current_user(
    db: Session = Depends(get_db_dependency),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    JWT token'dan mevcut kullanıcıyı alır.
    """
    try:
        # Token'ı doğrula ve kullanıcı ID'sini al
        user_id = verify_token(token, "access")
        
        # Kullanıcıyı veritabanından al
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise CredentialsException()
        
        # Kullanıcı aktif mi kontrol et
        if not user.is_active:
            raise PermissionDeniedException("Hesap devre dışı bırakılmış")
        
        return user
    except (TokenExpiredException, InvalidTokenException) as e:
        raise e
    except (jwt.JWTError, ValidationError):
        raise CredentialsException()

# Aktif kullanıcıyı alma bağımlılığı
def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Mevcut kullanıcının aktif olduğunu doğrular.
    """
    if not current_user.is_active:
        raise PermissionDeniedException("Hesap devre dışı bırakılmış")
    return current_user

# Doğrulanmış kullanıcıyı alma bağımlılığı
def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """
    Mevcut kullanıcının e-posta doğrulamasını tamamladığını doğrular.
    """
    if not current_user.is_verified:
        raise PermissionDeniedException("E-posta adresinizi doğrulamanız gerekmektedir")
    return current_user

# Belirli role sahip kullanıcıyı alma bağımlılığı
def get_current_user_with_role(role_name: str):
    """
    Mevcut kullanıcının belirli bir role sahip olduğunu doğrular.
    """
    def _get_current_user_with_role(
        current_user: User = Depends(get_current_verified_user),
        db: Session = Depends(get_db_dependency)
    ) -> User:
        # Kullanıcının rollerini kontrol et
        user_roles = [role.name for role in current_user.roles]
        if role_name not in user_roles:
            raise PermissionDeniedException(f"Bu işlem için '{role_name}' rolüne sahip olmanız gerekmektedir")
        return current_user
    
    return _get_current_user_with_role

# Admin kullanıcıyı alma bağımlılığı
def get_current_admin_user(
    current_user: User = Depends(get_current_user_with_role("admin"))
) -> User:
    """
    Mevcut kullanıcının admin rolüne sahip olduğunu doğrular.
    """
    return current_user