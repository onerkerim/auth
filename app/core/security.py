from datetime import datetime, timedelta
from typing import Any, Optional, Union

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.exceptions import TokenExpiredException, InvalidTokenException

# Şifre hashleme için context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Kullanıcı için JWT access token oluşturur.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expire, "sub": str(subject), "type": "access"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Kullanıcı için JWT refresh token oluşturur.
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_password_reset_token(email: str) -> str:
    """
    Şifre sıfırlama için token oluşturur.
    """
    expire = datetime.utcnow() + timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    to_encode = {"exp": expire, "sub": email, "type": "reset"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_email_verification_token(email: str) -> str:
    """
    E-posta doğrulama için token oluşturur.
    """
    expire = datetime.utcnow() + timedelta(hours=settings.VERIFICATION_TOKEN_EXPIRE_HOURS)
    to_encode = {"exp": expire, "sub": email, "type": "verification"}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str, token_type: str) -> str:
    """
    Token'ı doğrular ve subject'i (genellikle kullanıcı ID'si veya e-posta) döndürür.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        subject: str = payload.get("sub")
        expiration = payload.get("exp")
        token_type_from_payload = payload.get("type")
        
        # Token süresinin dolup dolmadığını kontrol et
        if expiration is None or datetime.fromtimestamp(expiration) < datetime.utcnow():
            raise TokenExpiredException()
        
        # Token tipini kontrol et
        if token_type_from_payload != token_type:
            raise InvalidTokenException(f"Geçersiz token tipi: {token_type_from_payload}")
        
        if subject is None:
            raise InvalidTokenException()
        
        return subject
    except jwt.JWTError:
        raise InvalidTokenException()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Düz metin şifreyi hash'lenmiş şifre ile karşılaştırır.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Şifreyi güvenli bir şekilde hash'ler.
    """
    return pwd_context.hash(password)