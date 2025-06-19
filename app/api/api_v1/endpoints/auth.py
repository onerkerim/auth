from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limiter tanımla
limiter = Limiter(key_func=get_remote_address)

from app.api.deps import get_db_dependency, get_current_user, get_current_admin_user
from app.core.config import settings
from app.core.exceptions import CredentialsException, ValidationException, NotFoundException
from app.core.security import (
    create_access_token, create_refresh_token, verify_password, get_password_hash,
    create_password_reset_token, create_email_verification_token, verify_token
)
from app.models.user import User, RefreshToken, PasswordReset
from app.schemas.token import Token, RefreshToken as RefreshTokenSchema, TokenResponse
from app.schemas.user import User as UserSchema
from app.schemas.user import UserCreate, EmailVerification, PasswordResetRequest, PasswordReset as PasswordResetSchema
from app.services.email import send_reset_password_email, send_verification_email

router = APIRouter()

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register(
    background_tasks: BackgroundTasks,
    user_in: UserCreate,
    db: Session = Depends(get_db_dependency),
    request: Request = None,
    current_user: User = Depends(get_current_admin_user)
) -> Any:
    """
    Yeni kullanıcı kaydı oluşturur.
    """
    # E-posta adresi zaten kullanılıyor mu kontrol et
    user = db.query(User).filter(User.email == user_in.email).first()
    if user:
        raise ValidationException("Bu e-posta adresi zaten kullanılmaktadır")
    
    # Kullanıcı adı zaten kullanılıyor mu kontrol et
    user = db.query(User).filter(User.username == user_in.username).first()
    if user:
        raise ValidationException("Bu kullanıcı adı zaten kullanılmaktadır")
    
    # Yeni kullanıcı oluştur
    db_user = User(
        email=user_in.email,
        username=user_in.username,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        is_active=True,
        is_verified=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # E-posta doğrulama token'ı oluştur ve e-posta gönder
    verification_token = create_email_verification_token(db_user.email)
    background_tasks.add_task(
        send_verification_email, email_to=db_user.email, token=verification_token, username=db_user.username
    )
    
    # Access ve refresh token oluştur
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(subject=db_user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(subject=db_user.id, expires_delta=refresh_token_expires)
    
    # Refresh token'ı veritabanına kaydet
    db_refresh_token = RefreshToken(
        token=refresh_token,
        user_id=db_user.id,
        expires_at=datetime.utcnow() + refresh_token_expires
    )
    db.add(db_refresh_token)
    db.commit()
    
    # Kullanıcı rollerini al
    roles = [role.name for role in db_user.roles]
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user_id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "roles": roles
    }

@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db_dependency)
) -> Any:
    """
    OAuth2 uyumlu token alır ve kullanıcı kimliğini doğrular.
    """
    # Kullanıcıyı e-posta veya kullanıcı adına göre bul
    user = db.query(User).filter(
        (User.email == form_data.username) | (User.username == form_data.username)
    ).first()
    
    # Kullanıcı bulunamadı veya şifre yanlış
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise CredentialsException("Geçersiz kimlik bilgileri")
    
    # Kullanıcı aktif değil
    if not user.is_active:
        raise CredentialsException("Hesap devre dışı bırakılmış")
    
    # Access ve refresh token oluştur
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(subject=user.id, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(subject=user.id, expires_delta=refresh_token_expires)
    
    # Refresh token'ı veritabanına kaydet
    db_refresh_token = RefreshToken(
        token=refresh_token,
        user_id=user.id,
        expires_at=datetime.utcnow() + refresh_token_expires
    )
    db.add(db_refresh_token)
    db.commit()
    
    # Kullanıcı rollerini al
    roles = [role.name for role in user.roles]
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": roles
    }

@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/hour")
async def refresh_token(
    token_data: RefreshTokenSchema,
    db: Session = Depends(get_db_dependency),
    request: Request = None
) -> Any:
    """
    Refresh token kullanarak yeni bir access token alır.
    """
    try:
        # Refresh token'ı doğrula
        user_id = verify_token(token_data.refresh_token, "refresh")
        
        # Veritabanında refresh token'ı kontrol et
        db_token = db.query(RefreshToken).filter(RefreshToken.token == token_data.refresh_token).first()
        if not db_token or db_token.revoked or db_token.expires_at < datetime.utcnow():
            raise CredentialsException("Geçersiz veya süresi dolmuş refresh token")
        
        # Kullanıcıyı kontrol et
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise CredentialsException("Kullanıcı bulunamadı veya hesap devre dışı")
        
        # Yeni access token oluştur
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(subject=user.id, expires_delta=access_token_expires)
        
        # Kullanıcı rollerini al
        roles = [role.name for role in user.roles]
        
        return {
            "access_token": access_token,
            "refresh_token": token_data.refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": roles
        }
    except Exception as e:
        raise CredentialsException("Geçersiz veya süresi dolmuş refresh token")

@router.get("/me", response_model=UserSchema)
async def read_users_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Mevcut kullanıcının bilgilerini alır.
    """
    return current_user

@router.post("/logout")
async def logout(
    token_data: RefreshTokenSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db_dependency)
) -> Any:
    """
    Kullanıcı oturumunu kapatır ve refresh token'ı geçersiz kılar.
    """
    # Refresh token'ı bul ve geçersiz kıl
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token_data.refresh_token,
        RefreshToken.user_id == current_user.id
    ).first()
    
    if db_token:
        db_token.revoked = True
        db.commit()
    
    return {"message": "Başarıyla çıkış yapıldı"}

@router.post("/verify-email")
@limiter.limit("3/hour")
async def verify_email(
    verification_data: EmailVerification,
    db: Session = Depends(get_db_dependency),
    request: Request = None
) -> Any:
    """
    E-posta doğrulama token'ını doğrular.
    """
    try:
        # Token'ı doğrula
        email = verify_token(verification_data.token, "verification")
        
        # Kullanıcıyı bul
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise NotFoundException("Kullanıcı bulunamadı")
        
        # Kullanıcıyı doğrulanmış olarak işaretle
        user.is_verified = True
        db.commit()
        
        return {"message": "E-posta adresiniz başarıyla doğrulandı"}
    except Exception as e:
        raise ValidationException("Geçersiz veya süresi dolmuş doğrulama token'ı")

@router.post("/password-reset-request")
@limiter.limit("3/hour")
async def password_reset_request(
    reset_data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db_dependency),
    request: Request = None
) -> Any:
    """
    Şifre sıfırlama isteği oluşturur ve e-posta gönderir.
    """
    # Kullanıcıyı bul
    user = db.query(User).filter(User.email == reset_data.email).first()
    
    # Kullanıcı bulunamasa bile güvenlik için başarılı mesajı döndür
    if not user:
        return {"message": "Şifre sıfırlama talimatları e-posta adresinize gönderildi"}
    
    # Şifre sıfırlama token'ı oluştur
    token = create_password_reset_token(user.email)
    
    # Token'ı veritabanına kaydet
    expires_at = datetime.utcnow() + timedelta(hours=settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    db_token = PasswordReset(
        email=user.email,
        token=token,
        expires_at=expires_at,
        used=False
    )
    db.add(db_token)
    db.commit()
    
    # E-posta gönder
    background_tasks.add_task(
        send_reset_password_email, email_to=user.email, token=token, username=user.username
    )
    
    return {"message": "Şifre sıfırlama talimatları e-posta adresinize gönderildi"}

@router.post("/password-reset")
@limiter.limit("3/hour")
async def password_reset(
    reset_data: PasswordResetSchema,
    db: Session = Depends(get_db_dependency),
    request: Request = None
) -> Any:
    """
    Şifre sıfırlama token'ını doğrular ve şifreyi günceller.
    """
    try:
        # Token'ı doğrula
        email = verify_token(reset_data.token, "reset")
        
        # Veritabanında token'ı kontrol et
        db_token = db.query(PasswordReset).filter(
            PasswordReset.token == reset_data.token,
            PasswordReset.used == False,
            PasswordReset.expires_at > datetime.utcnow()
        ).first()
        
        if not db_token:
            raise ValidationException("Geçersiz veya süresi dolmuş şifre sıfırlama token'ı")
        
        # Kullanıcıyı bul
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise NotFoundException("Kullanıcı bulunamadı")
        
        # Şifreyi güncelle
        user.hashed_password = get_password_hash(reset_data.new_password)
        
        # Token'ı kullanıldı olarak işaretle
        db_token.used = True
        
        db.commit()
        
        return {"message": "Şifreniz başarıyla sıfırlandı"}
    except Exception as e:
        raise ValidationException("Geçersiz veya süresi dolmuş şifre sıfırlama token'ı")