from typing import Optional
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr

from app.core.config import settings

# E-posta bağlantı yapılandırması
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_FROM_NAME=settings.PROJECT_NAME,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

fastmail = FastMail(conf)

async def send_email(
    email_to: str,
    subject: str,
    body: str,
    template_name: Optional[str] = None
) -> None:
    """Genel e-posta gönderme fonksiyonu."""
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype='html'
    )
    
    await fastmail.send_message(message)

async def send_verification_email(email_to: str, token: str, username: str) -> None:
    """E-posta doğrulama bağlantısı gönderir."""
    subject = "E-posta Adresinizi Doğrulayın"
    verification_url = f"http://localhost:8000/auth/verify-email?token={token}"
    
    body = f"""
    <p>Merhaba {username},</p>
    <p>Hesabınızı doğrulamak için aşağıdaki bağlantıya tıklayın:</p>
    <p><a href="{verification_url}">{verification_url}</a></p>
    <p>Bu bağlantı 48 saat boyunca geçerlidir.</p>
    <p>Bu e-postayı siz talep etmediyseniz, lütfen dikkate almayın.</p>
    """
    
    await send_email(email_to, subject, body)

async def send_reset_password_email(email_to: str, token: str, username: str) -> None:
    """Şifre sıfırlama bağlantısı gönderir."""
    subject = "Şifre Sıfırlama İsteği"
    reset_url = f"http://localhost:8000/auth/reset-password?token={token}"
    
    body = f"""
    <p>Merhaba {username},</p>
    <p>Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p>Bu bağlantı 24 saat boyunca geçerlidir.</p>
    <p>Bu e-postayı siz talep etmediyseniz, lütfen dikkate almayın.</p>
    """
    
    await send_email(email_to, subject, body)