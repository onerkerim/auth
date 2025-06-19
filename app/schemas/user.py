from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator
import re

# Temel kullanıcı şeması
class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    is_active: bool = True

# Kullanıcı oluşturma şeması
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    password_confirm: str
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Kullanıcı adı yalnızca harf, rakam ve alt çizgi içerebilir')
        return v
    
    @validator('password')
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Şifre en az bir büyük harf içermelidir')
        if not re.search(r'[a-z]', v):
            raise ValueError('Şifre en az bir küçük harf içermelidir')
        if not re.search(r'[0-9]', v):
            raise ValueError('Şifre en az bir rakam içermelidir')
        return v
    
    @validator('password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Şifreler eşleşmiyor')
        return v

# Kullanıcı güncelleme şeması
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None

# Şifre değiştirme şeması
class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    new_password_confirm: str
    
    @validator('new_password')
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Şifre en az bir büyük harf içermelidir')
        if not re.search(r'[a-z]', v):
            raise ValueError('Şifre en az bir küçük harf içermelidir')
        if not re.search(r'[0-9]', v):
            raise ValueError('Şifre en az bir rakam içermelidir')
        return v
    
    @validator('new_password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Şifreler eşleşmiyor')
        return v

# Şifre sıfırlama istek şeması
class PasswordResetRequest(BaseModel):
    email: EmailStr

# Şifre sıfırlama şeması
class PasswordReset(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
    new_password_confirm: str
    
    @validator('new_password')
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Şifre en az bir büyük harf içermelidir')
        if not re.search(r'[a-z]', v):
            raise ValueError('Şifre en az bir küçük harf içermelidir')
        if not re.search(r'[0-9]', v):
            raise ValueError('Şifre en az bir rakam içermelidir')
        return v
    
    @validator('new_password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Şifreler eşleşmiyor')
        return v

# Rol şeması
class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    pass

class RoleUpdate(RoleBase):
    name: Optional[str] = None
    description: Optional[str] = None

class RoleInDB(RoleBase):
    id: int
    
    class Config:
        orm_mode = True

# Veritabanından dönen kullanıcı şeması
class UserInDB(UserBase):
    id: int
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    roles: List[RoleInDB] = []
    
    class Config:
        orm_mode = True

# API yanıtı için kullanıcı şeması
class User(UserInDB):
    pass

# E-posta doğrulama şeması
class EmailVerification(BaseModel):
    token: str