from fastapi import status

class AuthException(Exception):
    """
    Kimlik doğrulama ve yetkilendirme ile ilgili hatalar için özel istisna sınıfı.
    """
    def __init__(self, detail: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.detail = detail
        self.status_code = status_code
        super().__init__(self.detail)

class TokenExpiredException(AuthException):
    """
    Token süresi dolduğunda fırlatılan istisna.
    """
    def __init__(self, detail: str = "Token süresi dolmuştur"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)

class InvalidTokenException(AuthException):
    """
    Geçersiz token durumunda fırlatılan istisna.
    """
    def __init__(self, detail: str = "Geçersiz token"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)

class CredentialsException(AuthException):
    """
    Kimlik bilgileri geçersiz olduğunda fırlatılan istisna.
    """
    def __init__(self, detail: str = "Kimlik bilgileri doğrulanamadı"):
        super().__init__(detail=detail, status_code=status.HTTP_401_UNAUTHORIZED)

class PermissionDeniedException(AuthException):
    """
    Kullanıcının yetkisi olmadığında fırlatılan istisna.
    """
    def __init__(self, detail: str = "Bu işlem için yetkiniz bulunmamaktadır"):
        super().__init__(detail=detail, status_code=status.HTTP_403_FORBIDDEN)

class NotFoundException(Exception):
    """
    Kaynak bulunamadığında fırlatılan istisna.
    """
    def __init__(self, detail: str = "Kaynak bulunamadı"):
        self.detail = detail
        super().__init__(self.detail)

class ValidationException(Exception):
    """
    Doğrulama hatalarında fırlatılan istisna.
    """
    def __init__(self, detail: str = "Doğrulama hatası"):
        self.detail = detail
        super().__init__(self.detail)

class EmailAlreadyExistsException(ValidationException):
    """
    E-posta adresi zaten kayıtlı olduğunda fırlatılan istisna.
    """
    def __init__(self, detail: str = "Bu e-posta adresi zaten kullanılmaktadır"):
        super().__init__(detail=detail)

class UsernameAlreadyExistsException(ValidationException):
    """
    Kullanıcı adı zaten kayıtlı olduğunda fırlatılan istisna.
    """
    def __init__(self, detail: str = "Bu kullanıcı adı zaten kullanılmaktadır"):
        super().__init__(detail=detail)