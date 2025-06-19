# FastAPI Auth Mikroservis

Bu proje, FastAPI kullanarak geliştirilmiş kapsamlı bir kimlik doğrulama ve yetkilendirme mikroservisidir.

## Özellikler

- Kullanıcı kaydı ve girişi
- JWT tabanlı kimlik doğrulama
- Rol tabanlı yetkilendirme
- Şifre sıfırlama ve e-posta doğrulama
- Kullanıcı profil yönetimi
- Token yönetimi (geçersiz ve süresi dolan tokenlar için uyarılar)
- PostgreSQL veritabanı entegrasyonu
- Alembic ile veritabanı migrasyonları
- Kapsamlı test suite

## Kurulum

```bash
# Sanal ortam oluşturma
python3.11 -m venv .venv
source .venv/bin/activate  # Linux/Mac için
# .venv\Scripts\activate  # Windows için

# Bağımlılıkları yükleme
python -m pip install -r requirements.txt

# .env dosyasını oluşturma
cp .env.example .env
# .env dosyasını düzenleyin

# Veritabanı migrasyonlarını çalıştırma
alembic upgrade head

# Uygulamayı başlatma (Geliştirme için)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Uygulamayı başlatma (Üretim için)
uvicorn app.main:app --host 0.0.0.0 --port 8000
```