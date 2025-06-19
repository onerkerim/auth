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
python -m venv venv
source venv/bin/activate  # Linux/Mac için
# venv\Scripts\activate  # Windows için

# Bağımlılıkları yükleme
pip install -r requirements.txt

# .env dosyasını oluşturma
cp .env.example .env
# .env dosyasını düzenleyin

# Veritabanı migrasyonlarını çalıştırma
alembic upgrade head

# Uygulamayı başlatma
uvicorn app.main:app --reload
```

## API Dokümantasyonu

Uygulama çalıştıktan sonra API dokümantasyonuna aşağıdaki URL'lerden erişebilirsiniz:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Proje Yapısı

```
.
├── alembic/              # Veritabanı migrasyon dosyaları
├── app/                  # Ana uygulama paketi
│   ├── api/              # API endpoint'leri
│   │   ├── auth/         # Kimlik doğrulama endpoint'leri
│   │   ├── users/        # Kullanıcı endpoint'leri
│   │   └── deps.py       # Bağımlılık enjeksiyonu
│   ├── core/             # Çekirdek modüller
│   │   ├── config.py     # Uygulama yapılandırması
│   │   ├── security.py   # Güvenlik işlevleri
│   │   └── exceptions.py # Özel istisnalar
│   ├── db/               # Veritabanı
│   │   ├── base.py       # Temel veritabanı işlevleri
│   │   └── session.py    # Veritabanı oturumu
│   ├── models/           # SQLAlchemy modelleri
│   ├── schemas/          # Pydantic şemaları
│   ├── services/         # İş mantığı servisleri
│   │   ├── auth.py       # Kimlik doğrulama servisi
│   │   ├── email.py      # E-posta servisi
│   │   └── user.py       # Kullanıcı servisi
│   └── main.py           # Uygulama giriş noktası
├── tests/                # Test dosyaları
├── .env                  # Ortam değişkenleri
├── .env.example          # Örnek ortam değişkenleri
├── alembic.ini           # Alembic yapılandırması
└── requirements.txt      # Bağımlılıklar
```