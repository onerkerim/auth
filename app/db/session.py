from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# SQLAlchemy veritabanı motoru oluşturma
engine = create_engine(settings.DATABASE_URL)

# Veritabanı oturumu oluşturma
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Temel model sınıfı
Base = declarative_base()

# Bağımlılık enjeksiyonu için veritabanı oturumu alma fonksiyonu
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()