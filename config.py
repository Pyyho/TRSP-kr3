from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MODE: str = "DEV"  # DEV or PROD
    DOCS_USER: str = "admin"
    DOCS_PASSWORD: str = "secret123"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_SECRET_KEY: str = "your-jwt-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 30

    class Config:
        env_file = ".env"


settings = Settings()