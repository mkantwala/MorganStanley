from pydantic_settings import BaseSettings

class Settings(BaseSettings):

    PROJECT_NAME: str = "Morgan Stanley Vulnerability Scanner"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10

    JWT_ALGORITHM: str = "HS256"
    JWT_SECRET: str = "morganstanley"

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    RATE_LIMIT_MAX_REQUESTS: int = 5
    RATE_LIMIT_WINDOW: int = 60

    CACHE_EXPIRE: int = 3600






settings = Settings()