from pydantic_settings import BaseSettings

class Settings(BaseSettings):

    PROJECT_NAME: str = "Morgan Stanley Vulnerability Scanner"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10

    JWT_ALGORITHM: str = "HS256"
    JWT_SECRET: str = "morganstanley"




settings = Settings()