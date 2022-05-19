from pydantic import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    server_host: str = '127.0.0.1'
    server_port: int = 8000

    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_time: int = 3600


@lru_cache()
def settings():
    return Settings(_env_file='.env',
                    _env_file_encoding='utf-8')
