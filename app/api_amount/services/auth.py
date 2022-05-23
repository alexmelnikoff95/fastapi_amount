from datetime import datetime, timedelta
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.hash import bcrypt
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from .. import tables
from ..settings import settings
from .. import models
from ..database import get_session

oauth = OAuth2PasswordBearer(tokenUrl='/auth/sign-in/')

'''Метод для чтения токена'''


def get_current_user(token: str = Depends(oauth)) -> models.User:
    return AuthService.validate(token)


class AuthService:

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        '''метод для создания чистого пароля и хэша'''
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        '''Метод для хэширования пароля'''
        return bcrypt.hash(password)

    @classmethod
    def validate(cls, token: str) -> models.User:
        '''Валидатор пользователя'''
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='no valid',
                                  headers={'WWW-Authenticate': 'bearer'}, )

        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = models.User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: tables.User) -> models.Token:
        '''Метод создания токена для пользователя'''
        user_data = models.User.from_orm(user)

        now = datetime.utcnow()

        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }

        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

        return models.Token(access_token=token)

    '''Методы для работы с БД'''

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: models.UserCreate) -> models.Token:
        user = tables.User(email=user_data.email, username=user_data.username,
                           password_hash=self.hash_password(user_data.password))

        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    '''Регистрация пользователя'''

    def authenticated_user(self, username: str, password: str) -> models.Token:
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                  detail='неверный пароль или имя пользователя',
                                  headers={'WWW-Authenticate': 'bearer'}, )

        user = (self.session.query(tables.User).filter(tables.User.username == username).first())

        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)
