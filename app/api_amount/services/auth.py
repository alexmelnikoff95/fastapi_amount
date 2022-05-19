from datetime import datetime, timedelta

from passlib.hash import bcrypt
from jose import jwt, JWTError
from pydantic import ValidationError
from starlette import status
from sqlalchemy.orm import Session

from ..database import get_session
from ..models.auth import User, Token, UserCreate
from ..settings import Settings
from .. import tables
from fastapi import HTTPException, Depends




class AuthService():
    '''создаем открытый пароль и хэш к паролю'''

    @classmethod
    def verify_password(cls, password_clean: str, hashed_password: str) -> bool:
        bcrypt.verify(password_clean, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate(cls, token: str) -> User:
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='no valid',
                                  headers={'WWW-Authenticate': 'bearer'}, )

        try:
            payload = jwt.decode(token, Settings.jwt_secret, algorithms=[Settings.jwt_algorithm])
        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = User.pars_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: tables.User) -> Token:
        '''Создание Токена'''
        user_data = User.from_orm(user)

        now = datetime.utcnow()

        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=Settings.jwt_time),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }

        token = jwt.encode(payload, Settings.jwt_secret, algorithm=Settings.jwt_algorithm)

        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_user(self, user_data: UserCreate) -> Token:
        user = tables.User(email=user_data.email, username=user_data.username,
                           password_hash=self.hash_password(user_data.password))

        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def authenticated_user(self, username: str, password: str) -> Token:
        exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                  detail='неверный пароль или имя пользователя',
                                  headers={'WWW-Authenticate': 'bearer'}, )
        user = (
            self.session.query(tables.User)
                .filter(tables.User.username == username)
                .first()
        )

        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)
