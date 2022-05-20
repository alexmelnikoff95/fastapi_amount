from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from ..import models

from ..services.auth import AuthService, get_current_user

router = APIRouter(prefix='/auth', tags=['auth'])


@router.post('/sign-up/', response_model=models.Token, status_code=status.HTTP_201_CREATED)
def sign_up(user_data: models.UserCreate, service: AuthService = Depends()):
    return service.register_new_user(user_data)


@router.post('/sign-in/', response_model=models.Token)
def sign_in(form_data: OAuth2PasswordRequestForm = Depends(), service: AuthService = Depends()):
    return service.authenticated_user(form_data.username, form_data.password)


@router.get('/user/', response_model=models.User)
def get_user(user: models.User = Depends(get_current_user)):
    return user
