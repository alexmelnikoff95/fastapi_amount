from fastapi import APIRouter

router = APIRouter(prefix='/auth,')


@router.post('/sign-up')
def sing_up():
    pass


@router.post('/sign-in')
def sign_in():
    pass
