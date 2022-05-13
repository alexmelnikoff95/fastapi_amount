from fastapi import FastAPI
from .api import router

tags_metadata = [

    {
        'name': 'operations',
        'description': 'Создание, редактирование, удаление и просмотр операций',
    }
]

app = FastAPI(
    title='FastApi_Amount',
    description='Сервис учета личных доходов и расходов',
    version='1.0.0',
    openapi_tags=tags_metadata,
)
app.include_router(router)
