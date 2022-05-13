import uvicorn

from settings import settings

uvicorn.run(
    'api_amount.app:app',
    host=settings.server_host,
    port=settings.server_port,
    reload=True,
)
