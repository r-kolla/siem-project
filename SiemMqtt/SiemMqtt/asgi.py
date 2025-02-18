import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
from SiemApp import consumers
from SiemMqtt import SiemApp


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SiemMqtt.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(SiemApp.routing.websocket_urlpatterns)
    ),
})