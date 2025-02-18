import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path
from SiemApp import consumers


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            path("ws/logs/", consumers.LogConsumer.as_asgi()),  # Ensure LogConsumer exists
        ])
    ),
})