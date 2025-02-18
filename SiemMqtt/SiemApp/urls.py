from . import views
from django.urls import path
from .views import get_logs


urlpatterns = [
    path('', get_logs),
    path('logs', views.logs_view, name='logs'),
]