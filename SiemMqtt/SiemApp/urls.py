from django.urls import path
from .views import main_page, get_logs  # Import the correct views

urlpatterns = [
    path('', main_page, name='main_page'),  # Homepage now shows logs in HTML
    path('api/logs/', get_logs, name='get_logs'),  # API for logs
]
