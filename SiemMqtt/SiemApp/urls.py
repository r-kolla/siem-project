from django.urls import path
from .views import update_device_status, device_list, logs_view, threats_list, threats_page, rules_page

urlpatterns = [
    path('devices/<str:action>/<int:device_id>/', update_device_status, name='update_device_status'),
    path("devices/", device_list, name="device_list"),
    path('logs/', logs_view, name='logs'),
    path("api/threats/", threats_list, name="threats-list"),
    path("threats/", threats_page, name="threats_page"),
    path("rules/", rules_page, name="rules_page"), 
]
