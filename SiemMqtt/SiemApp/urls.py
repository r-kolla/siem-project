from django import views
from django.urls import path
from .views import export_logs, log_detail, threat_detail_api, threats, update_device_status, device_list, logs_view, threats_list, threats_page, rules_page, rules, add_rule, edit_rule, delete_rule, update_threat_status
from django.views.generic import TemplateView

urlpatterns = [
    path('devices/<str:action>/<int:device_id>/', update_device_status, name='update_device_status'),
    path("devices/", device_list, name="device_list"),
    path('logs/', logs_view, name='logs'),
    #path("api/threats/", threats_list, name="threats-list"),
    #path("threats/", threats_page, name="threats_page"),
    #path("rules/", rules_page, name="rules_page"), 
    path('log/<int:log_id>/', log_detail, name='log_detail'),
    path('export-logs/', export_logs, name='export_logs'),
    path('rules/', rules, name='rules'),
    path('rules/add/', add_rule, name='add_rule'),
    path('rules/edit/<int:rule_id>/', edit_rule, name='edit_rule'),
    path('rules/delete/<int:rule_id>/', delete_rule, name='delete_rule'),
    path('threats/', threats, name='threats'),
    path('api/threats/<int:threat_id>/', threat_detail_api, name='threat_detail_api'),
    path('api/threats/<int:threat_id>/status/', update_threat_status, name='update_threat_status'),
]
