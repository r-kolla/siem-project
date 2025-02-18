from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Log


@api_view(['GET'])
def get_logs(request):
    logs = Log.objects.all().order_by('-timestamp')[:50]  # Latest 50 logs
    return Response({"logs": [{"timestamp": log.timestamp, "message": log.message} for log in logs]})

def logs_view(request):
    logs = Log.objects.all().order_by('-id')[:50]  # Fetch latest 50 logs
    return render(request, "logs.html", {"logs": logs})