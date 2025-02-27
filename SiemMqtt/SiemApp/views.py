from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Log

@api_view(['GET'])
def get_logs(request):
    logs = Log.objects.all().order_by('-timestamp')[:50]  # Latest 50 logs
    return Response({
        "logs": [
            {
                "timestamp": log.timestamp,
                "topic": log.topic,
                "publisher_id": log.publisher_id,  # Added publisher_id
                "message": log.message,
                "qos": log.qos,
                "retain": log.retain
            } 
            for log in logs
        ]
    })

def main_page(request):
    logs = Log.objects.all().order_by('-timestamp')[:50]  # Show latest 50 logs
    return render(request, "index.html", {"logs": logs})
