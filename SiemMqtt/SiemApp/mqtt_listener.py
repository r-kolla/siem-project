import os
import django
import sys
import json
import paho.mqtt.client as mqtt
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")
django.setup()

from SiemApp.models import Log  

channel_layer = get_channel_layer()

def on_message(client, userdata, msg):
    log_message = msg.payload.decode()
    print(f"Received Log: {log_message}")
    Log.objects.create(message=log_message)
    
    async_to_sync(channel_layer.group_send)(
        "logs",
        {"type": "send_log", "message": log_message}
    )

client = mqtt.Client()
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("iot/logs")

print("MQTT Listener Started...")
client.loop_forever()
