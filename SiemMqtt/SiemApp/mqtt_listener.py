import asyncio
import os
import django
import sys
import paho.mqtt.client as mqtt

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Correctly set Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")  
django.setup()

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from SiemApp.models import Log  

# MQTT callback function
def on_message(client, userdata, msg):
    log_message = msg.payload.decode()
    print(f"Received Log: {log_message}")

    # Save log to database
    Log.objects.create(message=log_message)

    # Send message to WebSocket group
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "logs",
        {
            "type": "log_message",
            "message": log_message
        }
    )

# Set up MQTT client
client = mqtt.Client()
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("iot/logs")

print("MQTT Listener Started...")
client.loop_forever()
