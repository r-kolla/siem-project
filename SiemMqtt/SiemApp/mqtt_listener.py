import os
import django
import sys
import json
import paho.mqtt.client as mqtt
from datetime import datetime, timezone  

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")
django.setup()

from SiemApp.models import Log  

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode()
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "topic": msg.topic,
            "message": "",
            "qos": msg.qos,
            "retain": msg.retain,
            "publisher_id": "unknown"  # Default if no publisher info
        }

        # Attempt to parse JSON if available
        try:
            json_payload = json.loads(payload)
            log_entry["message"] = json_payload.get("message", payload)
            log_entry["publisher_id"] = json_payload.get("publisher_id", "unknown")
        except json.JSONDecodeError:
            log_entry["message"] = payload  # Store raw message

        print(f"Received Log: {log_entry}")  

        Log.objects.create(
            timestamp=log_entry["timestamp"],
            topic=log_entry["topic"],
            message=log_entry["message"],
            qos=log_entry["qos"],
            retain=log_entry["retain"],
            publisher_id=log_entry["publisher_id"]
        )

    except Exception as e:
        print(f"Error processing MQTT message: {e}")

client = mqtt.Client(client_id="SIEM_Listener")  # This ID should only be for the listener
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("#")  # Subscribing to all subtopics under iot/logs

print("MQTT Listener Started...")
client.loop_forever()
