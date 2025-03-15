import paho.mqtt.client as mqtt
import json

# MQTT Configuration
MQTT_BROKER = "127.0.0.1"
MQTT_PORT = 8885
MQTT_TOPIC = "test/topic"
MQTT_USERNAME = "testuser"
MQTT_PASSWORD = "test"

# Create MQTT Client with Explicit Protocol Version
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)  # Avoids deprecation warning
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

# Connect to Broker
client.connect(MQTT_BROKER, MQTT_PORT, 60)

# Payload with IP and Device ID
payload = {
    "message": "hello",
    "ip": "127.0.0.1",
    "device_id": "Batmans-MBAir.local"
}

# Publish Message
print(f"Publishing: {payload}")
client.publish(MQTT_TOPIC, json.dumps(payload))

# Disconnect Client
client.disconnect()
