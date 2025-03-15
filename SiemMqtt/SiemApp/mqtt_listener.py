import os
import django
import sys
import json
import logging
import paho.mqtt.client as mqtt
from datetime import datetime, timezone  
import smtplib
from email.mime.text import MIMEText
import socket

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")
django.setup()

from SiemApp.models import Log  

# Logging Configuration
logging.basicConfig(
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)]
)

# MQTT Configuration
MQTT_BROKER = "127.0.0.1"
MQTT_PORT = 8885
MQTT_USERNAME = "revanthkolla"
MQTT_PASSWORD = "bananas"
MQTT_CLIENT_ID = "SIEM_Listener"

# Security Settings
AUTHORIZED_DEVICES = ["device_1", "device_2", "Batmans-MBAir", "Batmans-MBAir.local"]
FAILED_LOGIN_THRESHOLD = 5
failed_logins = {}

# SMTP Configuration
SMTP_SERVER = "smtp.zoho.in"
SMTP_PORT = 465
SMTP_USERNAME = "revanthkolla@zohomail.in"
SMTP_PASSWORD = "yttYLSn5Sirh"  # Use correct ASP

def send_notification(log_entry):
    sender = SMTP_USERNAME
    recipient = "revanthkolla2@gmail.com"
    subject = "SIEM Alert: Threat Detected"
    
    body = f"🚨 SIEM Alert Detected 🚨\n\n"
    body += f"Timestamp: {log_entry.get('timestamp', 'N/A')}\n"
    body += f"Topic: {log_entry.get('topic', 'N/A')}\n"
    body += f"Message: {log_entry.get('message', 'N/A')}\n"
    body += f"QoS: {log_entry.get('qos', 'N/A')}\n"
    body += f"Retain: {log_entry.get('retain', 'N/A')}\n"
    body += f"Publisher ID: {log_entry.get('publisher_id', 'N/A')}\n"
    body += f"IP Address: {log_entry.get('ip', 'N/A')}\n"
    body += f"Device ID: {log_entry.get('device_id', 'N/A')}\n\n"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)  
            server.sendmail(sender, recipient, msg.as_string())
            logging.info("📧 Detailed log notification sent successfully.")
    except Exception as e:
        logging.error(f"❌ Failed to send notification: {e}")

def detect_suspicious_activity(log_entry):
    ip = log_entry.get("ip", None)
    if ip and "failed login" in log_entry.get("message", "").lower():
        failed_logins[ip] = failed_logins.get(ip, 0) + 1
        logging.warning(f"⚠️ Failed login attempt detected from {ip}. Total attempts: {failed_logins[ip]}")

        if failed_logins[ip] >= FAILED_LOGIN_THRESHOLD:
            threat_details = f"Multiple failed login attempts detected from IP {ip} (Threshold: {FAILED_LOGIN_THRESHOLD})."
            logging.error(threat_details)
            send_notification(threat_details)
            return True
    return False

def track_active_devices(log_entry):
    device_id = log_entry.get("device_id", "unknown")
    if device_id not in AUTHORIZED_DEVICES:
        threat_details = f"Unauthorized device detected: {device_id}"
        logging.error(threat_details)
        send_notification(threat_details)
        return True
    return False

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logging.info("✅ Connected to MQTT broker successfully.")
        client.subscribe("#")
    else:
        logging.error(f"❌ Connection failed with error code {rc}")

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode()
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "topic": msg.topic,
            "message": "",
            "qos": msg.qos,
            "retain": msg.retain,
            "publisher_id": userdata.get("client_id", "unknown"),
            "ip": "",
            "device_id": ""
        }

        try:
            json_payload = json.loads(payload)
            log_entry["message"] = json_payload.get("message", payload)
            log_entry["publisher_id"] = json_payload.get("client_id", userdata.get("client_id", "unknown"))
        except json.JSONDecodeError:
            log_entry["message"] = payload  

        # Extract sender details
        sender_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        sender_device = socket.gethostname()
        
        log_entry["ip"] = sender_ip
        log_entry["device_id"] = sender_device

        logging.info(f"📥 Received Log: {log_entry}")

        if detect_suspicious_activity(log_entry):
            logging.warning("🚨 Suspicious activity detected! Notification sent.")

        if track_active_devices(log_entry):
            logging.warning("🚨 Unauthorized device detected! Notification sent.")

        # Save Log to Database
        try:
            Log.objects.create(
                timestamp=log_entry["timestamp"],
                topic=log_entry["topic"],
                message=log_entry["message"],
                qos=log_entry["qos"],
                retain=log_entry["retain"],
                publisher_id=log_entry["publisher_id"]
            )
        except Exception as e:
            logging.error(f"❌ Error saving log to database: {e}")
    except Exception as e:
        logging.error(f"❌ Error processing MQTT message: {e}")

# Setup MQTT Client
client = mqtt.Client(client_id=MQTT_CLIENT_ID, userdata={"client_id": MQTT_CLIENT_ID}, protocol=mqtt.MQTTv311)
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

# Connect to MQTT Broker
try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    logging.info("📡 MQTT Listener Started...")
    client.loop_forever()
except Exception as e:
    logging.error(f"❌ Failed to connect to MQTT broker: {e}")
