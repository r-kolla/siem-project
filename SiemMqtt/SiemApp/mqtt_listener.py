import os
import django
import sys
import json
import logging
import paho.mqtt.client as mqtt
from datetime import datetime, timezone, timedelta
import smtplib
from email.mime.text import MIMEText
import socket
from collections import defaultdict, deque
import time
import threading




# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")
django.setup()
from SiemApp.models import Log, Device

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
AUTHORIZED_DEVICES = ["device_1", "device_2", "Batmans-MBAir", "Batmans-MBAisrs.local"]
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



FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=1)

failed_logins = defaultdict(list)  # Tracks failed logins per (IP, Publisher ID)

def detect_suspicious_activity(log_entry):
    ip = log_entry.get("ip", None)
    publisher_id = log_entry.get("publisher_id", None)
    
    if not ip or not publisher_id:
        return False  # Skip if missing data

    # Check for failed login attempt in message
    if "connection refused" in log_entry.get("message", "").lower():
        now = datetime.now(timezone.utc)  # Ensure timezone awareness
        failed_logins[(ip, publisher_id)].append(now)

        # Remove entries older than 1 minute
        failed_logins[(ip, publisher_id)] = [
            timestamp for timestamp in failed_logins[(ip, publisher_id)] 
            if now - timestamp < FAILED_LOGIN_WINDOW
        ]

        failed_count = len(failed_logins[(ip, publisher_id)])
        logging.warning(f"⚠️ Failed login from {ip} ({publisher_id}) - Attempt {failed_count}")

        if failed_count >= FAILED_LOGIN_THRESHOLD:
            threat_details = (
                f"🚨 Multiple failed login attempts from {ip} ({publisher_id})!\n"
                f"Total failed attempts in the last minute: {failed_count}"
            )
            logging.error(threat_details)
            send_notification({
                "timestamp": now.isoformat(),
                "ip": ip,
                "publisher_id": publisher_id,
                "message": threat_details,
            })
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
        payload = msg.payload.decode().strip()
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "topic": msg.topic,
            "message": payload,  # Default to raw payload
            "qos": msg.qos,
            "retain": msg.retain,
            "publisher_id": userdata.get("client_id", "unknown"),
            "ip": "",
            "device_id": ""
        }

        # Attempt to parse JSON if valid
        if payload:
            try:
                json_payload = json.loads(payload)
                log_entry["message"] = json_payload.get("message", payload)
                log_entry["publisher_id"] = json_payload.get("client_id", log_entry["publisher_id"])
            except json.JSONDecodeError:
                pass  # Keep raw payload as message if JSON parsing fails

        # Extract sender details
        sender_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        sender_device = socket.gethostname()
        
        log_entry["ip"] = sender_ip
        log_entry["device_id"] = sender_device

        logging.info(f"📥 Received Log: {log_entry}")

        # Save Log to Database
        try:
            Log.objects.create(
                timestamp=log_entry["timestamp"],
                topic=log_entry["topic"],
                message=log_entry["message"],
                qos=log_entry["qos"],
                retain=log_entry["retain"],
                publisher_id=log_entry["publisher_id"],
                ip=log_entry["ip"]
            )
        except Exception as e:
            logging.error(f"❌ Error saving log to database: {e}")
    
    except Exception as e:
        logging.error(f"❌ Error processing MQTT message: {e}")
# Setup MQTT Client



MOSQUITTO_LOG_FILE = "/opt/homebrew/var/log/mosquitto/mosquitto.log"
UNAUTHORIZED_ATTEMPTS = {}

def monitor_mosquitto_logs():
    while True:
        try:
            with open(MOSQUITTO_LOG_FILE, "r", errors="ignore") as logfile:
                logfile.seek(0, os.SEEK_END)  # Start at the end of the file
                while True:
                    line = logfile.readline()
                    if not line:
                        time.sleep(1)  # Adjusted to avoid excessive CPU usage
                        continue
                    
                    if "disconnected, not authorised" in line:
                        process_unauthorized_login(line)
        except Exception as e:
            logging.error(f"❌ Error reading Mosquitto log file: {e}")
            time.sleep(5)  # Wait before retrying in case of file errors



logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - [%(levelname)s] - %(message)s")

# Constants
FAILED_ATTEMPT_WINDOW = 60  # Time window in seconds
MAX_FAILED_ATTEMPTS = 5 # Threshold for triggering an alert
UNAUTHORIZED_ATTEMPTS = {}  # Tracks failed login attempts per IP

def process_unauthorized_login(log_line):
    parts = log_line.split()
    
    try:
        # Extract timestamp safely
        timestamp_str = parts[0].strip(":")
        timestamp = int(timestamp_str) if timestamp_str.isdigit() else int(datetime.now(timezone.utc).timestamp())
        
        # Extract client ID and IP
        client_id = parts[2] if len(parts) > 2 else "unknown_client"
        ip = parts[3] if len(parts) > 3 else "127.0.0.1"  # Default to local IP

        logging.info(f"🔍 Processing login attempt: Client={client_id}, IP={ip}, Timestamp={timestamp}")

        # Track failed attempts
        if ip not in UNAUTHORIZED_ATTEMPTS:
            UNAUTHORIZED_ATTEMPTS[ip] = deque()
        
        attempts = UNAUTHORIZED_ATTEMPTS[ip]
        attempts.append(timestamp)

        # Remove old attempts outside the window
        while attempts and attempts[0] < timestamp - FAILED_ATTEMPT_WINDOW:
            attempts.popleft()

        logging.info(f"📊 Failed login count for {ip}: {len(attempts)}")

        # Check if threshold is reached
        if len(attempts) >= MAX_FAILED_ATTEMPTS:
            logging.error(f"🚨 Unauthorized login detected from {client_id} @ {ip} ({MAX_FAILED_ATTEMPTS} attempts in {FAILED_ATTEMPT_WINDOW} sec)")
            
            send_notification({
                "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                "ip": ip,
                "publisher_id": client_id,
                "message": f"Multiple failed login attempts detected from {client_id} @ {ip}"
            })
            attempts.clear()  # Reset after sending alert

    except Exception as e:
        logging.error(f"❌ Error processing log line: {log_line} | {e}")



client = mqtt.Client(client_id=MQTT_CLIENT_ID, userdata={"client_id": MQTT_CLIENT_ID}, protocol=mqtt.MQTTv311)
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

# Connect to MQTT Broker
try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    logging.info("📡 MQTT Listener Started...")
    log_monitor_thread = threading.Thread(target=monitor_mosquitto_logs, daemon=True)
    log_monitor_thread.start()
    client.loop_forever()
except Exception as e:
    logging.error(f"❌ Failed to connect to MQTT broker: {e}")