import os
import re
import django
import sys
import json
import logging
import paho.mqtt.client as mqtt
from datetime import datetime, timezone, timedelta
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict, deque
import time
import threading
from statistics import mean, stdev
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SiemMqtt.settings")
django.setup()

from SiemApp.models import Log, Rule, Threat, Alert, Device

# Logging Configuration
logging.basicConfig(
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)]
)

# MQTT Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 8885
MQTT_USERNAME = "revanthkolla"
MQTT_PASSWORD = "bananas"
MQTT_CLIENT_ID = "SIEM_Listener"
CA_CERT_PATH = "/opt/homebrew/etc/mosquitto/certs/ca.crt"
CLIENT_CERT_PATH = "/opt/homebrew/etc/mosquitto/certs/client.crt"
CLIENT_KEY_PATH = "/opt/homebrew/etc/mosquitto/certs/client.key"

# Security Settings
FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW = timedelta(minutes=5)
failed_logins = defaultdict(list)

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
    for key, value in log_entry.items():
        body += f"{key}: {value}\n"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    logging.info(f"📧 Attempting to send email to {recipient}")
    
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            logging.info(f"📧 Connected to SMTP server {SMTP_SERVER}:{SMTP_PORT}")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            logging.info(f"📧 Logged in to SMTP server")
            server.sendmail(sender, recipient, msg.as_string())
            logging.info(f"📧 Email sent successfully to {recipient}")
    except Exception as e:
        logging.error(f"❌ Failed to send notification: {str(e)}")
        logging.error(f"❌ Email details: From={sender}, To={recipient}, Subject={subject}")
        # Print the full exception info for debugging
        import traceback
        logging.error(traceback.format_exc())

def detect_suspicious_activity(log_entry):
    ip = log_entry.get("ip")
    publisher_id = log_entry.get("publisher_id")
    message = log_entry.get("message", "").lower()
    now = datetime.now(timezone.utc)

    if "connection refused" in message:
        failed_logins[(ip, publisher_id)].append(now)

        # Remove old attempts
        failed_logins[(ip, publisher_id)] = [
            t for t in failed_logins[(ip, publisher_id)] if now - t < FAILED_LOGIN_WINDOW
        ]

        if len(failed_logins[(ip, publisher_id)]) >= FAILED_LOGIN_THRESHOLD:
            logging.error(f"🚨 Brute force attack detected from {ip} ({publisher_id})!")

            log = Log.objects.create(**log_entry)

            rule, _ = Rule.objects.get_or_create(name="Brute Force Attack")

            threat = Threat.objects.create(log=log, rule=rule)
            alert = Alert.objects.create(threat=threat, message=f"Threat detected: {rule.name}", status="pending")

            send_notification(log_entry)
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
        timestamp = datetime.now(timezone.utc)
        payload = msg.payload.decode().strip()
        log_entry = {
            "timestamp": timestamp,
            "topic": msg.topic,
            "message": payload,
            "qos": msg.qos,
            "retain": msg.retain,
            "publisher_id": "unknown",  # Default value to prevent null
            "ip": None,
            "device": None,
        }
        
        # Extract sender IP
        device_found = False
        try:
            if hasattr(client, "_sock") and client._sock:
                ip = client._sock.getpeername()[0]
                log_entry["ip"] = ip
                
                # Check if the device exists and is authorized
                try:
                    device = Device.objects.get(ip_address=ip)
                    log_entry["device"] = device
                    device_found = True
                    
                    # ACL Check - If device is not authorized, treat as violation
                    if not device.is_authorized:
                        logging.warning(f"⚠️ ACL Violation: Unauthorized device {device} attempted to publish to {msg.topic}")
                        
                        # Save log for record
                        log = Log.objects.create(**log_entry)
                        
                        # Create threat and alert
                        rule, _ = Rule.objects.get_or_create(
                            name="ACL Violation",
                            defaults={
                                "description": "Device with revoked authorization attempted to publish",
                                "pattern": "unauthorized_access",
                                "severity": 3
                            }
                        )
                        
                        threat = Threat.objects.create(log=log, rule=rule)
                        alert = Alert.objects.create(
                            threat=threat, 
                            message=f"Unauthorized device {device} attempted to publish to {msg.topic}", 
                            status="pending"
                        )
                        
                        # Send notification
                        notification_data = {
                            "timestamp": log_entry["timestamp"].isoformat(),
                            "ip": str(ip),
                            "device": str(device),
                            "topic": msg.topic,
                            "message": payload,
                            "alert_type": "ACL Violation"
                        }
                        send_notification(notification_data)
                        
                        # Return early - don't process this message further
                        return
                        
                except Device.DoesNotExist:
                    logging.warning(f"⚠️ Unknown device with IP {ip} published to {msg.topic}")
                    
                    # Generate an alert for unknown devices - treat as unauthorized access
                    log = Log.objects.create(**log_entry)
                    
                    rule, _ = Rule.objects.get_or_create(
                        name="Unauthorized Access",
                        defaults={
                            "description": "Unknown/unregistered device attempting to publish",
                            "pattern": "unauthorized_access",
                            "severity": 3
                        }
                    )
                    
                    threat = Threat.objects.create(log=log, rule=rule)
                    alert = Alert.objects.create(
                        threat=threat, 
                        message=f"Unknown device with IP {ip} published to {msg.topic}", 
                        status="pending"
                    )
                    
                    # Send notification
                    notification_data = {
                        "timestamp": log_entry["timestamp"].isoformat(),
                        "ip": str(ip),
                        "topic": msg.topic,
                        "message": payload,
                        "alert_type": "Unauthorized Access"
                    }
                    logging.info(f"📧 Sending notification for unknown device: {notification_data}")
                    send_notification(notification_data)
                
        except Exception as e:
            logging.warning(f"⚠️ Could not retrieve sender IP: {e}")
        
        # Parse JSON payload if possible
        try:
            json_payload = json.loads(payload)
            log_entry["message"] = json_payload.get("message", payload)
            
            publisher_id = json_payload.get("client_id")
            if isinstance(publisher_id, int):
                log_entry["publisher_id"] = publisher_id
            elif isinstance(publisher_id, str) and publisher_id.isdigit():
                log_entry["publisher_id"] = int(publisher_id)
                
            # If we haven't found a device by IP, try to find by device ID
            if not device_found and "device_id" in json_payload:
                device_id = json_payload.get("device_id")
                if device_id:
                    try:
                        device = Device.objects.get(id=device_id)
                        log_entry["device"] = device
                        device_found = True
                        
                        # Check authorization status
                        if not device.is_authorized:
                            logging.warning(f"⚠️ ACL Violation: Unauthorized device ID {device_id} attempted to publish")
                            
                            # Create log, threat, and alert
                            log = Log.objects.create(**log_entry)
                            
                            rule, _ = Rule.objects.get_or_create(
                                name="ACL Violation",
                                defaults={
                                    "description": "Device with revoked authorization attempted to publish",
                                    "pattern": "unauthorized_access",
                                    "severity": 3
                                }
                            )
                            
                            threat = Threat.objects.create(log=log, rule=rule)
                            alert = Alert.objects.create(
                                threat=threat, 
                                message=f"Unauthorized device {device} attempted to publish to {msg.topic}", 
                                status="pending"
                            )
                            
                            # Send notification
                            notification_data = {
                                "timestamp": log_entry["timestamp"].isoformat(),
                                "device_id": device_id,
                                "device": str(device),
                                "topic": msg.topic,
                                "message": payload,
                                "alert_type": "ACL Violation"
                            }
                            send_notification(notification_data)
                            
                            # Return early
                            return
                            
                    except Device.DoesNotExist:
                        pass
                        
        except json.JSONDecodeError:
            logging.warning("⚠️ Failed to parse JSON payload.")
        
        # DoS Detection
        if log_entry["ip"]:
            is_dos, rate = detect_dos_attack(
                msg.topic, 
                log_entry["ip"], 
                log_entry.get("publisher_id", "unknown"), 
                timestamp
            )
            
            if is_dos:
                # Save log
                log = Log.objects.create(**log_entry)
                
                # Create DoS threat
                rule, _ = Rule.objects.get_or_create(
                    name="DoS Attack",
                    defaults={
                        "description": "High message rate indicating possible DoS attack",
                        "pattern": "high_frequency",
                        "severity": 4  # Critical
                    }
                )
                
                threat = Threat.objects.create(log=log, rule=rule)
                alert = Alert.objects.create(
                    threat=threat, 
                    message=f"Possible DoS attack from {log_entry['ip']} at rate {rate:.2f} msgs/min", 
                    status="pending"
                )
                
                # Send notification
                notification_data = {
                    "timestamp": log_entry["timestamp"].isoformat(),
                    "ip": str(log_entry["ip"]),
                    "topic": msg.topic,
                    "rate": f"{rate:.2f} msgs/min",
                    "alert_type": "DoS Attack"
                }
                send_notification(notification_data)
        
        # Behavior Anomaly Detection
        if log_entry["device"]:
            is_anomaly, reason = detect_behavior_anomaly(
                log_entry["device"],
                msg.topic,
                log_entry["message"],
                timestamp
            )
            
            if is_anomaly:
                # Save log
                log = Log.objects.create(**log_entry)
                
                # Create anomaly threat
                rule, _ = Rule.objects.get_or_create(
                    name="Behavior Anomaly",
                    defaults={
                        "description": "Device behavior deviating from established patterns",
                        "pattern": "behavior_deviation",
                        "severity": 2  # Medium
                    }
                )
                
                threat = Threat.objects.create(log=log, rule=rule)
                alert = Alert.objects.create(
                    threat=threat, 
                    message=f"Behavior anomaly detected for {log_entry['device']}: {reason}", 
                    status="pending"
                )
                
                # Send notification
                notification_data = {
                    "timestamp": log_entry["timestamp"].isoformat(),
                    "device": str(log_entry["device"]),
                    "topic": msg.topic,
                    "reason": reason,
                    "alert_type": "Behavior Anomaly"
                }
                send_notification(notification_data)
        
        logging.info(f"📌 Log Entry Before Insert: {log_entry}")
        
        if log_entry.get("publisher_id") is None:
            log_entry["publisher_id"] = "unknown"
            
        # Save log to the database for normal (non-threat) messages
        log = Log.objects.create(**log_entry)
        logging.info(f"✅ Log saved: {log.id}")
        
    except Exception as e:
        logging.error(f"🔥 Error in on_message: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())




MOSQUITTO_LOG_FILE = "/opt/homebrew/var/log/mosquitto/mosquitto.log"
UNAUTHORIZED_ATTEMPTS = {}

def monitor_mosquitto_logs():
    while True:
        try:
            with open(MOSQUITTO_LOG_FILE, "r", errors="ignore") as logfile:
                logfile.seek(0, os.SEEK_END)
                while True:
                    line = logfile.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    if "disconnected, not authorised" in line:
                        process_unauthorized_login(line)
        except Exception as e:
            logging.error(f"❌ Error reading Mosquitto log file: {e}")
            time.sleep(5)



# Add these global variables for tracking message rates
MESSAGE_RATES = defaultdict(list)
RATE_WINDOW = timedelta(minutes=5)
MESSAGE_HISTORY = defaultdict(list)  # For tracking message patterns
BASELINE_PERIOD = timedelta(days=1)  # Period to establish baseline behavior
ANOMALY_THRESHOLD = 3  # Standard deviations from normal behavior

def detect_dos_attack(topic, ip, publisher_id, timestamp):
    """
    Detect potential DoS attacks by monitoring message frequency
    """
    key = (ip, publisher_id, topic)
    now = timestamp
    
    # Add current timestamp to the list for this key
    MESSAGE_RATES[key].append(now)
    
    # Remove timestamps older than the window
    MESSAGE_RATES[key] = [t for t in MESSAGE_RATES[key] if now - t < RATE_WINDOW]
    
    # Calculate rate (messages per minute)
    rate = len(MESSAGE_RATES[key]) / (RATE_WINDOW.total_seconds() / 60)
    
    # Thresholds could be adjusted based on your specific requirements
    if rate > 100:  # More than 100 messages per minute
        logging.warning(f"🚨 Possible DoS attack detected from {ip} to topic {topic}. Rate: {rate:.2f} msgs/min")
        return True, rate
    
    return False, rate
def detect_behavior_anomaly(device, topic, message, timestamp):
    """
    Detect anomalies in device behavior by comparing to established patterns
    """
    if not device:
        return False, "No device to analyze"
    
    device_key = str(device.id)
    
    # Get historical messages for this device
    history = MESSAGE_HISTORY[device_key]
    
    # Add current message to history
    history.append({
        'timestamp': timestamp,
        'topic': topic,
        'message': message,
        'hour': timestamp.hour
    })
    
    # Remove old messages outside the baseline period
    MESSAGE_HISTORY[device_key] = [
        m for m in history if timestamp - m['timestamp'] < BASELINE_PERIOD
    ]
    
    # We need enough historical data to establish a pattern
    if len(history) < 10:
        return False, "Insufficient history to detect anomalies"
    
    # ANALYSIS EXAMPLES - customize these based on your specific needs
    
    # 1. Unusual hour of activity
    hour_counts = defaultdict(int)
    for msg in history[:-1]:  # All but current message
        hour_counts[msg['hour']] += 1
    
    # Convert to probability distribution
    total = sum(hour_counts.values())
    hour_probs = {h: count/total for h, count in hour_counts.items()}
    
    current_hour = timestamp.hour
    # If device rarely or never sends messages at this hour
    if hour_probs.get(current_hour, 0) < 0.05:
        return True, f"Unusual activity hour: Device rarely active at hour {current_hour}"
    
    # 2. Unusual topic for this device
    topic_counts = defaultdict(int)
    for msg in history[:-1]:
        topic_counts[msg['topic']] += 1
    
    # If device has never published to this topic before
    if topic not in topic_counts and len(history) > 20:
        return True, f"Device publishing to new topic {topic}"
    
    # More sophisticated analyses could be added:
    # - Message size anomalies
    # - Message frequency patterns
    # - Content-based anomalies
    # - Time interval patterns
    
    return False, "No anomalies detected"


FAILED_ATTEMPT_WINDOW = 60
MAX_FAILED_ATTEMPTS = 5

def process_unauthorized_login(log_line):
    parts = log_line.split()
    
    try:
        timestamp = int(datetime.now(timezone.utc).timestamp())
        client_id = parts[2] if len(parts) > 2 else "unknown_client"
        ip = parts[3] if len(parts) > 3 else "127.0.0.1"

        logging.info(f"🔍 Processing login attempt: Client={client_id}, IP={ip}")

        if ip not in UNAUTHORIZED_ATTEMPTS:
            UNAUTHORIZED_ATTEMPTS[ip] = deque()
        
        attempts = UNAUTHORIZED_ATTEMPTS[ip]
        attempts.append(timestamp)

        while attempts and attempts[0] < timestamp - FAILED_ATTEMPT_WINDOW:
            attempts.popleft()

        logging.info(f"📊 Failed login count for {ip}: {len(attempts)}")

        if len(attempts) >= MAX_FAILED_ATTEMPTS:
            logging.error(f"🚨 Unauthorized login detected from {client_id} @ {ip}")

            send_notification({
                "timestamp": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                "ip": ip,
                "publisher_id": client_id,
                "message": f"Multiple failed login attempts detected from {client_id} @ {ip}"
            })
            attempts.clear()

    except Exception as e:
        logging.error(f"❌ Error processing log line: {log_line} | {e}")

def check_rule_against_message(rule, topic, message, publisher_id, ip, timestamp):
    """
    Check if a message matches a rule's pattern
    Returns True if the rule is matched, False otherwise
    """
    pattern = rule.pattern
    matched = False
    
    # Check if rule pattern matches
    if pattern.startswith('/') and pattern.endswith('/'):
        # Regex pattern
        regex_pattern = pattern[1:-1]  # Remove the slashes
        try:
            if re.search(regex_pattern, message) or re.search(regex_pattern, topic):
                matched = True
                logging.info(f"📝 Rule '{rule.name}' matched with regex pattern: {regex_pattern}")
        except re.error:
            logging.error(f"❌ Invalid regex pattern in rule {rule.id}: {pattern}")
    
    elif '>' in pattern or '<' in pattern or '==' in pattern:
        # Simple condition (for numeric values)
        try:
            # Try to parse message as JSON or numeric value
            try:
                msg_data = json.loads(message)
                if isinstance(msg_data, dict):
                    # For each key in the JSON, check if it satisfies the condition
                    for key, value in msg_data.items():
                        if isinstance(value, (int, float)):
                            # Construct the condition and evaluate it
                            condition = f"{value} {pattern}"
                            if eval(condition):
                                matched = True
                                logging.info(f"📝 Rule '{rule.name}' matched with numeric condition: {value} {pattern}")
                                break
            except (json.JSONDecodeError, TypeError):
                # Try as simple numeric value
                try:
                    value = float(message)
                    condition = f"{value} {pattern}"
                    if eval(condition):
                        matched = True
                        logging.info(f"📝 Rule '{rule.name}' matched with numeric condition: {value} {pattern}")
                except (ValueError, TypeError):
                    pass
        except Exception as e:
            logging.error(f"❌ Error evaluating condition for rule {rule.id}: {e}")
    
    else:
        # Simple text search
        if pattern in message or pattern in topic:
            matched = True
            logging.info(f"📝 Rule '{rule.name}' matched with text pattern: {pattern}")
    
    # Log severity if matched
    if matched:
        severity_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        severity = severity_map.get(rule.severity, 'Unknown')
        logging.info(f"⚠️ Rule '{rule.name}' ({severity}) matched for topic {topic} from {publisher_id}/{ip}")
    
    return matched

def on_message(client, userdata, msg):
    try:
        timestamp = datetime.now(timezone.utc)
        payload = msg.payload.decode().strip()
        log_entry = {
            "timestamp": timestamp,
            "topic": msg.topic,
            "message": payload,
            "qos": msg.qos,
            "retain": msg.retain,
            "publisher_id": "unknown",  # Default value to prevent null
            "ip": None,
            "device": None,
        }
        
        # Extract sender IP
        device_found = False
        try:
            if hasattr(client, "_sock") and client._sock:
                ip = client._sock.getpeername()[0]
                log_entry["ip"] = ip
                
                # Check if the device exists and is authorized
                try:
                    device = Device.objects.get(ip_address=ip)
                    log_entry["device"] = device
                    device_found = True
                    
                    # ACL Check - If device is not authorized, treat as violation
                    if not device.is_authorized:
                        logging.warning(f"⚠️ ACL Violation: Unauthorized device {device} attempted to publish to {msg.topic}")
                        
                        # Save log for record
                        log = Log.objects.create(**log_entry)
                        
                        # Create threat and alert
                        rule, _ = Rule.objects.get_or_create(
                            name="ACL Violation",
                            defaults={
                                "description": "Device with revoked authorization attempted to publish",
                                "pattern": "unauthorized_access",
                                "severity": 3
                            }
                        )
                        
                        threat = Threat.objects.create(log=log, rule=rule)
                        alert = Alert.objects.create(
                            threat=threat, 
                            message=f"Unauthorized device {device} attempted to publish to {msg.topic}", 
                            status="pending"
                        )
                        
                        # Send notification
                        notification_data = {
                            "timestamp": log_entry["timestamp"].isoformat(),
                            "ip": str(ip),
                            "device": str(device),
                            "topic": msg.topic,
                            "message": payload,
                            "alert_type": "ACL Violation"
                        }
                        send_notification(notification_data)
                        
                        # Return early - don't process this message further
                        return
                        
                except Device.DoesNotExist:
                    logging.warning(f"⚠️ Unknown device with IP {ip} published to {msg.topic}")
                    
                    # Generate an alert for unknown devices - treat as unauthorized access
                    log = Log.objects.create(**log_entry)
                    
                    rule, _ = Rule.objects.get_or_create(
                        name="Unauthorized Access",
                        defaults={
                            "description": "Unknown/unregistered device attempting to publish",
                            "pattern": "unauthorized_access",
                            "severity": 3
                        }
                    )
                    
                    threat = Threat.objects.create(log=log, rule=rule)
                    alert = Alert.objects.create(
                        threat=threat, 
                        message=f"Unknown device with IP {ip} published to {msg.topic}", 
                        status="pending"
                    )
                    
                    # Send notification
                    notification_data = {
                        "timestamp": log_entry["timestamp"].isoformat(),
                        "ip": str(ip),
                        "topic": msg.topic,
                        "message": payload,
                        "alert_type": "Unauthorized Access"
                    }
                    logging.info(f"📧 Sending notification for unknown device: {notification_data}")
                    send_notification(notification_data)
                
        except Exception as e:
            logging.warning(f"⚠️ Could not retrieve sender IP: {e}")
        
        # Parse JSON payload if possible
        try:
            json_payload = json.loads(payload)
            log_entry["message"] = json_payload.get("message", payload)
            
            publisher_id = json_payload.get("client_id")
            if isinstance(publisher_id, int):
                log_entry["publisher_id"] = publisher_id
            elif isinstance(publisher_id, str) and publisher_id.isdigit():
                log_entry["publisher_id"] = int(publisher_id)
                
            # If we haven't found a device by IP, try to find by device ID
            if not device_found and "device_id" in json_payload:
                device_id = json_payload.get("device_id")
                if device_id:
                    try:
                        device = Device.objects.get(id=device_id)
                        log_entry["device"] = device
                        device_found = True
                        
                        # Check authorization status
                        if not device.is_authorized:
                            logging.warning(f"⚠️ ACL Violation: Unauthorized device ID {device_id} attempted to publish")
                            
                            # Create log, threat, and alert
                            log = Log.objects.create(**log_entry)
                            
                            rule, _ = Rule.objects.get_or_create(
                                name="ACL Violation",
                                defaults={
                                    "description": "Device with revoked authorization attempted to publish",
                                    "pattern": "unauthorized_access",
                                    "severity": 3
                                }
                            )
                            
                            threat = Threat.objects.create(log=log, rule=rule)
                            alert = Alert.objects.create(
                                threat=threat, 
                                message=f"Unauthorized device {device} attempted to publish to {msg.topic}", 
                                status="pending"
                            )
                            
                            # Send notification
                            notification_data = {
                                "timestamp": log_entry["timestamp"].isoformat(),
                                "device_id": device_id,
                                "device": str(device),
                                "topic": msg.topic,
                                "message": payload,
                                "alert_type": "ACL Violation"
                            }
                            send_notification(notification_data)
                            
                            # Return early
                            return
                            
                    except Device.DoesNotExist:
                        pass
                        
        except json.JSONDecodeError:
            logging.warning("⚠️ Failed to parse JSON payload.")
        
        # DoS Detection
        if log_entry["ip"]:
            is_dos, rate = detect_dos_attack(
                msg.topic, 
                log_entry["ip"], 
                log_entry.get("publisher_id", "unknown"), 
                timestamp
            )
            
            if is_dos:
                # Save log
                log = Log.objects.create(**log_entry)
                
                # Create DoS threat
                rule, _ = Rule.objects.get_or_create(
                    name="DoS Attack",
                    defaults={
                        "description": "High message rate indicating possible DoS attack",
                        "pattern": "high_frequency",
                        "severity": 4  # Critical
                    }
                )
                
                threat = Threat.objects.create(log=log, rule=rule)
                alert = Alert.objects.create(
                    threat=threat, 
                    message=f"Possible DoS attack from {log_entry['ip']} at rate {rate:.2f} msgs/min", 
                    status="pending"
                )
                
                # Send notification
                notification_data = {
                    "timestamp": log_entry["timestamp"].isoformat(),
                    "ip": str(log_entry["ip"]),
                    "rate": f"{rate:.2f} msgs/min",
                    "topic": msg.topic,
                    "alert_type": "DoS Attack"
                }
                send_notification(notification_data)
                
                # Return early - mark this as handled
                return
        
        # Brute Force Detection
        if detect_suspicious_activity(log_entry):
            # Already logged and alerted in the function
            return
                
        # Check against all custom rules in the database
        log_entry_saved = False
        log_obj = None
        
        # Get all active rules
        rules = Rule.objects.all()
        
        # Apply each rule to the current message
        for rule in rules:
            # Skip rules that are already implemented above
            if rule.name in ["Brute Force Attack", "Unauthorized Access", "ACL Violation", "DoS Attack"]:
                continue
                
            # Check if the message matches this rule
            if check_rule_against_message(
                rule, 
                msg.topic, 
                payload, 
                log_entry.get('publisher_id', 'unknown'),
                log_entry.get('ip'),
                timestamp
            ):
                # Save the log if not already saved
                if not log_entry_saved:
                    log_obj = Log.objects.create(**log_entry)
                    log_entry_saved = True
                
                # Create threat
                threat = Threat.objects.create(log=log_obj, rule=rule)
                
                # Create alert
                alert = Alert.objects.create(
                    threat=threat,
                    message=f"Rule matched: {rule.name}",
                    status="pending"
                )
                
                # Send notification if rule is high severity
                if rule.severity >= 3:  # High or Critical
                    notification_data = {
                        "timestamp": log_entry["timestamp"].isoformat(),
                        "rule": rule.name,
                        "severity": rule.get_severity_display(),
                        "topic": msg.topic,
                        "message": payload,
                        "publisher_id": log_entry.get('publisher_id', 'unknown'),
                        "ip": str(log_entry.get('ip', 'Unknown')),
                        "alert_type": "Rule Violation"
                    }
                    send_notification(notification_data)
        
        # Always save the log if it hasn't been saved yet (for normal operations)
        if not log_entry_saved:
            log_obj = Log.objects.create(**log_entry)
            
    except Exception as e:
        logging.error(f"❌ Error processing message: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())
            
    except Exception as e:
        logging.error(f"❌ Error processing message: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())

client = mqtt.Client(client_id=MQTT_CLIENT_ID, userdata={"client_id": MQTT_CLIENT_ID}, protocol=mqtt.MQTTv311)
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.tls_set(ca_certs=CA_CERT_PATH)
client.on_connect = on_connect
client.on_message = on_message

try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    logging.info("📡 MQTT Listener Started...")
    threading.Thread(target=monitor_mosquitto_logs, daemon=True).start()
    client.loop_forever()
except Exception as e:
    logging.error(f"❌ Failed to connect to MQTT broker: {e}")
