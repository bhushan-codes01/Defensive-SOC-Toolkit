import time
import json
from typing import List, Dict, Any, Optional

try:
    import paho.mqtt.client as mqtt
    HAS_PAHO = True
except ImportError:
    HAS_PAHO = False

from .db import insert_alert

APPROVED_DEVICES = {
    "ESP32_SENSOR_01": {"name": "Lab Temp/Humidity Sensor", "type": "Environmental Sensor", "ip": "192.168.1.50"},
    "ESP32_SENSOR_02": {"name": "Server Room Monitor", "type": "Environmental Sensor", "ip": "192.168.1.51"},
    "CAM_GATEWAY_01": {"name": "Smart Security Camera", "type": "Camera Gateway", "ip": "192.168.1.75"}
}

# In-memory telemetry log buffer
telemetry_buffer: List[Dict[str, Any]] = []

def process_telemetry_payload(device_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    temp = data.get("temperature", 24.0)
    humidity = data.get("humidity", 50.0)
    ip = data.get("ip", "192.168.1.50")
    
    status = "OK"
    anomalies = []

    # Whitelist Check
    if device_id not in APPROVED_DEVICES:
        status = "ROGUE_DEVICE"
        anomalies.append(f"Unauthorized device ID '{device_id}' connected to IoT Network.")
        insert_alert(
            rule_id="ROGUE_IOT_DEVICE",
            severity="HIGH",
            title="Rogue IoT Device Detected",
            description=f"Unauthorized device '{device_id}' publishing telemetry on MQTT broker.",
            evidence=f"Device ID: {device_id}, Payload: {json.dumps(data)}",
            mitre_technique="T1200",
            src_ip=ip,
            dst_ip="192.168.1.1"
        )
    else:
        # Telemetry Anomaly Check
        if temp > 65.0:
            status = "ANOMALY_CRITICAL"
            anomalies.append(f"Extreme thermal reading detected ({temp:.1f}°C > 65°C). Possible physical security or hardware malfunction.")
            insert_alert(
                rule_id="IOT_THERMAL_CRITICAL",
                severity="CRITICAL",
                title="Critical Thermal Reading from IoT Sensor",
                description=f"IoT Sensor '{device_id}' reported abnormal temperature of {temp:.1f}°C.",
                evidence=f"Temperature: {temp:.1f}°C, Humidity: {humidity:.1f}%",
                mitre_technique="T1499",
                src_ip=ip,
                dst_ip="192.168.1.1"
            )

    entry = {
        "timestamp": now,
        "device_id": device_id,
        "device_name": APPROVED_DEVICES.get(device_id, {}).get("name", "Unknown/Rogue Device"),
        "temperature": temp,
        "humidity": humidity,
        "status": status,
        "anomalies": anomalies,
        "ip": ip
    }

    telemetry_buffer.append(entry)
    if len(telemetry_buffer) > 100:
        telemetry_buffer.pop(0)

    return entry

def get_recent_telemetry(limit: int = 50) -> List[Dict[str, Any]]:
    if not telemetry_buffer:
        # Seed initial demo telemetry entries
        process_telemetry_payload("ESP32_SENSOR_01", {"temperature": 24.5, "humidity": 48.2, "ip": "192.168.1.50"})
        process_telemetry_payload("ESP32_SENSOR_02", {"temperature": 22.1, "humidity": 51.0, "ip": "192.168.1.51"})
        process_telemetry_payload("ROGUE_ESP8266_SNIFFER", {"temperature": 88.0, "humidity": 12.0, "ip": "192.168.1.199"})

    return telemetry_buffer[-limit:]
