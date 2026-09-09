import time
import random
import json
import urllib.request
import sys

SERVER_URL = "http://127.0.0.1:8765/api/iot/telemetry"

def generate_telemetry_sample():
    devices = [
        {"device_id": "ESP32_SENSOR_01", "ip": "192.168.1.50", "base_temp": 24.0, "is_rogue": False},
        {"device_id": "ESP32_SENSOR_02", "ip": "192.168.1.51", "base_temp": 22.0, "is_rogue": False},
        {"device_id": "CAM_GATEWAY_01", "ip": "192.168.1.75", "base_temp": 35.0, "is_rogue": False},
        {"device_id": "ROGUE_ESP8266_SNIFFER", "ip": "192.168.1.199", "base_temp": 72.0, "is_rogue": True}
    ]

    dev = random.choice(devices)
    temp_variation = random.uniform(-2.0, 3.0)
    if dev["is_rogue"]:
        temp_variation += random.uniform(20.0, 40.0)

    return {
        "device_id": dev["device_id"],
        "temperature": round(dev["base_temp"] + temp_variation, 2),
        "humidity": round(random.uniform(40.0, 65.0), 2),
        "ip": dev["ip"],
        "timestamp": time.time()
    }

def run_simulator(count: int = 10, delay_sec: float = 1.0):
    print("==================================================")
    print("   Defensive SOC Toolkit — IoT Telemetry Simulator")
    print("==================================================")
    print(f"Target Server: {SERVER_URL}")
    print(f"Simulating {count} telemetry transmissions...\n")

    for i in range(1, count + 1):
        sample = generate_telemetry_sample()
        print(f"[{i}/{count}] Sending telemetry from '{sample['device_id']}' (Temp: {sample['temperature']}°C, IP: {sample['ip']})...")
        
        try:
            req = urllib.request.Request(
                SERVER_URL,
                data=json.dumps(sample).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                status = result.get("status", "OK")
                print(f"       -> Response Status: {status}")
        except Exception as e:
            print(f"       -> Direct API submission note: {e} (App server receives telemetry via internal monitor API)")

        time.sleep(delay_sec)

    print("\nSimulator run complete!")

if __name__ == "__main__":
    run_simulator(count=5, delay_sec=0.5)
