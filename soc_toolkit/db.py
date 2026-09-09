import sqlite3
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = Path(__file__).parent.parent / "soc_toolkit.db"

def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                mitre_technique TEXT,
                src_ip TEXT,
                dst_ip TEXT
            )
        """)
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                target TEXT NOT NULL,
                results_json TEXT NOT NULL
            )
        """)
        
        # Packets summary table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                protocol TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                packet_size INTEGER,
                info TEXT
            )
        """)
        
        # Incidents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                notes TEXT,
                assigned_to TEXT
            )
        """)
        
        # Audit chain table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain (
                block_index INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                payload_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
        """)
        
        conn.commit()
    
    seed_demo_data_if_empty()

def seed_demo_data_if_empty():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        if count == 0:
            now = time.time()
            # Demo alerts
            cursor.execute("""
                INSERT INTO alerts (timestamp, rule_id, severity, title, description, evidence, mitre_technique, src_ip, dst_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now - 300, "PORT_SCAN", "HIGH", "Port Scan Detected", 
                  "Host 192.168.1.105 scanned 45 unique ports on 192.168.1.1 within 10 seconds.",
                  "Port list: [21, 22, 23, 80, 443, 8080, ...]", "T1046", "192.168.1.105", "192.168.1.1"))
            
            cursor.execute("""
                INSERT INTO alerts (timestamp, rule_id, severity, title, description, evidence, mitre_technique, src_ip, dst_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now - 120, "ARP_SPOOF", "CRITICAL", "ARP Poisoning Detected",
                  "MAC address 00:11:22:33:44:55 claimed IP 192.168.1.1 previously bound to 00:AA:BB:CC:DD:EE.",
                  "Conflicting MACs for 192.168.1.1: 00:11:22:33:44:55 vs 00:AA:BB:CC:DD:EE", "T1557.002", "192.168.1.105", "192.168.1.1"))

            # Demo incident
            cursor.execute("""
                INSERT INTO incidents (timestamp, title, severity, status, notes, assigned_to)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now - 100, "Suspected ARP Spoofing Attack on Router Gateway", "CRITICAL", "INVESTIGATING", "Isolate MAC 00:11:22:33:44:55 and inspect switch port logs.", "SOC Analyst"))
            
            # Demo packets
            demo_pkts = [
                (now - 50, "TCP", "192.168.1.105", "192.168.1.1", 44321, 80, 64, "HTTP GET /index.html"),
                (now - 45, "DNS", "192.168.1.105", "1.1.1.1", 53124, 53, 78, "Standard query A example.com"),
                (now - 40, "ARP", "192.168.1.105", "192.168.1.255", None, None, 42, "Who has 192.168.1.1? Tell 192.168.1.105"),
                (now - 30, "MQTT", "192.168.1.50", "192.168.1.1", 1883, 1883, 52, "Publish topic telemetry/temp: 24.5C"),
                (now - 10, "ICMP", "192.168.1.105", "8.8.8.8", None, None, 64, "Echo (ping) request"),
            ]
            for pkt in demo_pkts:
                cursor.execute("""
                    INSERT INTO packets_summary (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, packet_size, info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, pkt)

            conn.commit()

# CRUD Helpers
def insert_alert(rule_id: str, severity: str, title: str, description: str, evidence: str, mitre_technique: str, src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (timestamp, rule_id, severity, title, description, evidence, mitre_technique, src_ip, dst_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), rule_id, severity, title, description, evidence, mitre_technique, src_ip, dst_ip))
        conn.commit()
        return cursor.lastrowid

def get_alerts(limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        if severity:
            cursor.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?", (severity, limit))
        else:
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def insert_packet_summary(protocol: str, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], packet_size: int, info: str):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO packets_summary (timestamp, protocol, src_ip, dst_ip, src_port, dst_port, packet_size, info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (time.time(), protocol, src_ip, dst_ip, src_port, dst_port, packet_size, info))
        conn.commit()

def get_packets_summary(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packets_summary ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def get_incidents() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

def insert_incident(title: str, severity: str, status: str = "OPEN", notes: str = "", assigned_to: str = "SOC Analyst") -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (timestamp, title, severity, status, notes, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (time.time(), title, severity, status, notes, assigned_to))
        conn.commit()
        return cursor.lastrowid
