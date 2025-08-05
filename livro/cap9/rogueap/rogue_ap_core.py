import subprocess
import re
import sqlite3
from datetime import datetime

class RogueAPDetector:
    def __init__(self, interface="wlan0mon", db_path="rogue_detection.db"):
        self.interface = interface
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                signal_strength INTEGER,
                vendor TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_authorized BOOLEAN DEFAULT 0,
                is_suspicious BOOLEAN DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rogue_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                bssid TEXT,
                ssid TEXT,
                detection_reason TEXT,
                confidence REAL,
                action_taken TEXT
            )
        """)
        conn.commit()
        conn.close()

    def scan_access_points(self):
        try:
            result = subprocess.run(
                ['iwlist', self.interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                print(f"Erro no scan: {result.stderr}")
                return []

            return self.parse_scan_results(result.stdout)

        except Exception as e:
            print(f"Erro no scan: {e}")
            return []

    def parse_scan_results(self, scan_output):
        aps = []
        current_ap = {}

        for line in scan_output.split('\n'):
            line = line.strip()

            if 'Cell' in line and 'Address:' in line:
                if current_ap:
                    aps.append(current_ap)
                bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
                current_ap = {
                    'bssid': bssid_match.group(1) if bssid_match else 'Unknown',
                    'ssid': '',
                    'channel': 0,
                    'encryption': 'Open',
                    'signal_strength': -100,
                    'vendor': 'Unknown'
                }

            elif 'ESSID:' in line:
                ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                if ssid_match:
                    current_ap['ssid'] = ssid_match.group(1)

            elif 'Channel:' in line:
                channel_match = re.search(r'Channel:(\d+)', line)
                if channel_match:
                    current_ap['channel'] = int(channel_match.group(1))

            elif 'Signal level=' in line:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    current_ap['signal_strength'] = int(signal_match.group(1))

            elif 'Encryption key:on' in line:
                current_ap['encryption'] = 'WEP'
            elif 'WPA' in line:
                current_ap['encryption'] = 'WPA2'

        if current_ap:
            aps.append(current_ap)

        return aps

    def get_rogue_detections(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rogue_detections ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_all_access_points(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM access_points ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def record_scan_results(self, aps):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for ap in aps:
            cursor.execute("""
                INSERT OR REPLACE INTO access_points (bssid, ssid, channel, encryption, signal_strength, vendor, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                ap['bssid'], ap['ssid'], ap['channel'],
                ap['encryption'], ap['signal_strength'],
                ap['vendor']
            ))

        conn.commit()
        conn.close()
