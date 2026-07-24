#!/usr/bin/env python3
"""
Suricata eve.json -> SQLite Parser
Continuously reads new lines from eve.json and inserts them into alerts.db
"""

import json
import sqlite3
import time
import os

EVE_JSON_PATH = "/var/log/suricata/eve.json"
DB_PATH = "/root/nids-dashboard/alerts.db"
OFFSET_FILE = "/root/nids-dashboard/.eve_offset"


def get_attack_type(cursor, signature_id):
    """Looks up the attack type via sid_mapping, defaults to 'Unknown'"""
    cursor.execute(
        "SELECT attack_type FROM sid_mapping WHERE signature_id = ?",
        (signature_id,)
    )
    row = cursor.fetchone()
    return row[0] if row else "Unknown"


def load_offset():
    """Gets the last read position in eve.json"""
    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE, "r") as f:
            return int(f.read().strip() or 0)
    return 0


def save_offset(offset):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def parse_and_insert(line, conn):
    """Parses a JSON line and inserts it if it's an alert"""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return  # incomplete or corrupted line, skip it

    if data.get("event_type") != "alert":
        return

    alert = data.get("alert", {})
    cursor = conn.cursor()

    signature_id = alert.get("signature_id")
    attack_type = get_attack_type(cursor, signature_id)

    cursor.execute("""
        INSERT INTO alerts (
            timestamp, signature, signature_id, category, severity,
            protocol, src_ip, src_port, dest_ip, dest_port,
            attack_type, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("timestamp"),
        alert.get("signature"),
        signature_id,
        alert.get("category"),
        alert.get("severity"),
        data.get("proto"),
        data.get("src_ip"),
        data.get("src_port"),
        data.get("dest_ip"),
        data.get("dest_port"),
        attack_type,
        line.strip()
    ))
    conn.commit()


def main():
    print(f"[Parser] Starting - reading {EVE_JSON_PATH}")
    conn = sqlite3.connect(DB_PATH)

    offset = load_offset()

    while True:
        if not os.path.exists(EVE_JSON_PATH):
            time.sleep(2)
            continue

        with open(EVE_JSON_PATH, "r") as f:
            f.seek(offset)
            new_lines = f.readlines()
            new_offset = f.tell()

        if new_lines:
            for line in new_lines:
                if line.strip():
                    parse_and_insert(line, conn)
            offset = new_offset
            save_offset(offset)
            print(f"[Parser] {len(new_lines)} new line(s) processed.")

        time.sleep(3)  # polling interval


if __name__ == "__main__":
    main()
