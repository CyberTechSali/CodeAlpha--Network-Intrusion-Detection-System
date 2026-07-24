#!/usr/bin/env python3
"""
Response Engine - NIDS Suricata
Watches alerts.db and triggers automatic actions (logging or IP blocking).
Runs completely independently from the Flask Dashboard.
"""

import sqlite3
import time
import subprocess
from datetime import datetime, timedelta

DB_PATH = "/root/nids-dashboard/alerts.db"

# --- Configuration ---
DRY_RUN = True  # True = does not block for real, log only (default safety setting)
THRESHOLD_ALERTS = 5       # number of alerts that triggers a block
THRESHOLD_WINDOW_SEC = 30  # time window for this threshold
WHITELIST_IPS = ["192.168.10.10"]  # never block the IDS itself
CHECK_INTERVAL = 10  # seconds between each check


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def log_response(conn, action_type, target_ip, details, success):
    conn.execute("""
        INSERT INTO response_log (action_type, target_ip, details, success)
        VALUES (?, ?, ?, ?)
    """, (action_type, target_ip, details, success))
    conn.commit()


def is_already_blocked(conn, ip):
    cur = conn.execute(
        "SELECT 1 FROM blocked_ips WHERE ip_address = ? AND status = 'active'", (ip,)
    )
    return cur.fetchone() is not None


def block_ip(conn, ip, reason, sid, alert_count):
    if ip in WHITELIST_IPS:
        log_response(conn, "SKIP_WHITELIST", ip, f"IP whitelisted, not blocked ({reason})", True)
        return

    if is_already_blocked(conn, ip):
        return  # already blocked, nothing to do

    success = True
    details = reason

    if DRY_RUN:
        details = f"[DRY-RUN] Would have blocked {ip} - {reason}"
        print(f"[Response Engine] {details}")
    else:
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            details = f"IP blocked via iptables - {reason}"
            print(f"[Response Engine] {details}")
        except subprocess.CalledProcessError as e:
            success = False
            details = f"iptables block failed: {e}"
            print(f"[Response Engine] ERROR: {details}")

    conn.execute("""
        INSERT INTO blocked_ips (ip_address, reason, triggered_by_sid, alert_count, status)
        VALUES (?, ?, ?, ?, 'active')
    """, (ip, reason, sid, alert_count))
    conn.commit()

    log_response(conn, "BLOCK_IP", ip, details, success)


def check_thresholds(conn):
    """Looks for source IPs that exceeded the alert threshold within the time window"""
    since = (datetime.utcnow() - timedelta(seconds=THRESHOLD_WINDOW_SEC)).strftime("%Y-%m-%dT%H:%M:%S")

    cur = conn.execute("""
        SELECT src_ip, COUNT(*) AS cnt, MAX(signature_id) AS sid, GROUP_CONCAT(DISTINCT attack_type) AS types
        FROM alerts
        WHERE timestamp >= ?
        GROUP BY src_ip
        HAVING cnt >= ?
    """, (since, THRESHOLD_ALERTS))

    for row in cur.fetchall():
        reason = f"{row['cnt']} alerts in {THRESHOLD_WINDOW_SEC}s (types: {row['types']})"
        block_ip(conn, row["src_ip"], reason, row["sid"], row["cnt"])


def main():
    print(f"[Response Engine] Starting - DRY_RUN={DRY_RUN}")
    conn = get_db()

    while True:
        try:
            check_thresholds(conn)
        except Exception as e:
            print(f"[Response Engine] Error: {e}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
