#!/usr/bin/env python3
"""
NIDS Dashboard - Flask Backend
Reads alerts from SQLite (alerts.db), populated by parser.py from Suricata's eve.json.
Read-only web interface (does not perform blocking actions - see response_engine.py).
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
import subprocess
import os
import time
from datetime import datetime, timedelta

app = Flask(__name__)
DB_PATH = "/root/nids-dashboard/alerts.db"
EVE_JSON_PATH = "/var/log/suricata/eve.json"
APP_START_TIME = time.time()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def is_process_running(name):
    try:
        result = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True)
        return len(result.stdout.strip()) > 0
    except Exception:
        return False


def format_uptime(seconds):
    delta = timedelta(seconds=int(seconds))
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{delta.days}d {hours}h {minutes}m {secs}s"


# ---------- PAGES ----------

@app.route("/")
def index():
    return render_template("index.html", page="dashboard")


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html", page="alerts")


@app.route("/responses")
def responses_page():
    return render_template("responses.html", page="responses")


@app.route("/blocked-ips")
def blocked_ips_page():
    return render_template("blocked_ips.html", page="blocked-ips")


@app.route("/statistics")
def statistics_page():
    return render_template("statistics.html", page="statistics")


@app.route("/system")
def system_page():
    return render_template("system.html", page="system")


@app.route("/about")
def about_page():
    return render_template("about.html", page="about")


# ---------- API: SYSTEM STATUS ----------

@app.route("/api/system/status")
def api_system_status():
    suricata_running = is_process_running("suricata")
    parser_running = is_process_running("parser.py")
    db_exists = os.path.exists(DB_PATH)
    db_size_kb = round(os.path.getsize(DB_PATH) / 1024, 2) if db_exists else 0

    interface = "ens37"  # adjust to your monitored network interface

    return jsonify({
        "suricata": "Running" if suricata_running else "Stopped",
        "parser": "Running" if parser_running else "Stopped",
        "sqlite": "OK" if db_exists else "Missing",
        "flask": "Running",
        "response_engine": "Running" if is_process_running("response_engine.py") else "Stopped",
        "interface": interface,
        "db_size_kb": db_size_kb,
        "uptime": format_uptime(time.time() - APP_START_TIME)
    })


# ---------- API: KPI CARDS ----------

@app.route("/api/stats/kpi")
def api_kpi():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS c FROM alerts")
    total = cursor.fetchone()["c"]

    def count_by_severity(sev):
        cursor.execute("SELECT COUNT(*) AS c FROM alerts WHERE severity = ?", (sev,))
        return cursor.fetchone()["c"]

    critical = count_by_severity(1)
    high = count_by_severity(2)
    medium = count_by_severity(3)
    low = count_by_severity(4)

    cursor.execute("SELECT COUNT(*) AS c FROM alerts WHERE date(timestamp) = date('now')")
    today = cursor.fetchone()["c"]

    cursor.execute("""
        SELECT COUNT(*) AS c FROM alerts
        WHERE timestamp >= datetime('now', '-1 hour')
    """)
    this_hour = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) AS c FROM blocked_ips WHERE status = 'active'")
    blocked = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(DISTINCT dest_ip) AS c FROM alerts")
    hosts = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) AS c FROM response_log")
    responses_count = cursor.fetchone()["c"]

    conn.close()

    return jsonify({
        "total_alerts": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked_ips": blocked,
        "attacks_today": today,
        "attacks_this_hour": this_hour,
        "hosts_monitored": hosts,
        "auto_responses": responses_count
    })


# ---------- API: DASHBOARD CHARTS ----------

@app.route("/api/charts/attack-types")
def api_chart_attack_types():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*) AS count
        FROM alerts GROUP BY attack_type ORDER BY count DESC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route("/api/charts/timeline")
def api_chart_timeline():
    """Alerts grouped by hour (last 24h)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour, COUNT(*) AS count
        FROM alerts
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour ORDER BY hour ASC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route("/api/charts/top-ips")
def api_chart_top_ips():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT src_ip, COUNT(*) AS count FROM alerts
        GROUP BY src_ip ORDER BY count DESC LIMIT 5
    """)
    attackers = [dict(r) for r in cursor.fetchall()]

    cursor.execute("""
        SELECT dest_ip, COUNT(*) AS count FROM alerts
        GROUP BY dest_ip ORDER BY count DESC LIMIT 5
    """)
    victims = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"attackers": attackers, "victims": victims})


@app.route("/api/charts/ports-protocols")
def api_chart_ports_protocols():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT dest_port, COUNT(*) AS count FROM alerts
        WHERE dest_port IS NOT NULL
        GROUP BY dest_port ORDER BY count DESC LIMIT 5
    """)
    ports = [dict(r) for r in cursor.fetchall()]

    cursor.execute("""
        SELECT protocol, COUNT(*) AS count FROM alerts
        GROUP BY protocol ORDER BY count DESC
    """)
    protocols = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"ports": ports, "protocols": protocols})


@app.route("/api/charts/severity")
def api_chart_severity():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT severity, COUNT(*) AS count FROM alerts
        GROUP BY severity ORDER BY severity ASC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route("/api/charts/category")
def api_chart_category():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT category, COUNT(*) AS count FROM alerts
        WHERE category IS NOT NULL
        GROUP BY category ORDER BY count DESC LIMIT 8
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


# ---------- API: LATEST ALERTS (dashboard widget) ----------

@app.route("/api/alerts/latest")
def api_latest_alerts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, signature, signature_id, category, severity,
               protocol, src_ip, src_port, dest_ip, dest_port, attack_type
        FROM alerts ORDER BY id DESC LIMIT 15
    """)
    alerts = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)


# ---------- API: ALERTS PAGE - SEARCH / FILTERS / PAGINATION ----------

@app.route("/api/alerts/search")
def api_alerts_search():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "")
    attack_type = request.args.get("attack_type", "")
    category = request.args.get("category", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")

    conn = get_db()
    cursor = conn.cursor()

    where_clauses = []
    params = []

    if search:
        where_clauses.append("""
            (src_ip LIKE ? OR dest_ip LIKE ? OR signature LIKE ?
             OR CAST(signature_id AS TEXT) LIKE ? OR CAST(src_port AS TEXT) LIKE ?
             OR CAST(dest_port AS TEXT) LIKE ?)
        """)
        like_term = f"%{search}%"
        params.extend([like_term] * 6)

    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)

    if attack_type:
        where_clauses.append("attack_type = ?")
        params.append(attack_type)

    if category:
        where_clauses.append("category = ?")
        params.append(category)

    if date_from:
        where_clauses.append("date(timestamp) >= date(?)")
        params.append(date_from)

    if date_to:
        where_clauses.append("date(timestamp) <= date(?)")
        params.append(date_to)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    cursor.execute(f"SELECT COUNT(*) AS c FROM alerts {where_sql}", params)
    total = cursor.fetchone()["c"]

    offset = (page - 1) * per_page
    query = f"""
        SELECT id, timestamp, signature, signature_id, category, severity,
               protocol, src_ip, src_port, dest_ip, dest_port, attack_type
        FROM alerts
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(query, params + [per_page, offset])
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "data": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })


@app.route("/api/alerts/filters-options")
def api_alerts_filters_options():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT attack_type FROM alerts WHERE attack_type IS NOT NULL ORDER BY attack_type")
    attack_types = [r["attack_type"] for r in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT category FROM alerts WHERE category IS NOT NULL ORDER BY category")
    categories = [r["category"] for r in cursor.fetchall()]

    conn.close()
    return jsonify({"attack_types": attack_types, "categories": categories})


@app.route("/api/alerts/detail/<int:alert_id>")
def api_alert_detail(alert_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ---------- API: RESPONSES ----------

@app.route("/api/responses")
def api_responses():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, action_type, target_ip, details, success
        FROM response_log
        ORDER BY id DESC LIMIT 100
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


# ---------- API: BLOCKED IPS ----------

@app.route("/api/blocked-ips")
def api_blocked_ips():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, ip_address, reason, triggered_by_sid, alert_count,
               blocked_at, status, unblocked_at
        FROM blocked_ips
        ORDER BY blocked_at DESC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route("/api/blocked-ips/unblock/<int:ip_id>", methods=["POST"])
def api_unblock_ip(ip_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blocked_ips WHERE id = ?", (ip_id,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "not found"}), 404

    ip = row["ip_address"]

    # Optional: actually unblock via iptables if not in DRY_RUN mode
    # subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

    cursor.execute("""
        UPDATE blocked_ips SET status = 'unblocked', unblocked_at = datetime('now')
        WHERE id = ?
    """, (ip_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "ip": ip})


# ---------- API: ADVANCED STATISTICS ----------

@app.route("/api/stats/suricata")
def api_stats_suricata():
    """Stats read from Suricata's stats.log"""
    stats_path = "/var/log/suricata/stats.log"
    result = {
        "packets_analyzed": "N/A",
        "packets_dropped": "N/A",
        "total_alerts_engine": "N/A"
    }
    try:
        if os.path.exists(stats_path):
            with open(stats_path, "r") as f:
                lines = f.readlines()
            for line in reversed(lines):
                if "capture.kernel_packets" in line:
                    result["packets_analyzed"] = line.split("|")[-1].strip()
                if "capture.kernel_drops" in line:
                    result["packets_dropped"] = line.split("|")[-1].strip()
                if result["packets_analyzed"] != "N/A" and result["packets_dropped"] != "N/A":
                    break
    except Exception as e:
        result["error"] = str(e)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS c FROM alerts")
    result["total_alerts_engine"] = cursor.fetchone()["c"]
    conn.close()

    return jsonify(result)


@app.route("/api/stats/sqlite")
def api_stats_sqlite():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS c FROM alerts")
    total = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(DISTINCT src_ip) AS c FROM alerts")
    unique_ips = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) AS c FROM response_log")
    responses = cursor.fetchone()["c"]

    conn.close()

    db_size_kb = round(os.path.getsize(DB_PATH) / 1024, 2) if os.path.exists(DB_PATH) else 0

    return jsonify({
        "total_alerts": total,
        "unique_ips": unique_ips,
        "total_responses": responses,
        "db_size_kb": db_size_kb
    })


@app.route("/api/charts/timeline-daily")
def api_chart_timeline_daily():
    """Alerts grouped by day (last 7 days)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT date(timestamp) AS day, COUNT(*) AS count
        FROM alerts
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY day ORDER BY day ASC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route("/api/charts/responses-by-type")
def api_chart_responses_by_type():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT action_type, COUNT(*) AS count
        FROM response_log
        GROUP BY action_type ORDER BY count DESC
    """)
    data = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)


# ---------- API: SYSTEM LOGS ----------

@app.route("/api/system/logs/<log_name>")
def api_system_logs(log_name):
    """Returns the last lines of a log file (parser/response/flask)"""
    allowed_logs = {
        "parser": "/root/nids-dashboard/parser.log",
        "response": "/root/nids-dashboard/response.log",
        "flask": "/root/nids-dashboard/flask.log"
    }

    if log_name not in allowed_logs:
        return jsonify({"error": "invalid log name"}), 400

    path = allowed_logs[log_name]
    if not os.path.exists(path):
        return jsonify({
            "lines": [],
            "note": f"File {path} not found (file logging not yet enabled for this script)"
        })

    try:
        with open(path, "r") as f:
            lines = f.readlines()[-50:]
        return jsonify({"lines": [l.strip() for l in lines]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------- APP ENTRY POINT ----------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
