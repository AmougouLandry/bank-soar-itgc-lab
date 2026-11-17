import os
import re
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
import pymysql
import requests

DB_HOST = os.getenv("DB_HOST", "mariadb-governance")
DB_NAME = os.getenv("DB_NAME", "bank_governance")
DB_USER = os.getenv("DB_USER", "audit_svc")
DB_PASS = os.getenv("DB_PASS")
LOG_FILE = "/app/logs/bank_auth_perimeter.log"
SOAR_WEBHOOK_URL = os.getenv("SOAR_WEBHOOK_URL", "")

# Sliding window tracker: source_ip -> deque of timestamps for failed logins
failed_login_tracker = defaultdict(lambda: deque(maxlen=20))
alerted_bruteforce_ips = set()

LOG_PATTERN = re.compile(
    r"^(?P<ts>\S+)\s+\[(?P<service>\S+)\]\s+event=(?P<event>\S+)\s+user=(?P<user>\S+)\s+src_ip=(?P<src_ip>\S+)\s+detail=\"(?P<detail>.*)\"$"
)


def get_db_connection():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, autocommit=True)


def is_user_terminated(db_conn, username):
    with db_conn.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT employment_status FROM hr_employees WHERE sam_account_name = %s;", (username,))
        row = cursor.fetchone()
        return bool(row and row["employment_status"] == "TERMINATED")


def emit_alert(db_conn, rule_id, mitre, title, severity, src_ip, target_user, evidence):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with db_conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO soc_security_alerts
            (alert_timestamp, rule_id, mitre_technique, alert_title, severity, source_ip, target_user, raw_evidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (ts, rule_id, mitre, title, severity, src_ip, target_user, evidence),
        )
        alert_id = cursor.lastrowid

    payload = {
        "alert_id": alert_id,
        "timestamp": ts,
        "rule_id": rule_id,
        "mitre_technique": mitre,
        "title": title,
        "severity": severity,
        "source_ip": src_ip,
        "target_user": target_user,
        "evidence": evidence,
    }
    print(f"[ALERT #{alert_id}] [{severity}] {rule_id} ({mitre}) - {title} | user={target_user} src_ip={src_ip}", flush=True)

    if SOAR_WEBHOOK_URL:
        try:
            resp = requests.post(SOAR_WEBHOOK_URL, json=payload, timeout=5)
            print(f"    -> Forwarded alert #{alert_id} to SOAR webhook (HTTP {resp.status_code})", flush=True)
        except Exception as exc:
            print(f"    -> SOAR webhook forwarding skipped/failed: {exc}", flush=True)


def process_log_line(db_conn, line):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return

    data = match.groupdict()
    event = data["event"]
    user = data["user"]
    src_ip = data["src_ip"]
    detail = data["detail"]

    # Rule SOC-001: Credential Brute Force (5 failed logins from same IP within 60s)
    if event == "AUTH_FAILURE":
        now = time.time()
        window = failed_login_tracker[src_ip]
        window.append(now)
        recent = [t for t in window if now - t <= 60]
        if len(recent) >= 5 and src_ip not in alerted_bruteforce_ips:
            alerted_bruteforce_ips.add(src_ip)
            emit_alert(
                db_conn,
                "SOC-001",
                "T1110.001",
                "External Brute-Force / Password Spraying Against Banking AD",
                "HIGH",
                src_ip,
                user,
                f"Detected {len(recent)} consecutive authentication failures from {src_ip} within 60s (last target: {user}).",
            )

    # Rule SOC-002: Login Attempt by HR-Terminated Employee (Orphan Account Exploitation)
    if event in ("AUTH_SUCCESS", "AUTH_FAILURE") and is_user_terminated(db_conn, user):
        emit_alert(
            db_conn,
            "SOC-002",
            "T1078.002",
            "Terminated Employee Account Activity Detected (ITGC Breach)",
            "CRITICAL",
            src_ip,
            user,
            f"Account {user} is marked TERMINATED in HR but generated {event} from {src_ip} ({detail}).",
        )

    # Rule SOC-003: Unauthorized Privileged Group Modification
    if event == "GROUP_PRIV_ADD":
        emit_alert(
            db_conn,
            "SOC-003",
            "T1098",
            "Critical Privilege Escalation: User Added to Domain Admins",
            "CRITICAL",
            src_ip,
            user,
            f"Privileged directory change detected for {user} from {src_ip}: {detail}",
        )


def tail_logs():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a", encoding="utf-8").close()

    print(f"[*] Bank SIEM Telemetry & Detection Engine listening on {LOG_FILE}...", flush=True)
    db_conn = get_db_connection()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                db_conn.ping(reconnect=True)
                process_log_line(db_conn, line)
            except Exception as exc:
                print(f"[!] Error processing telemetry line: {exc}", flush=True)


if __name__ == "__main__":
    tail_logs()
