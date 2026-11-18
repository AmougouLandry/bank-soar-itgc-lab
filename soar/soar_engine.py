import os
import csv
import ssl
import ipaddress
from datetime import datetime, timezone
from fastapi import FastAPI
from pydantic import BaseModel
from ldap3 import Server, Connection, Tls, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_DELETE
import pymysql
import requests

app = FastAPI(title="Bank Defensive SOAR Orchestrator", version="1.0.0")

# Environment configuration
AD_HOST = os.getenv("AD_HOST", "ad-dc")
DOMAIN_REALM = os.getenv("DOMAIN_REALM", "CORP.BANKLAB.LOCAL")
BASE_DN = "DC=corp,DC=banklab,DC=local"
DOMAIN_ADMINS_DN = f"CN=Domain Admins,CN=Users,{BASE_DN}"
AD_BIND_USER = f"Administrator@{DOMAIN_REALM}"
AD_ADMIN_PASS = os.getenv("AD_ADMIN_PASS")

DB_HOST = os.getenv("DB_HOST", "mariadb-governance")
DB_NAME = os.getenv("DB_NAME", "bank_governance")
DB_USER = os.getenv("DB_USER", "audit_svc")
DB_PASS = os.getenv("DB_PASS")

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

BLOCKLIST_FILE = "/app/soar-data/firewall_blocked_ips.txt"
EXPORT_DIR = "/app/export"


class AlertPayload(BaseModel):
    alert_id: int
    timestamp: str
    rule_id: str
    mitre_technique: str
    title: str
    severity: str
    source_ip: str
    target_user: str
    evidence: str


def get_db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, autocommit=True)


def get_ldap_conn():
    tls_cfg = Tls(validate=ssl.CERT_NONE)
    server = Server(AD_HOST, port=636, use_ssl=True, tls=tls_cfg, get_info=ALL, connect_timeout=5)
    return Connection(server, user=AD_BIND_USER, password=AD_ADMIN_PASS, auto_bind=True)


def enrich_ip_threat_intel(ip_str: str) -> dict:
    """Enriches external IPs via AbuseIPDB / VirusTotal APIs with offline TI fallback."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return {"is_external": False, "abuse_score": 0, "provider": "Internal-RFC1918", "summary": "Internal corporate subnet IP"}
    except ValueError:
        return {"is_external": False, "abuse_score": 0, "provider": "Invalid-IP", "summary": "Unparseable IP"}

    # Live AbuseIPDB lookup if API key is configured
    if ABUSEIPDB_API_KEY and not ABUSEIPDB_API_KEY.startswith("your_"):
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip_str, "maxAgeInDays": 90},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = int(data.get("abuseConfidenceScore", 0))
                isp = data.get("isp", "Unknown ISP")
                country = data.get("countryCode", "??")
                return {
                    "is_external": True,
                    "abuse_score": score,
                    "provider": "AbuseIPDB-Live",
                    "summary": f"AbuseScore={score}% | Country={country} | ISP={isp}",
                }
        except Exception as exc:
            print(f"[!] AbuseIPDB API error: {exc}", flush=True)

    # Built-in Threat Intel Feed fallback for lab simulation & offline demos
    known_bad_prefixes = ("185.220.", "45.155.", "193.32.")
    if ip_str.startswith(known_bad_prefixes):
        return {
            "is_external": True,
            "abuse_score": 98,
            "provider": "ThreatIntel-Feed (Tor/Malicious ASN)",
            "summary": "AbuseScore=98% | Known Malicious Exit Node / Credential Stuffing Source",
        }
    return {
        "is_external": True,
        "abuse_score": 35,
        "provider": "ThreatIntel-Baseline",
        "summary": "AbuseScore=35% | External Unclassified IP",
    }


def contain_disable_ad_account(sam_account: str) -> str:
    """Disables an Active Directory user account via encrypted LDAPS (sets ACCOUNTDISABLE bit 0x0002)."""
    conn = get_ldap_conn()
    conn.search(BASE_DN, f"(sAMAccountName={sam_account})", SUBTREE, attributes=["distinguishedName", "userAccountControl"])
    if not conn.entries:
        conn.unbind()
        return f"User {sam_account} not found in AD"

    entry = conn.entries[0]
    user_dn = str(entry.distinguishedName)
    current_uac = int(str(entry.userAccountControl))
    disabled_uac = current_uac | 2

    conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [disabled_uac])]})
    conn.unbind()
    return f"LDAPS Containment: Disabled AD account '{sam_account}' (UAC {current_uac} -> {disabled_uac})"


def contain_revoke_domain_admin(sam_account: str) -> str:
    """Removes an unauthorized user from the Domain Admins security group via LDAPS."""
    conn = get_ldap_conn()
    conn.search(BASE_DN, f"(sAMAccountName={sam_account})", SUBTREE, attributes=["distinguishedName"])
    if not conn.entries:
        conn.unbind()
        return f"User {sam_account} not found in AD"

    user_dn = str(conn.entries[0].distinguishedName)
    conn.modify(DOMAIN_ADMINS_DN, {"member": [(MODIFY_DELETE, [user_dn])]})
    conn.unbind()
    return f"LDAPS Containment: Revoked 'Domain Admins' privilege from '{sam_account}'"


def contain_block_perimeter_ip(db_conn, ip_str: str, score: int, provider: str, reason: str) -> str:
    """Adds a confirmed malicious IP to the perimeter firewall dynamic blocklist."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with db_conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO blocked_perimeter_ips (blocked_at, ip_address, abuse_score, threat_source, reason)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE blocked_at=VALUES(blocked_at), abuse_score=VALUES(abuse_score), reason=VALUES(reason)
            """,
            (ts, ip_str, score, provider, reason),
        )
    os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
    existing = set()
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            existing = {line.strip() for line in f if line.strip()}
    if ip_str not in existing:
        with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ip_str} # Blocked at {ts} UTC | {reason}\n")
    return f"Firewall Containment: Blocked {ip_str} at perimeter gateway (AbuseScore={score}%)"


def export_soc_powerbi_csv(db_conn):
    """Exports enriched SOC incident & SOAR containment metrics for Power BI."""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    with db_conn.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT * FROM soc_security_alerts ORDER BY alert_id DESC;")
        rows = cursor.fetchall()
    if rows:
        out_path = os.path.join(EXPORT_DIR, "soc_incidents_latest.csv")
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)


@app.get("/health")
def health():
    return {"status": "online", "service": "bank-soar-orchestrator"}


@app.post("/api/v1/soar/ingest")
def ingest_alert(alert: AlertPayload):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    db_conn = get_db()

    # Step 1: Threat Intelligence Enrichment
    ti = enrich_ip_threat_intel(alert.source_ip)
    ti_summary = f"[{ti['provider']}] {ti['summary']}"

    playbook_id = "PB-00-TRIAGE"
    containment_action = "Logged for L1 analyst review"
    soar_status = "ENRICHED"

    # Step 2: Execute Automated Containment Playbook based on Rule / MITRE Technique
    if alert.rule_id == "SOC-001" and ti["abuse_score"] >= 75:
        playbook_id = "PB-01-BRUTEFORCE"
        containment_action = contain_block_perimeter_ip(
            db_conn, alert.source_ip, ti["abuse_score"], ti["provider"], f"Alert #{alert.alert_id}: {alert.title}"
        )
        soar_status = "CONTAINED"

    elif alert.rule_id == "SOC-002":
        playbook_id = "PB-02-ORPHAN-ACCOUNT"
        ad_msg = contain_disable_ad_account(alert.target_user)
        ip_msg = contain_block_perimeter_ip(
            db_conn, alert.source_ip, max(ti["abuse_score"], 85), ti["provider"], f"Terminated user login: {alert.target_user}"
        )
        containment_action = f"{ad_msg} | {ip_msg}"
        soar_status = "CONTAINED"

    elif alert.rule_id == "SOC-003":
        playbook_id = "PB-03-PRIV-ESCALATION"
        containment_action = contain_revoke_domain_admin(alert.target_user)
        soar_status = "CONTAINED"

    # Step 3: Update Alert Record & Log Playbook Execution
    with db_conn.cursor() as cursor:
        cursor.execute(
            """
            UPDATE soc_security_alerts
            SET soar_status=%s, threat_intel_summary=%s, action_taken=%s
            WHERE alert_id=%s
            """,
            (soar_status, ti_summary, containment_action, alert.alert_id),
        )
        cursor.execute(
            """
            INSERT INTO soar_playbook_executions
            (executed_at, alert_id, playbook_id, mitre_technique, target_entity, enrichment_result, containment_action, execution_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'SUCCESS')
            """,
            (ts, alert.alert_id, playbook_id, alert.mitre_technique, f"{alert.target_user} / {alert.source_ip}", ti_summary, containment_action),
        )

    export_soc_powerbi_csv(db_conn)
    db_conn.close()

    print(f"[SOAR {playbook_id}] Alert #{alert.alert_id} -> {containment_action}", flush=True)
    return {
        "alert_id": alert.alert_id,
        "playbook_id": playbook_id,
        "soar_status": soar_status,
        "threat_intel": ti_summary,
        "containment_action": containment_action,
    }
