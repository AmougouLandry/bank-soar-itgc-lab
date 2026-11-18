import os
import csv
import json
import ssl
import time
from datetime import datetime, timezone
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
import pymysql

AD_HOST = os.getenv("AD_HOST", "ad-dc")
DOMAIN_REALM = os.getenv("DOMAIN_REALM", "CORP.BANKLAB.LOCAL")
BASE_DN = "DC=corp,DC=banklab,DC=local"
AD_BIND_USER = f"Administrator@{DOMAIN_REALM}"
AD_ADMIN_PASS = os.getenv("AD_ADMIN_PASS")

DB_HOST = os.getenv("DB_HOST", "mariadb-governance")
DB_NAME = os.getenv("DB_NAME", "bank_governance")
DB_USER = os.getenv("DB_USER", "audit_svc")
DB_PASS = os.getenv("DB_PASS")

EXPORT_DIR = "/app/export"
SYSTEM_ACCOUNTS = {"Administrator", "Guest", "krbtgt"}

FINDINGS_FIELDS = [
    "audit_run_timestamp",
    "control_id",
    "severity",
    "sam_account_name",
    "full_name",
    "department",
    "hr_status",
    "ad_enabled",
    "is_domain_admin",
    "finding_description",
]


def connect_ldap_with_retry(retries=5, delay=2):
    """Connects to Samba4 AD over encrypted LDAPS (port 636)."""
    tls_config = Tls(validate=ssl.CERT_NONE)
    for attempt in range(1, retries + 1):
        try:
            server = Server(AD_HOST, port=636, use_ssl=True, tls=tls_config, get_info=ALL, connect_timeout=5)
            conn = Connection(server, user=AD_BIND_USER, password=AD_ADMIN_PASS, auto_bind=True)
            return conn
        except Exception as exc:
            print(f"[!] LDAPS connection attempt {attempt}/{retries} failed ({exc}). Retrying in {delay}s...", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Active Directory LDAPS at {AD_HOST}:636 after {retries} attempts.")


def fetch_ad_users():
    """Queries Samba4 Active Directory via LDAPS for user accounts and group memberships."""
    conn = connect_ldap_with_retry()

    search_filter = "(&(objectClass=user)(objectCategory=person))"
    attributes = ["sAMAccountName", "displayName", "mail", "userAccountControl", "memberOf", "distinguishedName"]
    conn.search(search_base=BASE_DN, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)

    ad_users = {}
    for entry in conn.entries:
        sam = str(entry.sAMAccountName)
        if sam in SYSTEM_ACCOUNTS:
            continue

        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 512
        is_enabled = not bool(uac & 2)

        groups = [str(g) for g in entry.memberOf] if entry.memberOf else []
        is_domain_admin = any("CN=Domain Admins" in g for g in groups)

        ad_users[sam] = {
            "sam_account_name": sam,
            "display_name": str(entry.displayName) if entry.displayName else sam,
            "ad_enabled": is_enabled,
            "is_domain_admin": is_domain_admin,
            "groups": groups,
            "dn": str(entry.distinguishedName)
        }

    conn.unbind()
    return ad_users


def fetch_hr_records(db_conn):
    """Fetches authoritative HR employee records from MariaDB."""
    with db_conn.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT * FROM hr_employees;")
        rows = cursor.fetchall()
    return {row["sam_account_name"]: row for row in rows}


def run_reconciliation():
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[*] Starting ITGC Access Reconciliation Audit at {run_ts} UTC...", flush=True)

    ad_users = fetch_ad_users()
    db_conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, autocommit=True)
    hr_records = fetch_hr_records(db_conn)

    findings = []
    reconciliation_snapshot = []

    for sam, ad_info in ad_users.items():
        hr = hr_records.get(sam)
        hr_status = hr["employment_status"] if hr else "NOT_IN_HR"
        full_name = hr["full_name"] if hr else ad_info["display_name"]
        department = hr["department"] if hr else "Unknown"
        approved_admin = bool(hr["approved_admin"]) if hr else False

        reconciliation_snapshot.append({
            "audit_timestamp": run_ts,
            "sam_account_name": sam,
            "full_name": full_name,
            "department": department,
            "hr_status": hr_status,
            "ad_enabled": ad_info["ad_enabled"],
            "is_domain_admin": ad_info["is_domain_admin"],
            "approved_admin": approved_admin,
            "compliant": True
        })

        # Control 1: ITGC-AC-01 - Terminated Employee with Active AD Account
        if hr and hr_status == "TERMINATED" and ad_info["ad_enabled"]:
            reconciliation_snapshot[-1]["compliant"] = False
            findings.append({
                "audit_run_timestamp": run_ts,
                "control_id": "ITGC-AC-01",
                "severity": "CRITICAL",
                "sam_account_name": sam,
                "full_name": full_name,
                "department": department,
                "hr_status": hr_status,
                "ad_enabled": True,
                "is_domain_admin": ad_info["is_domain_admin"],
                "finding_description": f"Orphan Account: {full_name} ({sam}) was terminated on {hr['termination_date']} in HR but remains ENABLED in Active Directory."
            })

        # Control 2: ITGC-AC-02 - Unauthorized Domain Admin Privilege
        if ad_info["is_domain_admin"] and not approved_admin:
            reconciliation_snapshot[-1]["compliant"] = False
            findings.append({
                "audit_run_timestamp": run_ts,
                "control_id": "ITGC-AC-02",
                "severity": "HIGH",
                "sam_account_name": sam,
                "full_name": full_name,
                "department": department,
                "hr_status": hr_status,
                "ad_enabled": ad_info["ad_enabled"],
                "is_domain_admin": True,
                "finding_description": f"Privilege Creep: {full_name} ({sam}, {hr_status}) holds Domain Admins membership without HR/Security approval."
            })

        # Control 3: ITGC-AC-03 - Shadow AD Account Missing from HR
        if not hr and ad_info["ad_enabled"]:
            reconciliation_snapshot[-1]["compliant"] = False
            findings.append({
                "audit_run_timestamp": run_ts,
                "control_id": "ITGC-AC-03",
                "severity": "MEDIUM",
                "sam_account_name": sam,
                "full_name": full_name,
                "department": department,
                "hr_status": "MISSING",
                "ad_enabled": True,
                "is_domain_admin": ad_info["is_domain_admin"],
                "finding_description": f"Shadow Account: Active AD account {sam} has no corresponding employee record in MariaDB HR registry."
            })

    # Persist findings into MariaDB for audit trail
    with db_conn.cursor() as cursor:
        cursor.execute("TRUNCATE TABLE itgc_audit_findings;")
        insert_sql = """
            INSERT INTO itgc_audit_findings
            (audit_run_timestamp, control_id, severity, sam_account_name, full_name, department, hr_status, ad_enabled, is_domain_admin, finding_description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        for f in findings:
            cursor.execute(insert_sql, (
                f["audit_run_timestamp"], f["control_id"], f["severity"], f["sam_account_name"],
                f["full_name"], f["department"], f["hr_status"], f["ad_enabled"],
                f["is_domain_admin"], f["finding_description"]
            ))

    db_conn.close()

    # Export Power BI datasets (always write headers even when 0 violations exist)
    os.makedirs(EXPORT_DIR, exist_ok=True)
    latest_csv = os.path.join(EXPORT_DIR, "itgc_findings_latest.csv")
    with open(latest_csv, "w", newline="", encoding="utf-8") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=FINDINGS_FIELDS)
        writer.writeheader()
        if findings:
            writer.writerows(findings)

    # Append summary run metrics to historical trend CSV for Power BI time-series
    history_csv = os.path.join(EXPORT_DIR, "itgc_audit_history.csv")
    file_exists = os.path.exists(history_csv)
    with open(history_csv, "a", newline="", encoding="utf-8") as h_csv:
        h_fields = ["audit_timestamp", "total_accounts", "violations_found", "compliance_rate_pct"]
        h_writer = csv.DictWriter(h_csv, fieldnames=h_fields)
        if not file_exists:
            h_writer.writeheader()
        total = len(ad_users)
        viol = len(findings)
        rate = round(((total - viol) / total) * 100, 1) if total > 0 else 100.0
        h_writer.writerow({
            "audit_timestamp": run_ts,
            "total_accounts": total,
            "violations_found": viol,
            "compliance_rate_pct": rate,
        })

    with open(os.path.join(EXPORT_DIR, "ad_hr_reconciliation_matrix.csv"), "w", newline="", encoding="utf-8") as m_csv:
        if reconciliation_snapshot:
            writer = csv.DictWriter(m_csv, fieldnames=reconciliation_snapshot[0].keys())
            writer.writeheader()
            writer.writerows(reconciliation_snapshot)

    with open(os.path.join(EXPORT_DIR, "itgc_findings_latest.json"), "w", encoding="utf-8") as f_json:
        json.dump(findings, f_json, indent=2)

    print(f"[+] Audit Complete: {len(ad_users)} AD accounts reconciled | {len(findings)} ITGC violations detected.", flush=True)
    for f in findings:
        print(f"    [{f['severity']}] {f['control_id']} -> {f['finding_description']}", flush=True)


if __name__ == "__main__":
    run_reconciliation()
