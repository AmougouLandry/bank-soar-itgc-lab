import time
from datetime import datetime, timezone

LOG_FILE = "logs/bank_auth_perimeter.log"


def write_event(service, event, user, src_ip, detail):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f'{ts} [{service}] event={event} user={user} src_ip={src_ip} detail="{detail}"\n'
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"[SIM] {line.strip()}")


if __name__ == "__main__":
    print("=== Simulating Enterprise Banking Cyber Attacks ===")
    # Scenario 1: External Brute Force from known malicious IP (185.220.101.45)
    for i in range(1, 6):
        write_event("VPN-GW", "AUTH_FAILURE", "claire.ewane", "185.220.101.45", f"Invalid NTLM password attempt #{i}")
        time.sleep(0.3)

    # Scenario 2: Terminated Employee Orphan Account Login (jean.mbarga)
    time.sleep(1)
    write_event("CORE-BANK-PORTAL", "AUTH_SUCCESS", "jean.mbarga", "41.202.219.74", "Kerberos TGT issued to terminated employee")

    # Scenario 3: Unauthorized Domain Admin Escalation (paul.ndongo)
    time.sleep(1)
    write_event("AD-DC01", "GROUP_PRIV_ADD", "paul.ndongo", "172.25.10.55", "Added CN=paul.ndongo to CN=Domain Admins")
    print("=== Attack Simulation Complete ===")
