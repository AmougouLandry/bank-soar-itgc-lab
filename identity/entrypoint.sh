#!/bin/bash
set -e

DOMAIN_NAME=${DOMAIN_NAME:-corp.banklab.local}
DOMAIN_REALM=${DOMAIN_REALM:-CORP.BANKLAB.LOCAL}
DOMAIN_NETBIOS=${DOMAIN_NETBIOS:-BANKLAB}
AD_ADMIN_PASS=${AD_ADMIN_PASS:-B@nkL@b_Adm1n2026!}

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "[*] Provisioning Active Directory Domain: $DOMAIN_REALM..."
    rm -f /etc/samba/smb.conf

    samba-tool domain provision \
        --use-rfc2307 \
        --realm="$DOMAIN_REALM" \
        --domain="$DOMAIN_NETBIOS" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="$AD_ADMIN_PASS" \
        --option="dns forwarder = 8.8.8.8"

    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    echo "[*] Seeding Banking OUs, Security Groups, and Users..."
    samba-tool ou create "OU=BankingStaff,DC=corp,DC=banklab,DC=local"
    samba-tool ou create "OU=Contractors,DC=corp,DC=banklab,DC=local"

    samba-tool group add "SOC_Analysts"
    samba-tool group add "CoreBanking_Ops"
    samba-tool group add "IT_Auditors"

    # Legitimate Active Banking Staff
    samba-tool user create "amougou.sec" "P@ssw0rd2026!" --userou="OU=BankingStaff" --given-name="M." --surname="Amougou" --mail-address="amougou.sec@corp.banklab.local"
    samba-tool group addmembers "SOC_Analysts" "amougou.sec"

    samba-tool user create "claire.ewane" "P@ssw0rd2026!" --userou="OU=BankingStaff" --given-name="Claire" --surname="Ewane" --mail-address="claire.ewane@corp.banklab.local"
    samba-tool group addmembers "CoreBanking_Ops" "claire.ewane"

    samba-tool user create "samuel.tchoua" "P@ssw0rd2026!" --userou="OU=BankingStaff" --given-name="Samuel" --surname="Tchoua" --mail-address="samuel.tchoua@corp.banklab.local"
    samba-tool group addmembers "IT_Auditors" "samuel.tchoua"

    # ITGC ANOMALY 1: Terminated Employee (Orphan Active Account)
    samba-tool user create "jean.mbarga" "P@ssw0rd2026!" --userou="OU=BankingStaff" --given-name="Jean" --surname="Mbarga" --mail-address="jean.mbarga@corp.banklab.local"
    samba-tool group addmembers "CoreBanking_Ops" "jean.mbarga"

    # ITGC ANOMALY 2: External Contractor with Unauthorized Domain Admin Privilege
    samba-tool user create "paul.ndongo" "P@ssw0rd2026!" --userou="OU=Contractors" --given-name="Paul" --surname="Ndongo" --mail-address="paul.ndongo@corp.banklab.local"
    samba-tool group addmembers "Domain Admins" "paul.ndongo"

    echo "[+] Active Directory Provisioning Complete."
fi

exec samba -i --debug-stderr
