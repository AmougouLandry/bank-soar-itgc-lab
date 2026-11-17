# Banking SOAR & ITGC Compliance Auditing Pipeline

A containerized enterprise security engineering and IT General Controls (ITGC) homelab modeled on financial sector governance standards (COBAC, ISO 27001, PCI-DSS).

## Architecture Overview
- **Identity & Access Management (ank_ad_dc):** Custom Samba4 Active Directory Domain Controller (corp.banklab.local) managing banking OUs, security groups, and Kerberos/LDAP authentication.
- **HR & Governance Registry (ank_mariadb_hr):** MariaDB LTS database storing authoritative HR employment status and privileged access approvals.
- **Network Segmentation:** Isolated bridge subnets separating corporate identity/database services (172.25.10.0/24) from SecOps & audit automation (172.25.20.0/24).

## Build Progress
- [x] **Phase 1:** Segmented Docker Networks, Samba4 Active Directory DC, and MariaDB HR/Governance Registry.
- [x] **Phase 2:** Python + SQL ITGC User Access Reconciliation Engine (Orphan Account & Privilege Creep Detection).
- [ ] **Phase 3:** Security Telemetry & Alert Ingestion Pipeline.
- [ ] **Phase 4:** Shuffle SOAR Automated Incident Response & Threat Intel Enrichment.
- [ ] **Phase 5:** Executive Power BI Compliance & SOC Dashboard.
