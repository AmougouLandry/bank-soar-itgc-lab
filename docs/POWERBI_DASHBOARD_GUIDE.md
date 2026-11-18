# Executive Power BI Compliance & SOC Dashboard Guide

## Data Sources (`powerbi-export/`)
| Dataset File | Refresh Trigger | Purpose |
| :--- | :--- | :--- |
| `ad_hr_reconciliation_matrix.csv` | `itgc-auditor` | Full user-by-user comparison between Samba4 AD (LDAPS) and MariaDB HR records |
| `itgc_findings_latest.csv` | `itgc-auditor` | Active ITGC control exceptions (`ITGC-AC-01`, `ITGC-AC-02`, `ITGC-AC-03`) |
| `itgc_audit_history.csv` | `itgc-auditor` | Time-series compliance rate (%) tracking pre- and post-SOAR remediation |
| `soc_incidents_latest.csv` | `soar-engine` | MITRE ATT&CK alerts enriched with Threat Intel scores and containment actions |

## Dashboard Preview
![Power BI Executive Dashboard](powerbi_dashboard_preview.png)
