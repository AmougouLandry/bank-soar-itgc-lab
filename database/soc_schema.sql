USE bank_governance;

CREATE TABLE IF NOT EXISTS soc_security_alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    alert_timestamp DATETIME NOT NULL,
    rule_id VARCHAR(20) NOT NULL,
    mitre_technique VARCHAR(30) NOT NULL,
    alert_title VARCHAR(120) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_user VARCHAR(50) NOT NULL,
    raw_evidence TEXT NOT NULL,
    soar_status ENUM('NEW', 'ENRICHED', 'CONTAINED', 'FALSE_POSITIVE') DEFAULT 'NEW',
    threat_intel_summary VARCHAR(255) DEFAULT 'Pending Enrichment',
    action_taken VARCHAR(255) DEFAULT 'None'
);
