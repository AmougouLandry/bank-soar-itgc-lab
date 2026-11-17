USE bank_governance;

CREATE TABLE IF NOT EXISTS itgc_audit_findings (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    audit_run_timestamp DATETIME NOT NULL,
    control_id VARCHAR(20) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    sam_account_name VARCHAR(50) NOT NULL,
    full_name VARCHAR(100),
    department VARCHAR(50),
    hr_status VARCHAR(30),
    ad_enabled BOOLEAN,
    is_domain_admin BOOLEAN,
    finding_description TEXT NOT NULL,
    remediation_status ENUM('OPEN', 'REMEDIATED') DEFAULT 'OPEN'
);
