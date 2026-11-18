USE bank_governance;

CREATE TABLE IF NOT EXISTS blocked_perimeter_ips (
    block_id INT AUTO_INCREMENT PRIMARY KEY,
    blocked_at DATETIME NOT NULL,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    abuse_score INT NOT NULL,
    threat_source VARCHAR(80) NOT NULL,
    reason VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS soar_playbook_executions (
    execution_id INT AUTO_INCREMENT PRIMARY KEY,
    executed_at DATETIME NOT NULL,
    alert_id INT NOT NULL,
    playbook_id VARCHAR(20) NOT NULL,
    mitre_technique VARCHAR(30) NOT NULL,
    target_entity VARCHAR(80) NOT NULL,
    enrichment_result VARCHAR(255) NOT NULL,
    containment_action VARCHAR(255) NOT NULL,
    execution_status ENUM('SUCCESS', 'FAILED') NOT NULL
);
