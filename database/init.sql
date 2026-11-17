CREATE DATABASE IF NOT EXISTS bank_governance;
USE bank_governance;

CREATE TABLE IF NOT EXISTS hr_employees (
    employee_id VARCHAR(10) PRIMARY KEY,
    sam_account_name VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    department VARCHAR(50) NOT NULL,
    role_title VARCHAR(80) NOT NULL,
    employment_status ENUM('ACTIVE', 'TERMINATED', 'CONTRACTOR') NOT NULL,
    approved_admin BOOLEAN DEFAULT FALSE,
    termination_date DATE NULL
);

INSERT INTO hr_employees (employee_id, sam_account_name, full_name, department, role_title, employment_status, approved_admin, termination_date) VALUES
('EMP-001', 'amougou.sec', 'M. Amougou', 'Cybersecurity & SOC', 'SOC Analyst / Security Engineer', 'ACTIVE', FALSE, NULL),
('EMP-002', 'claire.ewane', 'Claire Ewane', 'Core Banking Operations', 'Senior Teller Supervisor', 'ACTIVE', FALSE, NULL),
('EMP-003', 'samuel.tchoua', 'Samuel Tchoua', 'Internal Audit & Risk', 'IT Audit Lead', 'ACTIVE', FALSE, NULL),
('EMP-004', 'jean.mbarga', 'Jean Mbarga', 'Core Banking Operations', 'Former Operations Officer', 'TERMINATED', FALSE, '2026-10-15'),
('EMP-005', 'paul.ndongo', 'Paul Ndongo', 'External Vendor', 'Network Cabling Contractor', 'CONTRACTOR', FALSE, NULL);
