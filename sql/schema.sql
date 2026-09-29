CREATE DATABASE IF NOT EXISTS vulntracker CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE vulntracker;

CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role ENUM('ADMIN','ANALYST','ENGINEER') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS vulnerability (
    vuln_id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('CRITICAL','HIGH','MEDIUM','LOW') NOT NULL,
    cve_id VARCHAR(30) NULL,
    reported_by INT NOT NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vulnerability_reporter FOREIGN KEY (reported_by) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ticket (
    ticket_id INT PRIMARY KEY AUTO_INCREMENT,
    vuln_id INT NOT NULL UNIQUE,
    assigned_to INT NULL,
    status ENUM('OPEN','IN_PROGRESS','RESOLVED','CLOSED') NOT NULL DEFAULT 'OPEN',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_date DATE NULL,
    CONSTRAINT fk_ticket_vulnerability FOREIGN KEY (vuln_id) REFERENCES vulnerability(vuln_id),
    CONSTRAINT fk_ticket_engineer FOREIGN KEY (assigned_to) REFERENCES users(user_id),
    INDEX idx_ticket_assigned_status (assigned_to, status),
    INDEX idx_ticket_due_status (due_date, status)
) ENGINE=InnoDB;

DROP TRIGGER IF EXISTS ticket_before_insert;
DELIMITER $$
CREATE TRIGGER ticket_before_insert
BEFORE INSERT ON ticket
FOR EACH ROW
BEGIN
    DECLARE sev VARCHAR(20);
    SELECT severity INTO sev FROM vulnerability WHERE vuln_id = NEW.vuln_id;
    IF sev IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Ticket requires a valid vulnerability';
    END IF;
    SET NEW.due_date = CASE sev
        WHEN 'CRITICAL' THEN DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY)
        WHEN 'HIGH' THEN DATE_ADD(CURRENT_DATE, INTERVAL 3 DAY)
        WHEN 'MEDIUM' THEN DATE_ADD(CURRENT_DATE, INTERVAL 7 DAY)
        WHEN 'LOW' THEN DATE_ADD(CURRENT_DATE, INTERVAL 30 DAY)
        ELSE NULL
    END;
END$$
DELIMITER ;

CREATE TABLE IF NOT EXISTS comment (
    comment_id INT PRIMARY KEY AUTO_INCREMENT,
    ticket_id INT NOT NULL,
    user_id INT NOT NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_comment_ticket FOREIGN KEY (ticket_id) REFERENCES ticket(ticket_id),
    CONSTRAINT fk_comment_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    INDEX idx_comment_ticket_created (ticket_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    INDEX idx_audit_user_created (user_id, created_at),
    INDEX idx_audit_action_created (action, created_at)
) ENGINE=InnoDB;
