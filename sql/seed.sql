USE vulntracker;

-- Development-only accounts. Change/remove these passwords before any shared deployment.
-- Passwords: Admin@12345 / Analyst@12345 / Engineer@12345
INSERT INTO users (username, password_hash, full_name, role) VALUES
('admin', 'PBKDF2$120000$GBkOVFL33aYNVSGqwJ5VdA==$nMj1XHbR8647sYpK+GAc7VVb8grmpae/gAZWheZTO04=', 'System Administrator', 'ADMIN'),
('analyst', 'PBKDF2$120000$kPHZXIpxxinI+Gnm9gV/eQ==$cjD8lcsHecYDsRWIR0XS3/CXEH8knTjMMCfe7h/XNpY=', 'Security Analyst', 'ANALYST'),
('engineer', 'PBKDF2$120000$QLH4xF9FgOCnefxoHIa4iQ==$rGZBuvyk4O0y6kc/H0ENDLn9RnfbhKlVKTpu392zQMA=', 'Security Engineer', 'ENGINEER')
ON DUPLICATE KEY UPDATE full_name=VALUES(full_name), role=VALUES(role);
