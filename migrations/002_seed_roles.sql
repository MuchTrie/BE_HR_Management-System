INSERT INTO roles (name, created_at, updated_at) VALUES
('ADMIN', NOW(), NOW()), ('MANAGER', NOW(), NOW()), ('EMPLOYEE', NOW(), NOW())
ON DUPLICATE KEY UPDATE updated_at = NOW();
