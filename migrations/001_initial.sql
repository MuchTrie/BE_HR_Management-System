-- MySQL 8.x reference migration. The Go server also runs AutoMigrate for local development.
CREATE TABLE IF NOT EXISTS roles (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, name VARCHAR(20) NOT NULL UNIQUE, created_at DATETIME(3), updated_at DATETIME(3));
CREATE TABLE IF NOT EXISTS refresh_tokens (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, user_id BIGINT UNSIGNED NOT NULL, token_hash CHAR(64) NOT NULL UNIQUE, expires_at DATETIME(3) NOT NULL, revoked_at DATETIME(3) NULL, created_at DATETIME(3), INDEX (user_id), INDEX (expires_at));
