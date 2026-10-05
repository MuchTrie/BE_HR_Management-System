package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port                 string
	DatabaseDriver       string
	DatabaseDSN          string
	JWTSecret            string
	AccessTokenMinutes   int
	RefreshTokenDays     int
	SeedAdminEmail       string
	SeedAdminPassword    string
	SeedManagerEmail     string
	SeedManagerPassword  string
	SeedEmployeeEmail    string
	SeedEmployeePassword string
}

func Load() Config {
	return Config{
		Port: get("PORT", "8080"), DatabaseDriver: get("DATABASE_DRIVER", "sqlite"), DatabaseDSN: get("DATABASE_DSN", "securehr.db"),
		JWTSecret:          get("JWT_SECRET", "change-this-development-secret"),
		AccessTokenMinutes: getInt("ACCESS_TOKEN_MINUTES", 15), RefreshTokenDays: getInt("REFRESH_TOKEN_DAYS", 7),
		SeedAdminEmail: get("SEED_ADMIN_EMAIL", "admin@example.com"), SeedAdminPassword: get("SEED_ADMIN_PASSWORD", "change-me-admin"),
		SeedManagerEmail: get("SEED_MANAGER_EMAIL", "manager@example.com"), SeedManagerPassword: get("SEED_MANAGER_PASSWORD", "change-me-manager"),
		SeedEmployeeEmail: get("SEED_EMPLOYEE_EMAIL", "employee@example.com"), SeedEmployeePassword: get("SEED_EMPLOYEE_PASSWORD", "change-me-employee"),
	}
}

func get(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func getInt(key string, fallback int) int {
	value, err := strconv.Atoi(get(key, ""))
	if err != nil {
		return fallback
	}
	return value
}
