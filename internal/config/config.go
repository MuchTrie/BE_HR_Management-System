package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port               string
	DatabaseDriver     string
	DatabaseDSN        string
	JWTSecret          string
	AccessTokenMinutes int
	RefreshTokenDays   int
}

func Load() Config {
	return Config{
		Port: get("PORT", "8080"), DatabaseDriver: get("DATABASE_DRIVER", "sqlite"), DatabaseDSN: get("DATABASE_DSN", "securehr.db"),
		JWTSecret:          get("JWT_SECRET", "change-this-development-secret"),
		AccessTokenMinutes: getInt("ACCESS_TOKEN_MINUTES", 15), RefreshTokenDays: getInt("REFRESH_TOKEN_DAYS", 7),
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
