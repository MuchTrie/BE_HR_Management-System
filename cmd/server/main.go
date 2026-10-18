package main

import (
	"github.com/joho/godotenv"

	"securehr/backend/internal/config"
	"securehr/backend/internal/database"
	"securehr/backend/internal/server"
)

func main() {
	_ = godotenv.Load()
	cfg := config.Load()
	db, err := database.Open(cfg)
	if err != nil {
		panic("database connection failed: " + err.Error())
	}
	if err = database.Initialize(db); err != nil {
		panic("database initialization failed: " + err.Error())
	}
	app := server.New(db, cfg)

	r := app.Router()
	if err = r.Run(":" + cfg.Port); err != nil {
		panic(err)
	}
}
