package database

import (
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"securehr/backend/internal/config"
)

func Open(cfg config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector
	if cfg.DatabaseDriver == "mysql" {
		dialector = mysql.Open(cfg.DatabaseDSN)
	} else {
		dialector = sqlite.Open(cfg.DatabaseDSN)
	}
	return gorm.Open(dialector, &gorm.Config{})
}
