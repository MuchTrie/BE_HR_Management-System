package database

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"securehr/backend/internal/model"
	"securehr/backend/internal/seeder"
)

const (
	currentSchemaVersion = 2
	currentSeedVersion   = 1
)

type bootstrapState struct {
	Key       string    `gorm:"column:bootstrap_key;primaryKey;size:50"`
	Value     string    `gorm:"size:20;not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (bootstrapState) TableName() string {
	return "securehr_bootstrap_state"
}

func Initialize(db *gorm.DB) error {
	if !db.Migrator().HasTable(&bootstrapState{}) {
		if err := db.Migrator().CreateTable(&bootstrapState{}); err != nil {
			return fmt.Errorf("create bootstrap state table: %w", err)
		}
	} else if db.Migrator().HasColumn(&bootstrapState{}, "key") &&
		!db.Migrator().HasColumn(&bootstrapState{}, "bootstrap_key") {
		if err := db.Migrator().RenameColumn(&bootstrapState{}, "key", "bootstrap_key"); err != nil {
			return fmt.Errorf("rename bootstrap key column: %w", err)
		}
	}

	schemaVersion, err := getBootstrapVersion(db, "schema")
	if err != nil {
		return err
	}
	if schemaVersion < currentSchemaVersion {
		if err := db.AutoMigrate(&model.Role{}, &model.Employee{}, &model.User{}, &model.Department{}, &model.Position{}, &model.Attendance{}, &model.LeaveRequest{}, &model.RefreshToken{}); err != nil {
			return fmt.Errorf("database migration: %w", err)
		}
		if err := setBootstrapVersion(db, "schema", currentSchemaVersion); err != nil {
			return err
		}
	}

	seedVersion, err := getBootstrapVersion(db, "seed")
	if err != nil {
		return err
	}
	if seedVersion < currentSeedVersion {
		if err := seeder.Seed(db); err != nil {
			return fmt.Errorf("database seed: %w", err)
		}
		if err := setBootstrapVersion(db, "seed", currentSeedVersion); err != nil {
			return err
		}
	}
	return nil
}

func getBootstrapVersion(db *gorm.DB, key string) (int, error) {
	var state bootstrapState
	err := db.First(&state, "bootstrap_key = ?", key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read bootstrap version %s: %w", key, err)
	}
	version, err := strconv.Atoi(state.Value)
	if err != nil {
		return 0, fmt.Errorf("parse bootstrap version %s: %w", key, err)
	}
	return version, nil
}

func setBootstrapVersion(db *gorm.DB, key string, version int) error {
	state := bootstrapState{Key: key, Value: strconv.Itoa(version), UpdatedAt: time.Now()}
	if err := db.Save(&state).Error; err != nil {
		return fmt.Errorf("save bootstrap version %s: %w", key, err)
	}
	return nil
}
