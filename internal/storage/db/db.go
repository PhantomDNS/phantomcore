package db

import (
	"log"
	"time"

	"github.com/glebarez/sqlite" // <-- use this, pure-Go driver
	"github.com/lopster568/phantomDNS/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init initializes SQLite with sane defaults.
func InitDB(path string) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn), // reduce noise
	})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Connection pool tuning
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // SQLite is single-writer
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Enable WAL for better concurrency
	db.Exec("PRAGMA journal_mode=WAL;")

	// Run migrations
	if err := migrate(db); err != nil {
		log.Fatalf("migration failed: %v", err)
	}

	log.Println("Database connection established")

	DB = db
	return DB
}

func migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Policy{},
		&models.DNSQuery{},
	)
}
