package db

import (
	"database/sql"
	"fmt"
	"log"

	"restfulapi/config"

	_ "github.com/lib/pq"
)

func NewPostgres(cfg config.PostgresConfig) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func SetupDatabase(cfg config.PostgresConfig) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	if err := db.Ping(); err != nil {
		return err
	}

	_, err = db.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)
	if err != nil {
		log.Fatalf("failed to add uuid extension: %s", err)
	}

	// Clean Up Database During Development
	_, err = db.Exec("DROP TABLE users")
	if err != nil {
		log.Fatal(err)
	}

	// Setup Schemas
	_, err = db.Exec(GetUserTableQuery())
	if err != nil {
		return err
	}

	_, err = db.Exec(GetUserTableQuery())
	if err != nil {
		return err
	}

	return nil
}

func GetUserTableQuery() string {
	return `
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            email TEXT NOT NULL UNIQUE,
            email_verification_code TEXT NOT NULL,
            email_verified BOOLEAN DEFAULT FALSE,
            password TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )
    `
}

func GetPasswordResetTokenTableQuery() string {
	return `
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID NOT NULL UNIQUE,
            password_reset_code TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT now()
        )
    `
}
