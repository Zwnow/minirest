package config

import (
	"fmt"
	"os"
	"strconv"
)

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type MailjetConfig struct {
	Active string
	Key    string
	Secret string
}

type GeneralConfig struct {
	BaseURL string
	JwtKey  string
}

type Config struct {
	Postgres PostgresConfig
	Mailjet  MailjetConfig
	General  GeneralConfig
}

func Load() Config {
	port, err := strconv.Atoi(getEnv("POSTGRES_PORT", "5432"))
	if err != nil {
		panic(fmt.Sprintf("Invalid POSTGRES_PORT: %v", err))
	}

	return Config{
		Postgres: PostgresConfig{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     port,
			User:     getEnv("POSTGRES_USER", "user"),
			Password: getEnv("POSTGRES_PASSWORD", "password"),
			DBName:   getEnv("POSTGRES_DB", "devdb"),
			SSLMode:  getEnv("POSTGRES_SSLMODE", "disable"),
		},
		Mailjet: MailjetConfig{
			Active: getEnv("MAIL_ACTIVE", "false"),
			Key:    getEnv("MAILJET_KEY", ""),
			Secret: getEnv("MAILJET_SECRET", ""),
		},
		General: GeneralConfig{
			BaseURL: getEnv("BASE_URL", "http://localhost:8080"),
			JwtKey:  getEnv("JWT_KEY", ""),
		},
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return fallback
}
