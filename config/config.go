package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

// Config holds the global configuration for NodeGoDNS.
type Config struct {
	DBType               string        `validate:"omitempty,oneof=sqlite postgres"`
	DatabaseURL          string        `validate:"required_if=DBType postgres"`
	JWTSecret            string        `validate:"required,min=10"`
	TLSCertFile          string        `validate:"required,file"`
	TLSKeyFile           string        `validate:"required,file"`
	LogLevel             string        `validate:"oneof=debug info warn error"`
	ZonesDir             string        `validate:"required,dir"`
	BackupDir            string        `validate:"required,dir"`
	ZonesBackupDir       string        `validate:"required,dir"`
	KeysBackupDir        string        `validate:"required,dir"`
	HTTPPort             string        `validate:"required,port"`
	DNSPort              string        `validate:"required,port"`
	GRPCPort             string        `validate:"required,port"`
	MaxBackups           int           `validate:"gte=1,lte=100"`
	CacheDefaultTTL      time.Duration `validate:"gte=0"`
	CacheCleanupInterval time.Duration `validate:"gte=0"`
}

// LoadConfig loads configuration from environment variables and an optional .env file.
func LoadConfig() Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; relying on environment variables.")
	}

	getEnv := func(key, fallback string) string {
		if value, exists := os.LookupEnv(key); exists {
			return value
		}
		return fallback
	}

	getEnvAsInt := func(key string, fallback int) int {
		if valueStr, exists := os.LookupEnv(key); exists {
			if value, err := strconv.Atoi(valueStr); err == nil {
				return value
			}
		}
		return fallback
	}

	getEnvAsDuration := func(key string, fallback time.Duration) time.Duration {
		if valueStr, exists := os.LookupEnv(key); exists {
			if value, err := time.ParseDuration(valueStr); err == nil {
				return value
			}
		}
		return fallback
	}

	cfg := Config{
		DBType:               getEnv("DB_TYPE", "sqlite"), // Default to sqlite
		DatabaseURL:          getEnv("DATABASE_URL", ""),
		JWTSecret:            getEnv("JWT_SECRET", "default_jwt_secret"),
		TLSCertFile:          getEnv("TLS_CERT_FILE", "certs/cert.pem"),
		TLSKeyFile:           getEnv("TLS_KEY_FILE", "certs/key.pem"),
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		ZonesDir:             getEnv("ZONES_DIR", "zones"),
		BackupDir:            getEnv("BACKUP_DIR", "backups"),
		ZonesBackupDir:       getEnv("ZONES_BACKUP_DIR", "backups/zones"),
		KeysBackupDir:        getEnv("KEYS_BACKUP_DIR", "backups/keys"),
		HTTPPort:             getEnv("HTTP_PORT", ":8443"),
		DNSPort:              getEnv("DNS_PORT", ":53"),
		GRPCPort:             getEnv("GRPC_PORT", ":50051"),
		MaxBackups:           getEnvAsInt("MAX_BACKUP_COPIES", 10),
		CacheDefaultTTL:      getEnvAsDuration("CACHE_DEFAULT_TTL", 5*time.Minute),
		CacheCleanupInterval: getEnvAsDuration("CACHE_CLEANUP_INTERVAL", 10*time.Minute),
	}

	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		log.Fatalf("Configuration validation error: %v", err)
	}

	return cfg
}
