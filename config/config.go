package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

var (
	ErrMissingRequiredConfig = errors.New("missing required configuration")
)

// Config holds all configuration for our service
type Config struct {
	// Server configuration
	Server struct {
		Port         string
		Host         string
		ReadTimeout  time.Duration
		WriteTimeout time.Duration
		Environment  string // development, staging, production
	}

	// Database configuration
	Database struct {
		Host     string
		Port     string
		User     string
		Password string
		Name     string
		SSLMode  string
		URL      string // Computed connection string
	}

	// JWT configuration
	JWT struct {
		Secret          string
		ExpirationHours int
		Issuer          string
		SigningMethod   string
	}

	// Rate limiting
	RateLimit struct {
		Enabled   bool
		Requests  int
		Duration  time.Duration
		WhiteList []string
	}

	// CORS configuration
	CORS struct {
		Enabled          bool
		AllowOrigins     []string
		AllowMethods     []string
		AllowHeaders     []string
		ExposeHeaders    []string
		AllowCredentials bool
		MaxAge           int
	}
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	config := &Config{}

	// Server configuration
	config.Server.Port = getEnv("PORT", "8080")
	config.Server.Host = getEnv("HOST", "0.0.0.0")
	config.Server.Environment = getEnv("ENVIRONMENT", "development")
	config.Server.ReadTimeout = getDurationEnv("READ_TIMEOUT", 10*time.Second)
	config.Server.WriteTimeout = getDurationEnv("WRITE_TIMEOUT", 10*time.Second)

	// Database configuration
	config.Database.Host = getEnv("DB_HOST", "localhost")
	config.Database.Port = getEnv("DB_PORT", "5432")
	config.Database.User = getEnv("DB_USER", "postgres")
	config.Database.Password = getEnv("DB_PASSWORD", "")
	config.Database.Name = getEnv("DB_NAME", "user_service")
	config.Database.SSLMode = getEnv("DB_SSLMODE", "disable")

	// Allow overriding the complete database URL
	dbURL := getEnv("DATABASE_URL", "")
	if dbURL != "" {
		config.Database.URL = dbURL
	} else {
		// Construct database URL
		config.Database.URL = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=%s",
			config.Database.User,
			config.Database.Password,
			config.Database.Host,
			config.Database.Port,
			config.Database.Name,
			config.Database.SSLMode,
		)
	}

	// JWT configuration
	config.JWT.Secret = getEnv("JWT_SECRET", "")
	config.JWT.ExpirationHours = getIntEnv("JWT_EXPIRATION_HOURS", 24)
	config.JWT.Issuer = getEnv("JWT_ISSUER", "user-service")
	config.JWT.SigningMethod = getEnv("JWT_SIGNING_METHOD", "HS256")

	// Rate limiting configuration
	config.RateLimit.Enabled = getBoolEnv("RATE_LIMIT_ENABLED", true)
	config.RateLimit.Requests = getIntEnv("RATE_LIMIT_REQUESTS", 100)
	config.RateLimit.Duration = getDurationEnv("RATE_LIMIT_DURATION", time.Minute)
	config.RateLimit.WhiteList = getSliceEnv("RATE_LIMIT_WHITELIST", []string{})

	// CORS configuration
	config.CORS.Enabled = getBoolEnv("CORS_ENABLED", true)
	config.CORS.AllowOrigins = getSliceEnv("CORS_ALLOW_ORIGINS", []string{"*"})
	config.CORS.AllowMethods = getSliceEnv("CORS_ALLOW_METHODS", []string{
		"GET", "POST", "PUT", "DELETE", "OPTIONS",
	})
	config.CORS.AllowHeaders = getSliceEnv("CORS_ALLOW_HEADERS", []string{
		"Origin", "Content-Type", "Accept", "Authorization",
	})
	config.CORS.ExposeHeaders = getSliceEnv("CORS_EXPOSE_HEADERS", []string{})
	config.CORS.AllowCredentials = getBoolEnv("CORS_ALLOW_CREDENTIALS", true)
	config.CORS.MaxAge = getIntEnv("CORS_MAX_AGE", 24*60*60)

	// Validate required configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Load function to load configuration
func Load() (*Config, error) {
	cfg := &Config{}
	// Set defaults for demo; in production, load from env or file
	cfg.Server.Port = "8080"
	cfg.Server.Host = "localhost"
	cfg.Server.Environment = "development"
	cfg.Database.Host = "localhost"
	cfg.Database.Port = "5432"
	cfg.Database.User = "user"
	cfg.Database.Password = "pass"
	cfg.Database.Name = "noxstack_user"
	cfg.Database.SSLMode = "disable"
	cfg.Database.URL = "postgres://user:pass@localhost:5432/noxstack_user?sslmode=disable"
	cfg.JWT.Secret = "secret"
	cfg.JWT.ExpirationHours = 24
	cfg.JWT.Issuer = "user-service"
	cfg.JWT.SigningMethod = "HS256"
	return cfg, nil
}

// Validate checks if all required configuration is present
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return fmt.Errorf("%w: JWT_SECRET is required", ErrMissingRequiredConfig)
	}

	if c.Database.URL == "" {
		return fmt.Errorf("%w: DATABASE_URL is required", ErrMissingRequiredConfig)
	}

	return nil
}

// Helper functions for environment variable loading

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		boolValue, err := strconv.ParseBool(value)
		if err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		intValue, err := strconv.Atoi(value)
		if err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		duration, err := time.ParseDuration(value)
		if err == nil {
			return duration
		}
	}
	return defaultValue
}

func getSliceEnv(key string, defaultValue []string) []string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return splitAndTrim(value)
	}
	return defaultValue
}

func splitAndTrim(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
