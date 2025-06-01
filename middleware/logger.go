package middleware

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogConfig defines the config for logger middleware
type LogConfig struct {
	// Logger instance
	Logger *zap.Logger
	// Skip logging for paths
	SkipPaths []string
	// Log level for requests
	Level zapcore.Level
	// Skip logging of specific headers (e.g., Authorization)
	SkipHeaders []string
	// Maximum length of logged request/response body
	MaxBodySize int
	// Whether to log request bodies
	LogRequestBody bool
	// Whether to log response bodies
	LogResponseBody bool
}

// DefaultLogConfig returns the default logging configuration
func DefaultLogConfig() LogConfig {
	logger, _ := zap.NewProduction()
	return LogConfig{
		Logger:          logger,
		Level:           zapcore.InfoLevel,
		SkipHeaders:     []string{"Authorization", "Cookie"},
		MaxBodySize:     1024, // 1KB
		LogRequestBody:  true,
		LogResponseBody: false,
	}
}

// Logger returns a Fiber middleware for logging HTTP requests
func Logger(config ...LogConfig) fiber.Handler {
	// Set default config
	cfg := DefaultLogConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx) error {
		// Skip logging for specified paths
		path := c.Path()
		for _, skip := range cfg.SkipPaths {
			if strings.HasPrefix(path, skip) {
				return c.Next()
			}
		}

		start := time.Now()
		requestID := uuid.New().String()
		c.Locals("request_id", requestID)

		// Get request body if enabled
		var requestBody string
		if cfg.LogRequestBody && c.Request().Body() != nil {
			body := c.Request().Body()
			if len(body) > cfg.MaxBodySize {
				requestBody = string(body[:cfg.MaxBodySize]) + "..."
			} else {
				requestBody = string(body)
			}
		}

		// Create response body buffer
		var responseBuffer bytes.Buffer
		// c.Response().SetBodyWriter(responseWriter) // Remove or comment out this line

		// Process request
		err := c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get user ID if authenticated
		userID := "anonymous"
		if id := GetUserID(c); id != "" {
			userID = id
		}

		// Prepare log fields
		fields := []zapcore.Field{
			zap.String("request_id", requestID),
			zap.String("user_id", userID),
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
			zap.String("ip", c.IP()),
			zap.Int("status", c.Response().StatusCode()),
			zap.Duration("duration", duration),
			zap.String("user_agent", c.Get("User-Agent")),
		}

		// Add request headers (excluding skipped ones)
		headers := make(map[string]string)
		c.Request().Header.VisitAll(func(key, value []byte) {
			headerKey := string(key)
			if !contains(cfg.SkipHeaders, headerKey) {
				headers[headerKey] = string(value)
			}
		})
		fields = append(fields, zap.Any("headers", headers))

		// Add request body if enabled and present
		if cfg.LogRequestBody && requestBody != "" {
			fields = append(fields, zap.String("request_body", sanitizeJSON(requestBody)))
		}

		// Add response body if enabled
		if cfg.LogResponseBody {
			responseBody := responseBuffer.String()
			if len(responseBody) > cfg.MaxBodySize {
				responseBody = responseBody[:cfg.MaxBodySize] + "..."
			}
			fields = append(fields, zap.String("response_body", sanitizeJSON(responseBody)))
		}

		// Add error if present
		if err != nil {
			fields = append(fields, zap.Error(err))
		}

		// Log with appropriate level based on status code
		statusCode := c.Response().StatusCode()
		switch {
		case statusCode >= 500:
			cfg.Logger.Error("Server error", fields...)
		case statusCode >= 400:
			cfg.Logger.Warn("Client error", fields...)
		default:
			cfg.Logger.Info("Request completed", fields...)
		}

		return err
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func sanitizeJSON(input string) string {
	// Try to parse as JSON to ensure it's valid
	var parsed interface{}
	if err := json.Unmarshal([]byte(input), &parsed); err != nil {
		return input // Return as-is if not JSON
	}

	// Re-encode with indentation for readability
	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return input
	}
	return string(pretty)
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Locals("request_id", requestID)
		c.Set("X-Request-ID", requestID)
		return c.Next()
	}
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(c *fiber.Ctx) string {
	if requestID, ok := c.Locals("request_id").(string); ok {
		return requestID
	}
	return ""
}
