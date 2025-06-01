package middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrMissingToken = errors.New("missing authorization token")
	ErrInvalidToken = errors.New("invalid authorization token")
	ErrExpiredToken = errors.New("token has expired")
)

// Config holds the configuration for the JWT middleware
type Config struct {
	SigningKey       []byte
	TokenLookup      string   // e.g., "header:Authorization"
	AuthScheme       string   // e.g., "Bearer"
	ContextKey       string   // Key to store user claims in context
	Claims           jwt.MapClaims
	ErrorHandler     fiber.ErrorHandler
	SuccessHandler   fiber.Handler
	SkipPaths        []string // Paths to skip authentication
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		TokenLookup:    "header:Authorization",
		AuthScheme:     "Bearer",
		ContextKey:     "user",
		ErrorHandler:   defaultErrorHandler,
		SkipPaths:      []string{},
	}
}

// JWTProtected creates a JWT protection middleware with custom config
func JWTProtected(config ...Config) fiber.Handler {
	// Set default config
	cfg := DefaultConfig()
	
	// Override config if provided
	if len(config) > 0 {
		cfg = config[0]
	}

	// Set default error handler if not provided
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}

	// Return middleware handler
	return func(c *fiber.Ctx) error {
		// Check if path should be skipped
		path := c.Path()
		for _, skip := range cfg.SkipPaths {
			if strings.HasPrefix(path, skip) {
				return c.Next()
			}
		}

		// Extract token
		token, err := extractToken(c, cfg)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Parse and validate token
		claims, err := validateToken(token, cfg.SigningKey)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Store user information in context
		c.Locals(cfg.ContextKey, claims)
		// Store user ID in a dedicated context key for easy access
		if userID, ok := claims["user_id"].(string); ok {
			c.Locals("userID", userID)
		}

		// Call success handler if provided
		if cfg.SuccessHandler != nil {
			return cfg.SuccessHandler(c)
		}

		return c.Next()
	}
}

// extractToken extracts the JWT token from the request
func extractToken(c *fiber.Ctx, config Config) (string, error) {
	parts := strings.Split(config.TokenLookup, ":")
	if len(parts) != 2 {
		return "", ErrInvalidToken
	}

	switch parts[0] {
	case "header":
		// Get token from header
		auth := c.Get(parts[1])
		if auth == "" {
			return "", ErrMissingToken
		}

		// Check if the header contains the correct scheme
		if config.AuthScheme != "" {
			schemeLen := len(config.AuthScheme)
			if len(auth) > schemeLen+1 && auth[:schemeLen] == config.AuthScheme {
				return auth[schemeLen+1:], nil
			}
			return "", ErrInvalidToken
		}
		return auth, nil

	case "query":
		// Get token from query parameter
		token := c.Query(parts[1])
		if token == "" {
			return "", ErrMissingToken
		}
		return token, nil

	case "cookie":
		// Get token from cookie
		token := c.Cookies(parts[1])
		if token == "" {
			return "", ErrMissingToken
		}
		return token, nil

	default:
		return "", ErrInvalidToken
	}
}

// validateToken validates the JWT token
func validateToken(tokenString string, signingKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return signingKey, nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, ErrExpiredToken
		}
	}

	return claims, nil
}

// defaultErrorHandler handles authentication errors
func defaultErrorHandler(c *fiber.Ctx, err error) error {
	var statusCode int
	var message string

	switch err {
	case ErrMissingToken:
		statusCode = fiber.StatusUnauthorized
		message = "Missing authorization token"
	case ErrInvalidToken:
		statusCode = fiber.StatusUnauthorized
		message = "Invalid authorization token"
	case ErrExpiredToken:
		statusCode = fiber.StatusUnauthorized
		message = "Token has expired"
	default:
		statusCode = fiber.StatusInternalServerError
		message = "Internal server error"
	}

	return c.Status(statusCode).JSON(fiber.Map{
		"error": message,
	})
}

// GetUserID extracts the user ID from the context
func GetUserID(c *fiber.Ctx) string {
	// First try the dedicated userID key
	if userID, ok := c.Locals("userID").(string); ok {
		return userID
	}
	
	// Fall back to extracting from claims
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		return ""
	}
	
	userID, ok := claims["user_id"].(string)
	if !ok {
		return ""
	}
	
	return userID
}

// GetUserEmail extracts the user email from the context
func GetUserEmail(c *fiber.Ctx) string {
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		return ""
	}
	
	email, ok := claims["email"].(string)
	if !ok {
		return ""
	}
	
	return email
}

// GetUsername extracts the username from the context
func GetUsername(c *fiber.Ctx) string {
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		return ""
	}
	
	username, ok := claims["username"].(string)
	if !ok {
		return ""
	}
	
	return username
}

// IsAuthenticated checks if the request is authenticated
func IsAuthenticated(c *fiber.Ctx) bool {
	return c.Locals("user") != nil
}

