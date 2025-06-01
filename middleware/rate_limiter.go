package middleware

import (
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/time/rate"
)

// RateLimitStore handles storage of rate limiters
type RateLimitStore struct {
	sync.RWMutex
	limiters map[string]*rate.Limiter
	cleanup  time.Duration
}

// RateLimitConfig defines the configuration for rate limiting
type RateLimitConfig struct {
	// Max requests per duration
	Max int
	// Time window for rate limiting
	Duration time.Duration
	// Key function to determine rate limit bucket
	KeyFunc func(*fiber.Ctx) string
	// Skip rate limiting for certain requests
	SkipFunc func(*fiber.Ctx) bool
	// Whitelist of IPs or users
	Whitelist []string
	// Time after which unused limiters are cleaned up
	Cleanup time.Duration
	// Custom error handler
	ErrorHandler fiber.ErrorHandler
}

// DefaultRateLimitConfig returns the default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Max:      100,
		Duration: time.Minute,
		KeyFunc: func(c *fiber.Ctx) string {
			// Use user ID if authenticated, otherwise use IP
			if userID := GetUserID(c); userID != "" {
				return fmt.Sprintf("user:%s", userID)
			}
			return fmt.Sprintf("ip:%s", c.IP())
		},
		Cleanup: time.Hour,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		},
	}
}

// newRateLimitStore creates a new rate limit store
func newRateLimitStore(cleanup time.Duration) *RateLimitStore {
	store := &RateLimitStore{
		limiters: make(map[string]*rate.Limiter),
		cleanup:  cleanup,
	}

	// Start cleanup routine
	go store.startCleanup()
	return store
}

// getLimiter returns the rate limiter for the given key
func (s *RateLimitStore) getLimiter(key string, r rate.Limit, burst int) *rate.Limiter {
	s.RLock()
	limiter, exists := s.limiters[key]
	s.RUnlock()

	if exists {
		return limiter
	}

	s.Lock()
	defer s.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists = s.limiters[key]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(r, burst)
	s.limiters[key] = limiter
	return limiter
}

// cleanup removes unused limiters
func (s *RateLimitStore) startCleanup() {
	ticker := time.NewTicker(s.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		s.Lock()
		for key := range s.limiters {
			delete(s.limiters, key)
		}
		s.Unlock()
	}
}

// RateLimit creates a rate limiting middleware
func RateLimit(config ...RateLimitConfig) fiber.Handler {
	// Set default config
	cfg := DefaultRateLimitConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	// Create limiter store
	store := newRateLimitStore(cfg.Cleanup)

	// Convert max requests per duration to rate.Limit
	limit := rate.Every(cfg.Duration / time.Duration(cfg.Max))

	return func(c *fiber.Ctx) error {
		// Skip if needed
		if cfg.SkipFunc != nil && cfg.SkipFunc(c) {
			return c.Next()
		}

		// Check whitelist
		key := cfg.KeyFunc(c)
		for _, whitelisted := range cfg.Whitelist {
			if key == whitelisted {
				return c.Next()
			}
		}

		// Get limiter for this key
		limiter := store.getLimiter(key, limit, cfg.Max)

		// Try to allow request
		if !limiter.Allow() {
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, nil)
			}
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		}

		// Add rate limit headers
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", cfg.Max))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%.0f", limiter.Tokens()))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(cfg.Duration).Unix()))

		return c.Next()
	}
}

// UserRateLimit creates a rate limiter specifically for authenticated users
func UserRateLimit(max int, duration time.Duration) fiber.Handler {
	return RateLimit(RateLimitConfig{
		Max:      max,
		Duration: duration,
		KeyFunc: func(c *fiber.Ctx) string {
			return fmt.Sprintf("user:%s", GetUserID(c))
		},
		SkipFunc: func(c *fiber.Ctx) bool {
			return GetUserID(c) == "" // Skip if not authenticated
		},
	})
}

// IPRateLimit creates a rate limiter based on IP addresses
func IPRateLimit(max int, duration time.Duration) fiber.Handler {
	return RateLimit(RateLimitConfig{
		Max:      max,
		Duration: duration,
		KeyFunc: func(c *fiber.Ctx) string {
			return fmt.Sprintf("ip:%s", c.IP())
		},
	})
}
