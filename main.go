package main

import (
	"database/sql"
	"log"
	"time"

	"consolidated-user-service/config"
	"consolidated-user-service/controllers"
	"consolidated-user-service/middleware"
	"consolidated-user-service/repository"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	// "github.com/gofiber/swagger"
	_ "github.com/lib/pq"
)

// @title Consolidated User Service API
// @version 1.0
// @description API for user authentication, profile management, and session handling
// @contact.name NoxStack Development Team
// @contact.email dev@noxstack.com
// @license.name MIT
// @host localhost:8080
// @BasePath /api/v1
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Connect to the database
	db, err := sql.Open("postgres", cfg.Database.URL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}

	// Initialize repositories
	repo := repository.NewPostgresUserRepository(db)
	userController := controllers.NewUserController(repo)

	// Initialize AuthController with repository and config
	authController := controllers.NewAuthController(repo, cfg)

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: middleware.DefaultConfig().ErrorHandler,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// API routes
	api := app.Group("/api/v1")

	// Serve OpenAPI YAML at /docs/openapi.yaml (use absolute path for reliability)
	app.Static("/docs/openapi.yaml", "docs/openapi.yaml")

	// Serve Swagger UI at /docs
	app.Get("/docs", func(c *fiber.Ctx) error {
		html := `<!DOCTYPE html>
<html>
<head>
  <title>Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: '/docs/openapi.yaml',
        dom_id: '#swagger-ui',
      });
    };
  </script>
</body>
</html>`
		return c.Type("html").SendString(html)
	})
	// Auth routes
	auth := api.Group("/auth")
	auth.Post("/signup/email", authController.Signup)
	auth.Post("/register", authController.Signup)
	auth.Post("/verify-email", authController.VerifyEmail)
	auth.Post("/create-profile/email", authController.CreateProfile)
	auth.Post("/signup/phone", authController.SignupPhone)
	auth.Post("/verify-otp", authController.VerifyPhoneOTP)
	auth.Post("/create-profile/phone", authController.CreatePhoneProfile)
	auth.Post("/signin/email", authController.SigninEmail)
	auth.Post("/login", authController.SigninEmail)
	auth.Post("/signin/phone", authController.SigninPhone)
	auth.Post("/forgot-password", authController.ForgotPassword)
	auth.Post("/verify-reset-code", authController.VerifyResetCode)
	auth.Post("/reset-password", authController.ResetPassword)
	auth.Post("/refresh", authController.RefreshToken)
	auth.Post("/google", authController.GoogleAuth)
	auth.Get("/callback", authController.GoogleCallback)

	// User routes
	users := api.Group("/users")
	users.Use(middleware.JWTProtected(middleware.Config{
		SigningKey:  []byte(cfg.JWT.Secret),
		TokenLookup: "header:Authorization",
		AuthScheme:  "Bearer",
		ContextKey:  "user",
	}))
	users.Get("/me", userController.GetProfile)
	users.Get("/:id", userController.GetUser) // Get specific user (for admins or public profiles)
	users.Put("/me", userController.UpdateProfile)
	users.Put("/:id", userController.UpdateUser) // Update specific user (admin only)
	users.Delete("/me", userController.DeleteAccount)
	users.Put("/me/location", userController.UpdateLocation)
	users.Get("/me/preferences", userController.GetPreferences)
	users.Put("/me/preferences", userController.UpdatePreferences)
	users.Put("/me/password", userController.ChangePassword)
	users.Get("/me/services", userController.GetServicesOffered)
	users.Put("/me/services", userController.UpdateServicesOffered)

	// Session management routes
	sessions := api.Group("/sessions")
	sessions.Use(middleware.JWTProtected(middleware.Config{
		SigningKey:  []byte(cfg.JWT.Secret),
		TokenLookup: "header:Authorization",
		AuthScheme:  "Bearer",
		ContextKey:  "user",
	}))
	sessions.Post("/", userController.CreateSession)
	sessions.Get("/", userController.GetActiveSessions)
	sessions.Delete("/:id", userController.DeleteSession)
	sessions.Delete("/", userController.DeleteAllSessions)

	// Admin routes
	admin := api.Group("/admin")
	admin.Use(middleware.JWTProtected(middleware.Config{
		SigningKey:  []byte(cfg.JWT.Secret),
		TokenLookup: "header:Authorization",
		AuthScheme:  "Bearer",
		ContextKey:  "user",
	}) /* TODO: Add AdminOnly middleware if implemented */)
	admin.Get("/users", userController.ListUsers)
	admin.Get("/users/:id", userController.GetUser)
	admin.Put("/users/:id", userController.UpdateUser)
	admin.Delete("/users/:id", userController.DeleteUser)
	admin.Get("/stats", userController.GetUserStats)

	// Health check endpoint
	api.Get("/health", func(c *fiber.Ctx) error {
		// Simple health check - verify database connection
		if err := db.Ping(); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "unhealthy",
				"error":  "Database connection failed",
			})
		}
		return c.JSON(fiber.Map{
			"status":    "healthy",
			"service":   "user-service",
			"timestamp": time.Now().Unix(),
		})
	})

	// Start server
	log.Printf("Starting server on port %s", cfg.Server.Port)
	log.Fatal(app.Listen(":" + cfg.Server.Port))
}
