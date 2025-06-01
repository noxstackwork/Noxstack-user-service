package controllers

import (
	"database/sql"
	"fmt"
	"time"

	"consolidated-user-service/middleware"
	"consolidated-user-service/models"

	"github.com/gofiber/fiber/v2"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Models
type User struct {
	ID                       string         `json:"id"`
	Email                    string         `json:"email"`
	Phone                    string         `json:"phone,omitempty"`
	Username                 string         `json:"username"`
	FullName                 string         `json:"full_name,omitempty"`
	PasswordHash             string         `json:"-"`
	GoogleID                 string         `json:"google_id,omitempty"`
	IsEmailVerified          bool           `json:"is_email_verified"`
	IsPhoneVerified          bool           `json:"is_phone_verified"`
	Role                     string         `json:"role"`
	WillingToProvideServices bool           `json:"willing_to_provide_services"`
	Level                    int            `json:"level"`
	ServicesOffered          pq.StringArray `json:"services_offered"`
	Location                 string         `json:"location,omitempty"` // WKT or GeoJSON string
	Rating                   *float64       `json:"rating,omitempty"`   // Average rating (0-5)
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

type Profile struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	FullName    string    `json:"full_name"`
	Bio         string    `json:"bio,omitempty"`
	AvatarURL   string    `json:"avatar_url,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	Rating      *float64  `json:"rating,omitempty"` // User rating (0-5)
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	DeviceInfo   string    `json:"device_info,omitempty"`
	IsActive     bool      `json:"is_active"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=64"`
	FullName string `json:"full_name,omitempty" validate:"omitempty,max=255"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         User   `json:"user"`
	ExpiresAt    int64  `json:"expires_at"`
}

type EmailVerification struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

type PhoneOTP struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Phone     string    `json:"phone"`
	OTP       string    `json:"otp"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

type PasswordReset struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

type OAuthIdentity struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Provider   string    `json:"provider"`
	ProviderID string    `json:"provider_id"`
	Email      string    `json:"email"`
	CreatedAt  time.Time `json:"created_at"`
}

// Request DTOs for API endpoints
type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	FullName string `json:"full_name" validate:"required"`
	Role     string `json:"role" validate:"required,oneof=user creator"`
}

type CreateCreatorRequest struct {
	CreateUserRequest
	Services     []Service    `json:"services" validate:"required"`
	Location     Location     `json:"location" validate:"required"`
	Availability Availability `json:"availability" validate:"required"`
}

type Service struct {
	Name        string  `json:"name" validate:"required"`
	Description string  `json:"description"`
	Price       float64 `json:"price" validate:"required,min=0"`
	Duration    int     `json:"duration" validate:"required,min=1"` // in minutes
	Category    string  `json:"category" validate:"required"`
}

type Location struct {
	Address   string  `json:"address" validate:"required"`
	City      string  `json:"city" validate:"required"`
	State     string  `json:"state" validate:"required"`
	Country   string  `json:"country" validate:"required"`
	Latitude  float64 `json:"latitude" validate:"required"`
	Longitude float64 `json:"longitude" validate:"required"`
}

type Availability struct {
	Schedule []ScheduleSlot `json:"schedule" validate:"required"`
}

type ScheduleSlot struct {
	Day   string     `json:"day" validate:"required,oneof=monday tuesday wednesday thursday friday saturday sunday"`
	Slots []TimeSlot `json:"slots" validate:"required"`
}

type TimeSlot struct {
	Start string `json:"start" validate:"required"`
	End   string `json:"end" validate:"required"`
}

type UpdateUserRequest struct {
	Email                    string         `json:"email,omitempty" validate:"omitempty,email"`
	Phone                    string         `json:"phone,omitempty"`
	Username                 string         `json:"username,omitempty" validate:"omitempty,min=3,max=64"`
	FullName                 string         `json:"full_name,omitempty"`
	Role                     string         `json:"role,omitempty"`
	WillingToProvideServices *bool          `json:"willing_to_provide_services,omitempty"`
	ServicesOffered          pq.StringArray `json:"services_offered,omitempty"`
	Location                 string         `json:"location,omitempty"`
}

type UpdateProfileRequest struct {
	FullName    string `json:"full_name,omitempty"`
	Bio         string `json:"bio,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type SessionCreateRequest struct {
	DeviceInfo string `json:"device_info,omitempty"`
}

// UserController handles all user-related operations
type UserController struct {
	repo UserRepository
	db   *sql.DB
}

// NewUserController creates a new UserController instance
func NewUserController(repo UserRepository) *UserController {
	return &UserController{
		repo: repo,
	}
}

// Authentication methods

// Register handles user registration
func (uc *UserController) Register(c *fiber.Ctx) error {
	var req models.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Register user
	user, token, err := uc.repo.Register(c.Context(), req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(models.AuthResponse{
		Token:     token,
		User:      *user,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	})
}

// Login handles user authentication
func (uc *UserController) Login(c *fiber.Ctx) error {
	var req models.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Authenticate user
	authResp, err := uc.repo.Login(c.Context(), req)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	return c.JSON(authResp)
}

// User management methods

// CreateUser creates a new user
func (uc *UserController) CreateUser(c *fiber.Ctx) error {
	var user models.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate user data
	if user.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email is required",
		})
	}

	createdUser, err := uc.repo.CreateUser(c.Context(), user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(createdUser)
}

// GetUser retrieves user details by ID
func (uc *UserController) GetUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(user)
}

// UpdateUser updates user information
func (uc *UserController) UpdateUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	var user models.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	updatedUser, err := uc.repo.UpdateUser(c.Context(), userID, user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	return c.JSON(updatedUser)
}

// DeleteUser removes a user
func (uc *UserController) DeleteUser(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	if err := uc.repo.DeleteUser(c.Context(), userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ListCreators retrieves all users marked as creators
func (uc *UserController) ListCreators(c *fiber.Ctx) error {
	creators, err := uc.repo.ListCreators(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to list creators",
		})
	}

	return c.JSON(creators)
}

// ListUsers retrieves all users with pagination
func (uc *UserController) ListUsers(c *fiber.Ctx) error {
	offset := c.QueryInt("offset", 0)
	limit := c.QueryInt("limit", 10)

	users, err := uc.repo.ListUsers(c.Context(), offset, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to list users",
		})
	}

	return c.JSON(users)
}

// Profile management methods

// CreateProfile creates a profile for a user
func (uc *UserController) CreateProfile(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	var profile models.Profile
	if err := c.BodyParser(&profile); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	profile.UserID = userID
	createdProfile, err := uc.repo.CreateProfile(c.Context(), profile)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create profile",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(createdProfile)
}

// GetProfile retrieves a user's profile
func (uc *UserController) GetProfile(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(user)
}

// UpdateProfile updates a user's profile
func (uc *UserController) UpdateProfile(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var req struct {
		FullName  string `json:"full_name"`
		Bio       string `json:"bio"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	profile, err := uc.repo.GetProfile(c.Context(), userID)
	if err != nil {
		// If profile not found, create it
		if err.Error() == "profile not found" {
			newProfile := models.Profile{
				UserID:    userID,
				FullName:  req.FullName,
				Bio:       req.Bio,
				AvatarURL: req.AvatarURL,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			createdProfile, err := uc.repo.CreateProfile(c.Context(), newProfile)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create profile", "details": err.Error()})
			}
			return c.JSON(createdProfile)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get profile", "details": err.Error()})
	}

	if req.FullName != "" {
		profile.FullName = req.FullName
	}
	if req.Bio != "" {
		profile.Bio = req.Bio
	}
	if req.AvatarURL != "" {
		profile.AvatarURL = req.AvatarURL
	}

	updatedProfile, err := uc.repo.UpdateProfile(c.Context(), userID, *profile)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update profile", "details": err.Error()})
	}

	return c.JSON(updatedProfile)
}

// DeleteProfile removes a user's profile
func (uc *UserController) DeleteProfile(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	if err := uc.repo.DeleteProfile(c.Context(), userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete profile",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// Session management methods

// CreateSession creates a new session for a user
func (uc *UserController) CreateSession(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var req models.SessionCreateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	session, err := uc.repo.CreateSession(c.Context(), userID, req.DeviceInfo)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create session"})
	}

	return c.Status(fiber.StatusCreated).JSON(session)
}

// GetSession retrieves a session by ID
func (uc *UserController) GetSession(c *fiber.Ctx) error {
	sessionID := c.Params("session_id")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Session ID is required",
		})
	}

	session, err := uc.repo.GetSession(c.Context(), sessionID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	return c.JSON(session)
}

// GetActiveSessions retrieves all active sessions for a user
func (uc *UserController) GetActiveSessions(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	sessions, err := uc.repo.GetActiveSessionsByUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get active sessions"})
	}

	return c.JSON(sessions)
}

// DeleteSession removes a session
func (uc *UserController) DeleteSession(c *fiber.Ctx) error {
	sessionID := c.Params("session_id")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Session ID is required"})
	}

	if err := uc.repo.DeleteSession(c.Context(), sessionID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete session"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// DeleteAllSessions removes all sessions for a user
func (uc *UserController) DeleteAllSessions(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	if err := uc.repo.DeleteAllUserSessions(c.Context(), userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete sessions"})
	}

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

// Implement missing methods

// DeleteAccount handles user account deletion
func (uc *UserController) DeleteAccount(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	if err := uc.repo.DeleteUser(c.Context(), userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete account",
		})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// UpdateLocation updates user's location
func (uc *UserController) UpdateLocation(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var location struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	}
	if err := c.BodyParser(&location); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body", "details": err.Error()})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found", "details": err.Error()})
	}

	locationStr := fmt.Sprintf("POINT(%f %f)", location.Longitude, location.Latitude)
	user.Location = locationStr

	_, err = uc.repo.UpdateUser(c.Context(), userID, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update location", "details": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Location updated successfully",
		"status":  "success",
	})
}

// GetPreferences retrieves user preferences
func (uc *UserController) GetPreferences(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	preferences := fiber.Map{
		"willing_to_provide_services": user.WillingToProvideServices,
		"services_offered":            user.ServicesOffered,
		"location":                    user.Location,
	}

	return c.JSON(preferences)
}

// UpdatePreferences updates user preferences
func (uc *UserController) UpdatePreferences(c *fiber.Ctx) error {
	userID := c.Params("id")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "User ID is required",
		})
	}

	var preferences struct {
		WillingToProvideServices *bool          `json:"willing_to_provide_services"`
		ServicesOffered          pq.StringArray `json:"services_offered"`
	}

	if err := c.BodyParser(&preferences); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	if preferences.WillingToProvideServices != nil {
		user.WillingToProvideServices = *preferences.WillingToProvideServices
	}
	if preferences.ServicesOffered != nil {
		user.ServicesOffered = preferences.ServicesOffered
	}

	updatedUser, err := uc.repo.UpdateUser(c.Context(), userID, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update preferences",
		})
	}

	return c.JSON(updatedUser)
}

// ChangePassword handles password change
func (uc *UserController) ChangePassword(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body", "details": err.Error()})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found", "details": err.Error()})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Current password is incorrect", "details": err.Error()})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password", "details": err.Error()})
	}

	if err := uc.repo.UpdatePassword(c.Context(), userID, string(hashedPassword)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password", "details": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Password changed successfully",
	})
}

// GetServicesOffered retrieves services offered by a user
func (uc *UserController) GetServicesOffered(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	services, err := uc.repo.GetServicesOffered(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get services"})
	}

	return c.Status(fiber.StatusOK).JSON(services)
}

// UpdateServicesOffered updates services offered by a user
func (uc *UserController) UpdateServicesOffered(c *fiber.Ctx) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	var servicesPayload struct {
		Services []string `json:"services"`
	}
	var services []models.Service
	var serviceNames pq.StringArray

	if err := c.BodyParser(&servicesPayload); err == nil && len(servicesPayload.Services) > 0 {
		// Handle {"services": ["service1", ...]}
		serviceNames = servicesPayload.Services
	} else if err := c.BodyParser(&services); err == nil && len(services) > 0 {
		// Handle array of Service objects
		serviceNames = make(pq.StringArray, len(services))
		for i, service := range services {
			serviceNames[i] = service.Name
		}
	} else {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	user, err := uc.repo.GetUser(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	user.ServicesOffered = serviceNames
	_, err = uc.repo.UpdateUser(c.Context(), userID, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update services"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Services updated successfully",
		"status":  "success",
	})
}

// GetUserStats returns user statistics (admin only)
func (uc *UserController) GetUserStats(c *fiber.Ctx) error {
	stats, err := uc.repo.GetUserStats(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get user statistics",
		})
	}

	return c.JSON(stats)
}
