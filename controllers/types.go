package controllers

import (
	"consolidated-user-service/models"
	"context"
)

// UserRepository defines the interface for user-related database operations
type UserRepository interface {
	// Authentication
	Register(ctx context.Context, req models.RegisterRequest) (*models.User, string, error)
	Login(ctx context.Context, req models.LoginRequest) (*models.AuthResponse, error)

	// User management
	CreateUser(ctx context.Context, user models.User) (*models.User, error)
	GetUser(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*models.User, error)
	UpdateUser(ctx context.Context, id string, user models.User) (*models.User, error)
	DeleteUser(ctx context.Context, id string) error
	ListCreators(ctx context.Context) ([]models.User, error)
	ListUsers(ctx context.Context, offset, limit int) ([]models.User, error)

	// Profile management
	CreateProfile(ctx context.Context, profile models.Profile) (*models.Profile, error)
	GetProfile(ctx context.Context, userID string) (*models.Profile, error)
	UpdateProfile(ctx context.Context, userID string, profile models.Profile) (*models.Profile, error)
	DeleteProfile(ctx context.Context, userID string) error

	// Session management
	CreateSession(ctx context.Context, userID string, deviceInfo string) (*models.Session, error)
	GetSession(ctx context.Context, sessionID string) (*models.Session, error)
	GetActiveSessionsByUser(ctx context.Context, userID string) ([]models.Session, error)
	RefreshSession(ctx context.Context, refreshToken string) (*models.Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteAllUserSessions(ctx context.Context, userID string) error

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string) (*models.EmailVerification, error)
	GetEmailVerification(ctx context.Context, email string) (*models.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id string) error
	DeleteEmailVerification(ctx context.Context, userID string) error

	// Phone OTP
	CreatePhoneOTP(ctx context.Context, userID, phone string) (*models.PhoneOTP, error)
	GetPhoneOTP(ctx context.Context, userID string) (*models.PhoneOTP, error)
	DeletePhoneOTP(ctx context.Context, userID string) error

	// Password reset
	CreatePasswordReset(ctx context.Context, userID string) (*models.PasswordReset, error)
	GetPasswordReset(ctx context.Context, userID string) (*models.PasswordReset, error)
	DeletePasswordReset(ctx context.Context, userID string) error

	// OAuth management
	CreateOAuthIdentity(ctx context.Context, userID, provider, providerID, email string) (*models.OAuthIdentity, error)
	GetOAuthIdentity(ctx context.Context, userID string) (*models.OAuthIdentity, error)
	DeleteOAuthIdentity(ctx context.Context, userID string) error

	// Additional methods
	CreateUserWithEmail(ctx context.Context, email, passwordHash, fullName string) (string, error)
	MarkEmailVerified(ctx context.Context, userID string) error
	MarkPhoneVerified(ctx context.Context, userID string) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	GetUserStats(ctx context.Context) (map[string]interface{}, error)
	GetServicesOffered(ctx context.Context, userID string) ([]models.Service, error)
	GetLocation(ctx context.Context, userID string) (models.Location, error)
	GetAvailability(ctx context.Context, userID string) (models.Availability, error)
	UpdateCreatorProfile(ctx context.Context, userID string, req models.CreateCreatorRequest) error
	UpdateUserProfile(ctx context.Context, userID string, req models.CreateUserRequest) error
}
