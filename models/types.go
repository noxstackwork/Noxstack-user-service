package models

import (
	"time"

	"github.com/lib/pq"
)

// User represents a user in the system
type User struct {
	ID                       string         `json:"id"`
	Email                    string         `json:"email" validate:"required,email"`
	Phone                    string         `json:"phone,omitempty"`
	Username                 string         `json:"username,omitempty" validate:"omitempty,min=3,max=64"`
	FullName                 string         `json:"full_name,omitempty"`
	PasswordHash             string         `json:"-"`
	Role                     string         `json:"role,omitempty"`
	IsEmailVerified          bool           `json:"is_email_verified"`
	IsPhoneVerified          bool           `json:"is_phone_verified"`
	WillingToProvideServices bool           `json:"willing_to_provide_services"`
	Level                    int            `json:"level"`
	ServicesOffered          pq.StringArray `json:"services_offered,omitempty"`
	Location                 string         `json:"location,omitempty"`
	Rating                   *float64       `json:"rating,omitempty"`
	GoogleID                 string         `json:"google_id,omitempty"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

// Profile represents a user's profile
type Profile struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	FullName    string    `json:"full_name,omitempty"`
	Bio         string    `json:"bio,omitempty"`
	AvatarURL   string    `json:"avatar_url,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Session represents a user's session
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

// AuthResponse represents the response for authentication endpoints
type AuthResponse struct {
	Token        string      `json:"token"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	User         interface{} `json:"user"`
	ExpiresAt    int64       `json:"expires_at"`
}

// Request DTOs
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

type SignupRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	FullName string `json:"full_name" validate:"required"`
	Role     string `json:"role" validate:"required,oneof=user creator"`
}

type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

type CreateProfileRequest struct {
	Email       string `json:"email"`
	FullName    string `json:"full_name,omitempty"`
	Bio         string `json:"bio,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type CreateUserRequest struct {
	Email                    string         `json:"email" validate:"required,email"`
	Password                 string         `json:"password" validate:"required,min=8"`
	FullName                 string         `json:"full_name" validate:"required"`
	Role                     string         `json:"role,omitempty"`
	WillingToProvideServices bool           `json:"willing_to_provide_services,omitempty"`
	ServicesOffered          pq.StringArray `json:"services_offered,omitempty"`
	Location                 string         `json:"location,omitempty"`
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

// Additional types for verification and OAuth
type EmailVerification struct {
	ID        string    `json:"id"`
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
