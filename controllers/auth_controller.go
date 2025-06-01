package controllers

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"consolidated-user-service/config"
	"consolidated-user-service/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthController handles all authentication-related operations
type AuthController struct {
	repo      UserRepository
	db        *sql.DB
	jwtSecret string
	cfg       *config.Config
}

// Request DTOs
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
	Email    string `json:"email" validate:"required,email"`
	FullName string `json:"full_name" validate:"required"`
	Role     string `json:"role" validate:"required,oneof=user creator"`
}

// JWT Claims structure
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Helper function to generate JWT token
func (ac *AuthController) generateTokens(user *models.User) (string, string, int64, error) {
	// Access token (short-lived)
	accessClaims := &JWTClaims{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ac.cfg.JWT.Issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(ac.cfg.JWT.ExpirationHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(ac.jwtSecret))
	if err != nil {
		return "", "", 0, err
	}

	// Refresh token (long-lived)
	refreshClaims := &JWTClaims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ac.cfg.JWT.Issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)), // 30 days
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(ac.jwtSecret))
	if err != nil {
		return "", "", 0, err
	}

	return accessTokenString, refreshTokenString, accessClaims.ExpiresAt.Unix(), nil
}

// Helper function to generate verification code
func (ac *AuthController) generateVerificationCode() string {
	bytes := make([]byte, 3)
	rand.Read(bytes)
	return fmt.Sprintf("%06d", int(bytes[0])<<16|int(bytes[1])<<8|int(bytes[2]))[:6]
}

// Signup handles user registration
func (ac *AuthController) Signup(c *fiber.Ctx) error {
	var req models.SignupRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	if len(hashedPassword) < 60 || hashedPassword[0] != '$' {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Password hash invalid", "details": string(hashedPassword)})
	}

	// Create user with unverified email
	user := models.User{
		Email:           req.Email,
		PasswordHash:    string(hashedPassword),
		FullName:        req.FullName,
		IsEmailVerified: false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	createdUser, err := ac.repo.CreateUser(c.Context(), user)
	if err != nil {
		if ac.cfg.Server.Environment == "development" {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create user",
		})
	}

	// Generate verification code
	code := ac.generateVerificationCode()
	_, err = ac.repo.CreateEmailVerification(c.Context(), req.Email, code)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create email verification",
		})
	}

	// TODO: Send verification email with code

	response := fiber.Map{
		"message": "User created successfully. Please verify your email.",
		"user":    createdUser,
	}
	if ac.cfg.Server.Environment == "development" {
		response["code"] = code
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

// VerifyEmail handles email verification
func (ac *AuthController) VerifyEmail(c *fiber.Ctx) error {
	var req models.VerifyEmailRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Get verification record
	verification, err := ac.repo.GetEmailVerification(c.Context(), req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get email verification",
		})
	}

	if verification == nil || verification.Code != req.Code {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	if verification.IsUsed {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Verification code already used",
		})
	}

	if time.Now().After(verification.ExpiresAt) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Verification code expired",
		})
	}

	// Get user
	user, err := ac.repo.GetUserByEmail(c.Context(), req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get user",
		})
	}

	// Mark email as verified
	err = ac.repo.MarkEmailVerified(c.Context(), user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to mark email as verified",
		})
	}

	// Mark verification code as used
	err = ac.repo.MarkEmailVerificationUsed(c.Context(), verification.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to mark verification code as used",
		})
	}

	// Generate token
	accessToken, refreshToken, expiresAt, err := ac.generateTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(models.AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *user,
		ExpiresAt:    expiresAt,
	})
}

// CreateProfile handles profile creation after email verification
func (ac *AuthController) CreateProfile(c *fiber.Ctx) error {
	var req models.CreateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body", "details": err.Error()})
	}

	var userID string
	if uid := c.Locals("user_id"); uid != nil {
		userID = uid.(string)
	} else if req.Email != "" {
		user, err := ac.repo.GetUserByEmail(c.Context(), req.Email)
		if err != nil || user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		userID = user.ID
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	profile := models.Profile{
		UserID:      userID,
		FullName:    req.FullName,
		Bio:         req.Bio,
		AvatarURL:   req.AvatarURL,
		PhoneNumber: req.PhoneNumber,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err := ac.repo.CreateProfile(c.Context(), profile)
	if err != nil {
		if ac.cfg.Server.Environment == "development" {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error", "details": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

	return c.Status(fiber.StatusCreated).JSON(profile)
}

// Phone sign up: /api/v1/auth/signup/phone
func (ac *AuthController) SignupPhone(c *fiber.Ctx) error {
	type reqBody struct {
		Phone string `json:"phone" validate:"required"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate phone number format
	if len(req.Phone) < 8 {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid phone number"})
	}

	// Generate OTP
	otp := ac.generateVerificationCode()

	// Store OTP in database - we need a user ID, so create a temporary record
	tempUserID := uuid.New().String()
	_, err := ac.repo.CreatePhoneOTP(c.Context(), tempUserID, req.Phone)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate OTP"})
	}

	// Send SMS (stub implementation)
	err = ac.sendSMS(req.Phone, fmt.Sprintf("Your verification code is: %s", otp))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to send OTP"})
	}

	response := fiber.Map{"message": "OTP sent to phone"}
	if ac.cfg.Server.Environment == "development" {
		response["otp"] = otp // Only in development
	}

	return c.Status(200).JSON(response)
}

// Send SMS stub
func (ac *AuthController) sendSMS(phone, message string) error {
	// TODO: Implement actual SMS sending with Twilio/AWS SNS
	fmt.Printf("[SMS] To: %s, Message: %s\n", phone, message)
	return nil
}

// Verify phone OTP: /api/v1/auth/verify-otp
func (ac *AuthController) VerifyPhoneOTP(c *fiber.Ctx) error {
	type reqBody struct {
		Phone string `json:"phone" validate:"required"`
		OTP   string `json:"otp" validate:"required"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if ac.cfg.Server.Environment == "development" && req.OTP == "123456" {
		// Upsert user with this phone and mark as verified
		user, err := ac.repo.GetUserByPhone(c.Context(), req.Phone)
		if user == nil || err != nil {
			// Create new user
			user = &models.User{
				ID:              uuid.New().String(),
				Phone:           req.Phone,
				IsPhoneVerified: true,
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}
			_, err = ac.repo.CreateUser(c.Context(), *user)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to create phone user", "details": err.Error()})
			}
		} else {
			user.IsPhoneVerified = true
			user.UpdatedAt = time.Now()
			_, err = ac.repo.UpdateUser(c.Context(), user.ID, *user)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update phone user", "details": err.Error()})
			}
		}
		return c.Status(200).JSON(fiber.Map{"message": "Phone verified successfully"})
	}

	return c.Status(400).JSON(fiber.Map{"error": "Invalid OTP"})
}

// Create profile after phone verification: /api/v1/auth/create-profile/phone
func (ac *AuthController) CreatePhoneProfile(c *fiber.Ctx) error {
	var req struct {
		Phone    string `json:"phone"`
		FullName string `json:"full_name"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body", "details": err.Error()})
	}

	// Validate Indian phone number (E.164: +91XXXXXXXXXX)
	matched, _ := regexp.MatchString(`^\+91[6-9][0-9]{9}$`, req.Phone)
	if !matched {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Indian phone number format"})
	}

	if len(req.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Password must be at least 8 characters"})
	}

	user, err := ac.repo.GetUserByPhone(c.Context(), req.Phone)
	if err != nil || user == nil || !user.IsPhoneVerified {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Phone not verified or user not found"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password", "details": err.Error()})
	}

	user.FullName = req.FullName
	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	_, err = ac.repo.UpdateUser(c.Context(), user.ID, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user", "details": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "Phone profile created successfully"})
}

// SigninEmail handles email-based sign in
func (ac *AuthController) SigninEmail(c *fiber.Ctx) error {
	var req models.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Get user
	user, err := ac.repo.GetUserByEmail(c.Context(), req.Email)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Generate token
	accessToken, refreshToken, expiresAt, err := ac.generateTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(models.AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *user,
		ExpiresAt:    expiresAt,
	})
}

// SigninPhone handles phone-based sign in
func (ac *AuthController) SigninPhone(c *fiber.Ctx) error {
	var req struct {
		Phone string `json:"phone" validate:"required"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Get user by phone
	user, err := ac.repo.GetUserByPhone(c.Context(), req.Phone)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Generate token
	accessToken, refreshToken, expiresAt, err := ac.generateTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(models.AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *user,
		ExpiresAt:    expiresAt,
	})
}

// Forgot password: /api/v1/auth/forgot-password
func (ac *AuthController) ForgotPassword(c *fiber.Ctx) error {
	type reqBody struct {
		Email string `json:"email" validate:"required,email"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Check if user exists
	user, err := ac.repo.GetUserByEmail(c.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists or not
		return c.Status(200).JSON(fiber.Map{"message": "If the email exists, a reset code has been sent"})
	}

	// Create password reset code
	_, err = ac.repo.CreatePasswordReset(c.Context(), user.ID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create reset code"})
	}

	// TODO: Send email with reset code
	return c.Status(200).JSON(fiber.Map{"message": "If the email exists, a reset code has been sent"})
}

// Verify reset code: /api/v1/auth/verify-reset-code
func (ac *AuthController) VerifyResetCode(c *fiber.Ctx) error {
	type reqBody struct {
		Email string `json:"email" validate:"required,email"`
		Code  string `json:"code" validate:"required"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// TODO: Implement reset code verification
	return c.Status(200).JSON(fiber.Map{"message": "Reset code verified (not implemented)"})
}

// Reset password: /api/v1/auth/reset-password
func (ac *AuthController) ResetPassword(c *fiber.Ctx) error {
	type reqBody struct {
		Email       string `json:"email" validate:"required,email"`
		Code        string `json:"code" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=8"`
	}
	var req reqBody
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// TODO: Implement password reset
	return c.Status(200).JSON(fiber.Map{"message": "Password reset (not implemented)"})
}

// Google OAuth2 sign-in: /api/v1/auth/google
func (ac *AuthController) GoogleAuth(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth2
	return c.Status(501).JSON(fiber.Map{"error": "Google OAuth2 not implemented yet"})
}

// Google OAuth2 callback: /api/v1/auth/callback
func (ac *AuthController) GoogleCallback(c *fiber.Ctx) error {
	// TODO: Implement Google OAuth2 callback
	return c.Status(501).JSON(fiber.Map{"error": "Google OAuth2 callback not implemented yet"})
}

// RefreshToken handles token refresh
func (ac *AuthController) RefreshToken(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(req.RefreshToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(ac.jwtSecret), nil
	})
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	// Get user
	user, err := ac.repo.GetUser(c.Context(), claims.UserID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Generate new tokens
	accessToken, refreshToken, expiresAt, err := ac.generateTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(models.AuthResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         *user,
		ExpiresAt:    expiresAt,
	})
}

// PhoneSignin handles phone-based sign in
func (ac *AuthController) PhoneSignin(c *fiber.Ctx) error {
	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body", "details": err.Error()})
	}

	matched, _ := regexp.MatchString(`^\+91[6-9][0-9]{9}$`, req.Phone)
	if !matched {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid Indian phone number format"})
	}

	user, err := ac.repo.GetUserByPhone(c.Context(), req.Phone)
	if err != nil || user == nil || !user.IsPhoneVerified {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Generate JWT token (reuse existing logic)
	token, refreshToken, _, _ := ac.generateTokens(user)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"token":         token,
		"refresh_token": refreshToken,
		"user":          user,
	})
}

// NewAuthController creates a new AuthController instance
func NewAuthController(repo UserRepository, cfg *config.Config) *AuthController {
	return &AuthController{
		repo:      repo,
		jwtSecret: cfg.JWT.Secret,
		cfg:       cfg,
	}
}
