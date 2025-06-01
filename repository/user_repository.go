package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"consolidated-user-service/models"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrDuplicateEmail     = errors.New("email already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// PostgresUserRepository implements the UserRepository interface for PostgreSQL
type PostgresUserRepository struct {
	db *sql.DB
}

// NewPostgresUserRepository creates a new PostgreSQL repository instance
func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{
		db: db,
	}
}

// Authentication methods

// Register creates a new user account
func (r *PostgresUserRepository) Register(ctx context.Context, req models.RegisterRequest) (*models.User, string, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	// Start transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	// Check for existing user
	var count int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", req.Email).Scan(&count)
	if err != nil {
		return nil, "", err
	}
	if count > 0 {
		return nil, "", ErrDuplicateEmail
	}

	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)",
		user.ID, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return nil, "", err
	}

	if err := tx.Commit(); err != nil {
		return nil, "", err
	}

	// Return user and empty token (token generation handled elsewhere)
	return user, "", nil
}

// Login authenticates a user
func (r *PostgresUserRepository) Login(ctx context.Context, req models.LoginRequest) (*models.AuthResponse, error) {
	var user models.User
	var passwordHash string

	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE email = $1",
		req.Email,
	).Scan(&user.ID, &user.Email, &passwordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &models.AuthResponse{
		User: user,
	}, nil
}

// User management methods

// CreateUser creates a new user
func (r *PostgresUserRepository) CreateUser(ctx context.Context, user models.User) (*models.User, error) {
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		"INSERT INTO users (id, email, password_hash, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
		user.ID, user.Email, user.PasswordHash, user.Role, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUser retrieves a user by ID
func (r *PostgresUserRepository) GetUser(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE id = $1",
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates user information
func (r *PostgresUserRepository) UpdateUser(ctx context.Context, id string, user models.User) (*models.User, error) {
	// Update fields
	updateTime := time.Now()
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET email = $1, role = $2, updated_at = $3 WHERE id = $4",
		user.Email, user.Role, updateTime, id,
	)
	if err != nil {
		return nil, err
	}

	// Get updated user
	return r.GetUser(ctx, id)
}

// DeleteUser removes a user by ID
func (r *PostgresUserRepository) DeleteUser(ctx context.Context, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete associated profile
	_, err = tx.ExecContext(ctx, "DELETE FROM profiles WHERE user_id = $1", id)
	if err != nil {
		return err
	}

	// Delete associated sessions
	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = $1", id)
	if err != nil {
		return err
	}

	// Delete user
	result, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = $1", id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return tx.Commit()
}

// ListCreators retrieves all users marked as creators
func (r *PostgresUserRepository) ListCreators(ctx context.Context) ([]models.User, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, email, role, created_at, updated_at FROM users WHERE role = 'creator'",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creators []models.User
	for rows.Next() {
		var creator models.User
		err := rows.Scan(&creator.ID, &creator.Email, &creator.Role, &creator.CreatedAt, &creator.UpdatedAt)
		if err != nil {
			return nil, err
		}
		creators = append(creators, creator)
	}

	return creators, nil
}

// Profile management methods

// CreateProfile creates a profile for a user
func (r *PostgresUserRepository) CreateProfile(ctx context.Context, profile models.Profile) (*models.Profile, error) {
	profile.ID = uuid.New().String()
	profile.CreatedAt = time.Now()
	profile.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		"INSERT INTO profiles (id, user_id, full_name, bio, avatar_url, phone_number, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		profile.ID, profile.UserID, profile.FullName, profile.Bio, profile.AvatarURL, profile.PhoneNumber, profile.CreatedAt, profile.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetProfile retrieves a user's profile
func (r *PostgresUserRepository) GetProfile(ctx context.Context, userID string) (*models.Profile, error) {
	var profile models.Profile
	err := r.db.QueryRowContext(ctx,
		"SELECT id, user_id, full_name, bio, avatar_url, phone_number, created_at, updated_at FROM profiles WHERE user_id = $1",
		userID,
	).Scan(&profile.ID, &profile.UserID, &profile.FullName, &profile.Bio, &profile.AvatarURL, &profile.PhoneNumber, &profile.CreatedAt, &profile.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("profile not found")
		}
		return nil, err
	}

	return &profile, nil
}

// UpdateProfile updates a user's profile
func (r *PostgresUserRepository) UpdateProfile(ctx context.Context, userID string, profile models.Profile) (*models.Profile, error) {
	profile.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		"UPDATE profiles SET full_name = $1, bio = $2, avatar_url = $3, phone_number = $4, updated_at = $5 WHERE user_id = $6",
		profile.FullName, profile.Bio, profile.AvatarURL, profile.PhoneNumber, profile.UpdatedAt, userID,
	)
	if err != nil {
		return nil, err
	}

	return r.GetProfile(ctx, userID)
}

// DeleteProfile removes a user's profile
func (r *PostgresUserRepository) DeleteProfile(ctx context.Context, userID string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM profiles WHERE user_id = $1", userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("profile not found")
	}

	return nil
}

// Session management methods

// CreateSession creates a new user session with refresh token support
func (r *PostgresUserRepository) CreateSession(ctx context.Context, userID string, deviceInfo string) (*models.Session, error) {
	session := &models.Session{
		ID:         uuid.New().String(),
		UserID:     userID,
		DeviceInfo: deviceInfo,
		IsActive:   true,
		ExpiresAt:  time.Now().Add(24 * time.Hour), // 24 hours
		CreatedAt:  time.Now(),
	}

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, device_info, is_active, expires_at, created_at) 
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		session.ID, session.UserID, session.DeviceInfo, session.IsActive, session.ExpiresAt, session.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession retrieves a session by ID
func (r *PostgresUserRepository) GetSession(ctx context.Context, sessionID string) (*models.Session, error) {
	var session models.Session
	err := r.db.QueryRowContext(ctx,
		"SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = $1",
		sessionID,
	).Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		_, _ = r.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)
		return nil, errors.New("session expired")
	}

	return &session, nil
}

// DeleteSession removes a session
func (r *PostgresUserRepository) DeleteSession(ctx context.Context, sessionID string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = $1", sessionID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("session not found")
	}

	return nil
}

// PhoneOTPRepository defines methods for phone OTP
func (r *PostgresUserRepository) CreatePhoneOTP(ctx context.Context, userID, phone string) (*models.PhoneOTP, error) {
	id := uuid.New().String()
	otp := uuid.New().String()[:6]
	expiresAt := time.Now().Add(10 * time.Minute)
	createdAt := time.Now()
	_, err := r.db.ExecContext(ctx, `INSERT INTO phone_otps (id, user_id, phone, otp, expires_at, is_used, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, userID, phone, otp, expiresAt, false, createdAt)
	if err != nil {
		return nil, err
	}
	return &models.PhoneOTP{
		ID:        id,
		UserID:    userID,
		Phone:     phone,
		OTP:       otp,
		ExpiresAt: expiresAt,
		IsUsed:    false,
		CreatedAt: createdAt,
	}, nil
}

func (r *PostgresUserRepository) GetPhoneOTP(ctx context.Context, userID string) (*models.PhoneOTP, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, phone, otp, expires_at, is_used, created_at FROM phone_otps WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, userID)
	var po models.PhoneOTP
	err := row.Scan(&po.ID, &po.UserID, &po.Phone, &po.OTP, &po.ExpiresAt, &po.IsUsed, &po.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &po, nil
}

// PasswordResetRepository defines methods for password reset
func (r *PostgresUserRepository) CreatePasswordReset(ctx context.Context, userID string) (*models.PasswordReset, error) {
	id := uuid.New().String()
	code := uuid.New().String()[:6]
	expiresAt := time.Now().Add(10 * time.Minute)
	createdAt := time.Now()
	_, err := r.db.ExecContext(ctx, `INSERT INTO password_resets (id, user_id, code, expires_at, is_used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		id, userID, code, expiresAt, false, createdAt)
	if err != nil {
		return nil, err
	}
	return &models.PasswordReset{
		ID:        id,
		UserID:    userID,
		Code:      code,
		ExpiresAt: expiresAt,
		IsUsed:    false,
		CreatedAt: createdAt,
	}, nil
}

func (r *PostgresUserRepository) GetPasswordReset(ctx context.Context, userID string) (*models.PasswordReset, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, code, expires_at, is_used, created_at FROM password_resets WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, userID)
	var pr models.PasswordReset
	err := row.Scan(&pr.ID, &pr.UserID, &pr.Code, &pr.ExpiresAt, &pr.IsUsed, &pr.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &pr, nil
}

// OAuthIdentityRepository defines methods for OAuth identities
func (r *PostgresUserRepository) CreateOAuthIdentity(ctx context.Context, userID, provider, providerID, email string) (*models.OAuthIdentity, error) {
	id := uuid.New().String()
	createdAt := time.Now()
	_, err := r.db.ExecContext(ctx, `INSERT INTO oauth_identities (id, user_id, provider, provider_id, email, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		id, userID, provider, providerID, email, createdAt)
	if err != nil {
		return nil, err
	}
	return &models.OAuthIdentity{
		ID:         id,
		UserID:     userID,
		Provider:   provider,
		ProviderID: providerID,
		Email:      email,
		CreatedAt:  createdAt,
	}, nil
}

func (r *PostgresUserRepository) GetOAuthIdentity(ctx context.Context, userID string) (*models.OAuthIdentity, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, user_id, provider, provider_id, email, created_at FROM oauth_identities WHERE user_id = $1 LIMIT 1`, userID)
	var oi models.OAuthIdentity
	err := row.Scan(&oi.ID, &oi.UserID, &oi.Provider, &oi.ProviderID, &oi.Email, &oi.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &oi, nil
}

// DeleteEmailVerification removes an email verification record
func (r *PostgresUserRepository) DeleteEmailVerification(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, userID)
	return err
}

func (r *PostgresUserRepository) DeleteOAuthIdentity(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM oauth_identities WHERE user_id = $1`, userID)
	return err
}

func (r *PostgresUserRepository) DeletePasswordReset(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID)
	return err
}

func (r *PostgresUserRepository) DeletePhoneOTP(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM phone_otps WHERE user_id = $1`, userID)
	return err
}

// Additional methods for production use

// MarkPhoneVerified marks a user's phone as verified
func (r *PostgresUserRepository) MarkPhoneVerified(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET is_phone_verified = true, updated_at = $1 WHERE id = $2",
		time.Now(), userID)
	return err
}

// UpdatePassword updates a user's password
func (r *PostgresUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	if len(passwordHash) < 60 || passwordHash[0] != '$' {
		return errors.New("Password hash invalid: " + passwordHash)
	}
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3",
		passwordHash, time.Now(), userID)
	return err
}

// GetUserStats returns user statistics for analytics
func (r *PostgresUserRepository) GetUserStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total users
	var totalUsers int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	if err != nil {
		return nil, err
	}
	stats["total_users"] = totalUsers

	// Verified emails
	var verifiedEmails int
	err = r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE is_email_verified = true").Scan(&verifiedEmails)
	if err != nil {
		return nil, err
	}
	stats["verified_emails"] = verifiedEmails

	// Creators
	var creators int
	err = r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM users WHERE role = 'creator' OR willing_to_provide_services = true").Scan(&creators)
	if err != nil {
		return nil, err
	}
	stats["creators"] = creators

	// Users registered today
	var todayUsers int
	err = r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE").Scan(&todayUsers)
	if err != nil {
		return nil, err
	}
	stats["today_registrations"] = todayUsers

	return stats, nil
}

// DeleteAllUserSessions deletes all sessions for a user
func (r *PostgresUserRepository) DeleteAllUserSessions(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE sessions SET is_active = false WHERE user_id = $1", userID)
	return err
}

// GetUserByEmail retrieves a user by email address
func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	var passwordHash sql.NullString
	var phone sql.NullString
	var username sql.NullString
	var fullName sql.NullString
	var googleID sql.NullString
	var role sql.NullString
	var location sql.NullString
	var rating sql.NullFloat64
	var level sql.NullInt64
	var servicesOffered pq.StringArray

	err := r.db.QueryRowContext(ctx, `
		SELECT id, email, phone, username, full_name, password_hash, google_id, 
		       is_email_verified, is_phone_verified, role, willing_to_provide_services, 
		       level, services_offered, location, rating, created_at, updated_at 
		FROM users WHERE email = $1`, email).Scan(
		&user.ID, &user.Email, &phone, &username, &fullName, &passwordHash, &googleID,
		&user.IsEmailVerified, &user.IsPhoneVerified, &role, &user.WillingToProvideServices,
		&level, &servicesOffered, &location, &rating, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Handle nullable fields
	if phone.Valid {
		user.Phone = phone.String
	}
	if username.Valid {
		user.Username = username.String
	}
	if fullName.Valid {
		user.FullName = fullName.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if googleID.Valid {
		user.GoogleID = googleID.String
	}
	if role.Valid {
		user.Role = role.String
	}
	if location.Valid {
		user.Location = location.String
	}
	if rating.Valid {
		user.Rating = &rating.Float64
	}
	if level.Valid {
		user.Level = int(level.Int64)
	}
	user.ServicesOffered = servicesOffered

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	var passwordHash sql.NullString
	var phone sql.NullString
	var fullName sql.NullString
	var googleID sql.NullString
	var role sql.NullString
	var location sql.NullString
	var rating sql.NullFloat64
	var level sql.NullInt64
	var servicesOffered pq.StringArray

	err := r.db.QueryRowContext(ctx, `
		SELECT id, email, phone, username, full_name, password_hash, google_id, 
		       is_email_verified, is_phone_verified, role, willing_to_provide_services, 
		       level, services_offered, location, rating, created_at, updated_at 
		FROM users WHERE username = $1`, username).Scan(
		&user.ID, &user.Email, &phone, &user.Username, &fullName, &passwordHash, &googleID,
		&user.IsEmailVerified, &user.IsPhoneVerified, &role, &user.WillingToProvideServices,
		&level, &servicesOffered, &location, &rating, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Handle nullable fields
	if phone.Valid {
		user.Phone = phone.String
	}
	if fullName.Valid {
		user.FullName = fullName.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if googleID.Valid {
		user.GoogleID = googleID.String
	}
	if role.Valid {
		user.Role = role.String
	}
	if location.Valid {
		user.Location = location.String
	}
	if rating.Valid {
		user.Rating = &rating.Float64
	}
	if level.Valid {
		user.Level = int(level.Int64)
	}
	user.ServicesOffered = servicesOffered

	return &user, nil
}

// GetActiveSessionsByUser retrieves all active sessions for a user
func (r *PostgresUserRepository) GetActiveSessionsByUser(ctx context.Context, userID string) ([]models.Session, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, refresh_token, device_info, is_active, expires_at, created_at 
		FROM sessions 
		WHERE user_id = $1 AND is_active = true AND expires_at > NOW()
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		var session models.Session
		var refreshToken sql.NullString
		var deviceInfo sql.NullString

		err := rows.Scan(&session.ID, &session.UserID, &refreshToken, &deviceInfo,
			&session.IsActive, &session.ExpiresAt, &session.CreatedAt)
		if err != nil {
			return nil, err
		}

		if refreshToken.Valid {
			session.RefreshToken = refreshToken.String
		}
		if deviceInfo.Valid {
			session.DeviceInfo = deviceInfo.String
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

// RefreshSession handles refresh token validation and new session creation
func (r *PostgresUserRepository) RefreshSession(ctx context.Context, refreshToken string) (*models.Session, error) {
	// For now, just create a new session - in production you'd validate the refresh token
	// and extract user ID from it, then create a new session
	// This is a simplified implementation
	return nil, errors.New("refresh session not fully implemented")
}

// ListUsers lists users with pagination
func (r *PostgresUserRepository) ListUsers(ctx context.Context, offset, limit int) ([]models.User, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, email, phone, username, full_name, role, is_email_verified, 
		       is_phone_verified, willing_to_provide_services, level, rating, created_at 
		FROM users 
		ORDER BY created_at DESC 
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		var phone sql.NullString
		var username sql.NullString
		var fullName sql.NullString
		var role sql.NullString
		var rating sql.NullFloat64
		var level sql.NullInt64

		err := rows.Scan(&user.ID, &user.Email, &phone, &username, &fullName, &role,
			&user.IsEmailVerified, &user.IsPhoneVerified, &user.WillingToProvideServices,
			&level, &rating, &user.CreatedAt)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if phone.Valid {
			user.Phone = phone.String
		}
		if username.Valid {
			user.Username = username.String
		}
		if fullName.Valid {
			user.FullName = fullName.String
		}
		if role.Valid {
			user.Role = role.String
		}
		if rating.Valid {
			user.Rating = &rating.Float64
		}
		if level.Valid {
			user.Level = int(level.Int64)
		}

		users = append(users, user)
	}

	return users, nil
}

// CreateEmailVerification creates a new email verification record
func (r *PostgresUserRepository) CreateEmailVerification(ctx context.Context, email, code string) (*models.EmailVerification, error) {
	id := uuid.New().String()
	expiresAt := time.Now().Add(10 * time.Minute)
	createdAt := time.Now()
	_, err := r.db.ExecContext(ctx, `INSERT INTO email_verifications (id, email, code, expires_at, is_used, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		id, email, code, expiresAt, false, createdAt)
	if err != nil {
		return nil, err
	}
	return &models.EmailVerification{
		ID:        id,
		Email:     email,
		Code:      code,
		ExpiresAt: expiresAt,
		IsUsed:    false,
		CreatedAt: createdAt,
	}, nil
}

// CreateUserWithEmail creates a new user with email
func (r *PostgresUserRepository) CreateUserWithEmail(ctx context.Context, email, passwordHash, fullName string) (string, error) {
	userID := uuid.New().String()
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO users (id, email, password_hash, full_name, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
		userID, email, passwordHash, fullName, time.Now(), time.Now())
	if err != nil {
		return "", err
	}
	return userID, nil
}

// GetAvailability retrieves a user's availability
func (r *PostgresUserRepository) GetAvailability(ctx context.Context, userID string) (models.Availability, error) {
	var schedule []models.ScheduleSlot
	err := r.db.QueryRowContext(ctx,
		"SELECT schedule FROM availabilities WHERE user_id = $1",
		userID,
	).Scan(&schedule)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return default availability if none exists
			return models.Availability{
				Schedule: []models.ScheduleSlot{},
			}, nil
		}
		return models.Availability{}, err
	}

	return models.Availability{
		Schedule: schedule,
	}, nil
}

// GetEmailVerification retrieves an email verification record
func (r *PostgresUserRepository) GetEmailVerification(ctx context.Context, email string) (*models.EmailVerification, error) {
	var verification models.EmailVerification
	err := r.db.QueryRowContext(ctx,
		"SELECT id, email, code, expires_at, is_used, created_at FROM email_verifications WHERE email = $1 ORDER BY created_at DESC LIMIT 1",
		email,
	).Scan(&verification.ID, &verification.Email, &verification.Code, &verification.ExpiresAt, &verification.IsUsed, &verification.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &verification, nil
}

// MarkEmailVerificationUsed marks an email verification as used
func (r *PostgresUserRepository) MarkEmailVerificationUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE email_verifications SET is_used = true WHERE id = $1",
		id)
	return err
}

// MarkEmailVerified marks a user's email as verified
func (r *PostgresUserRepository) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET is_email_verified = true, updated_at = $1 WHERE id = $2",
		time.Now(), userID)
	return err
}

// GetServicesOffered retrieves services offered by a user
func (r *PostgresUserRepository) GetServicesOffered(ctx context.Context, userID string) ([]models.Service, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT name, description, price, duration, category FROM services WHERE user_id = $1",
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []models.Service
	for rows.Next() {
		var service models.Service
		err := rows.Scan(&service.Name, &service.Description, &service.Price, &service.Duration, &service.Category)
		if err != nil {
			return nil, err
		}
		services = append(services, service)
	}

	return services, nil
}

// GetLocation retrieves a user's location
func (r *PostgresUserRepository) GetLocation(ctx context.Context, userID string) (models.Location, error) {
	var location models.Location
	err := r.db.QueryRowContext(ctx,
		"SELECT address, city, state, country, latitude, longitude FROM locations WHERE user_id = $1",
		userID,
	).Scan(&location.Address, &location.City, &location.State, &location.Country, &location.Latitude, &location.Longitude)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return empty location if none exists
			return models.Location{}, nil
		}
		return models.Location{}, err
	}

	return location, nil
}

// UpdateCreatorProfile updates a creator's profile
func (r *PostgresUserRepository) UpdateCreatorProfile(ctx context.Context, userID string, req models.CreateCreatorRequest) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update user basic info
	_, err = tx.ExecContext(ctx,
		"UPDATE users SET email = $1, full_name = $2, willing_to_provide_services = $3, updated_at = $4 WHERE id = $5",
		req.Email, req.FullName, req.WillingToProvideServices, time.Now(), userID)
	if err != nil {
		return err
	}

	// Additional logic for services, location, availability would go here
	return tx.Commit()
}

// UpdateUserProfile updates a user's profile
func (r *PostgresUserRepository) UpdateUserProfile(ctx context.Context, userID string, req models.CreateUserRequest) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET email = $1, full_name = $2, role = $3, willing_to_provide_services = $4, location = $5, updated_at = $6 WHERE id = $7",
		req.Email, req.FullName, req.Role, req.WillingToProvideServices, req.Location, time.Now(), userID)
	return err
}

// GetUserByPhone retrieves a user by phone number
func (r *PostgresUserRepository) GetUserByPhone(ctx context.Context, phone string) (*models.User, error) {
	var user models.User
	var passwordHash sql.NullString
	var username sql.NullString
	var fullName sql.NullString
	var googleID sql.NullString
	var role sql.NullString
	var location sql.NullString
	var rating sql.NullFloat64
	var level sql.NullInt64
	var servicesOffered pq.StringArray

	err := r.db.QueryRowContext(ctx, `
		SELECT id, email, phone, username, full_name, password_hash, google_id, 
		       is_email_verified, is_phone_verified, role, willing_to_provide_services, 
		       level, services_offered, location, rating, created_at, updated_at 
		FROM users WHERE phone = $1`, phone).Scan(
		&user.ID, &user.Email, &user.Phone, &username, &fullName, &passwordHash, &googleID,
		&user.IsEmailVerified, &user.IsPhoneVerified, &role, &user.WillingToProvideServices,
		&level, &servicesOffered, &location, &rating, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Handle nullable fields
	if username.Valid {
		user.Username = username.String
	}
	if fullName.Valid {
		user.FullName = fullName.String
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	if googleID.Valid {
		user.GoogleID = googleID.String
	}
	if role.Valid {
		user.Role = role.String
	}
	if location.Valid {
		user.Location = location.String
	}
	if rating.Valid {
		user.Rating = &rating.Float64
	}
	if level.Valid {
		user.Level = int(level.Int64)
	}
	user.ServicesOffered = servicesOffered

	return &user, nil
}
