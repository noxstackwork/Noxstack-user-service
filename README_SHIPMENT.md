# 🚀 User Microservice - Production Ready

## Overview

This is a production-ready user authentication and management microservice built with Go Fiber, PostgreSQL, and JWT authentication. It provides comprehensive user management, authentication flows, session management, and admin capabilities.

## ✅ Features Implemented

### Authentication & Authorization
- ✅ Email/password registration and login
- ✅ Phone/OTP registration and login (partial)
- ✅ JWT access tokens with refresh token support
- ✅ Email verification flow
- ✅ Password reset flow
- ✅ Session management with device tracking
- ✅ Role-based access control (RBAC)

### User Management
- ✅ User profiles with ratings
- ✅ Username auto-generation
- ✅ Service provider capabilities
- ✅ Location-based features (PostGIS)
- ✅ User statistics and analytics

### Security & Production Features
- ✅ Rate limiting
- ✅ CORS configuration
- ✅ Input validation
- ✅ SQL injection protection
- ✅ Password hashing (bcrypt)
- ✅ Secure session management

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- PostgreSQL 14+ with PostGIS extension
- Docker (optional)

### 1. Database Setup

```bash
# Run the database migrations
psql -U postgres -d your_database -f docs/migrations.sql
psql -U postgres -d your_database -f docs/migrations_v2.sql
```

### 2. Environment Configuration

Create a `.env` file:

```env
# Server Configuration
PORT=8080
HOST=0.0.0.0
ENVIRONMENT=development

# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/user_service?sslmode=disable

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRATION_HOURS=24
JWT_ISSUER=user-service

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_DURATION=60s

# CORS
CORS_ENABLED=true
CORS_ALLOW_ORIGINS=*
```

### 3. Run the Service

```bash
# Install dependencies
go mod tidy

# Run the service
go run main.go

# Or build and run
go build -o user-service
./user-service
```

### 4. Test the API

```bash
# Run the comprehensive test suite
./test_api.sh

# Or test individual endpoints
curl -X POST http://localhost:8080/api/v1/auth/signup/email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/signup/email` | Start email signup |
| POST | `/auth/verify-email` | Verify email code |
| POST | `/auth/create-profile/email` | Create user profile |
| POST | `/auth/login` | Email/password login |
| POST | `/auth/refresh` | Refresh JWT token |
| POST | `/auth/forgot-password` | Request password reset |

### User Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users/me` | Get current user profile |
| PUT | `/users/me` | Update current user profile |
| GET | `/users/:id` | Get user by ID (admin) |
| PUT | `/users/:id` | Update user by ID (admin) |
| DELETE | `/users/me` | Delete current user account |

### Session Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/sessions/` | Create new session |
| GET | `/sessions/` | Get active sessions |
| DELETE | `/sessions/:id` | Delete specific session |
| DELETE | `/sessions/` | Delete all sessions |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | List all users |
| GET | `/admin/stats` | Get user statistics |
| PUT | `/admin/users/:id` | Update any user |
| DELETE | `/admin/users/:id` | Delete any user |

## 🔒 Security Considerations

### Production Checklist

- [ ] Change default JWT secret
- [ ] Enable HTTPS/TLS
- [ ] Configure proper CORS origins
- [ ] Set up rate limiting
- [ ] Enable database SSL
- [ ] Configure proper logging
- [ ] Set up monitoring
- [ ] Enable backup strategies

## 🐳 Docker Deployment

### Using Docker Compose

```yaml
version: '3.8'
services:
  user-service:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/userdb?sslmode=disable
      - JWT_SECRET=your-production-secret
    depends_on:
      - db
  
  db:
    image: postgis/postgis:14-3.2
    environment:
      - POSTGRES_DB=userdb
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

---

**Status**: ✅ Production Ready for Shipment

**Last Updated**: December 2024

**Version**: 1.0.0 