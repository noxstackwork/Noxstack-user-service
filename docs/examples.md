# API Examples

## Authentication Endpoints

### Register User

**Request:**
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "full_name": "John Doe",
  "role": "general",
  "willing_to_provide_services": true,
  "location": {
    "type": "Point",
    "coordinates": [-122.4194, 37.7749]
  }
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "general",
    "willing_to_provide_services": true,
    "level": 0,
    "services_offered": [],
    "location": {
      "type": "Point",
      "coordinates": [-122.4194, 37.7749]
    },
    "created_at": "2025-05-30T12:00:00Z",
    "updated_at": "2025-05-30T12:00:00Z"
  }
}
```

### Login

**Request:**
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "general",
    "willing_to_provide_services": true,
    "level": 0,
    "services_offered": [],
    "location": {
      "type": "Point",
      "coordinates": [-122.4194, 37.7749]
    },
    "created_at": "2025-05-30T12:00:00Z",
    "updated_at": "2025-05-30T12:00:00Z"
  }
}
```

## User Management Endpoints

### Get User Profile

**Request:**
```http
GET /api/v1/users/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "user@example.com",
  "full_name": "John Doe",
  "username": "johndoe",
  "role": "general",
  "willing_to_provide_services": true,
  "level": 0,
  "services_offered": [],
  "location": {
    "type": "Point",
    "coordinates": [-122.4194, 37.7749]
  },
  "created_at": "2025-05-30T12:00:00Z",
  "updated_at": "2025-05-30T12:00:00Z"
}
```

### Update User Profile

**Request:**
```http
PUT /api/v1/users/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "full_name": "John Smith",
  "username": "johnsmith",
  "willing_to_provide_services": false
}
```

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "email": "user@example.com",
  "full_name": "John Smith",
  "username": "johnsmith",
  "role": "general",
  "willing_to_provide_services": false,
  "level": 0,
  "services_offered": [],
  "location": {
    "type": "Point",
    "coordinates": [-122.4194, 37.7749]
  },
  "created_at": "2025-05-30T12:00:00Z",
  "updated_at": "2025-05-30T12:30:00Z"
}
```

### Update User Location

**Request:**
```http
PUT /api/v1/users/me/location
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "type": "Point",
  "coordinates": [-74.0060, 40.7128]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Location updated successfully"
}
```

## Error Responses

### Invalid Credentials

```json
{
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "details": {}
}
```

### Unauthorized Access

```json
{
  "code": "UNAUTHORIZED",
  "message": "Authentication required",
  "details": {}
}
```

### Resource Not Found

```json
{
  "code": "NOT_FOUND",
  "message": "User not found",
  "details": {}
}
```

### Validation Error

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Invalid input data",
  "details": {
    "email": "Invalid email format",
    "password": "Password must be at least 8 characters"
  }
}
```

