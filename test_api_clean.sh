#!/bin/bash

# Test script for User Service API endpoints
# This script tests all major authentication and user management flows

BASE_URL="http://localhost:8080/api/v1"
# Generate unique email for each test run
EMAIL="test$(date +%s)@example.com"
PASSWORD="testpassword123"
FULL_NAME="Test User"

echo "🚀 Starting User Service API Tests"
echo "=================================="
echo "Testing with email: $EMAIL"
echo ""

# Function to extract JSON value
extract_json() {
  echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | cut -d'"' -f4
}

# Test 1: Email Signup
echo "📧 Testing email signup..."
SIGNUP_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/signup/email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}")

echo "Signup Response: $SIGNUP_RESPONSE"

# Extract verification code (in development mode)
VERIFICATION_CODE=$(extract_json "$SIGNUP_RESPONSE" "code")
echo "Verification Code: $VERIFICATION_CODE"

# Test 2: Email Verification
echo ""
echo "✅ Testing email verification..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/verify-email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"code\":\"$VERIFICATION_CODE\"}")

echo "Verify Response: $VERIFY_RESPONSE"

# Test 3: Create Profile
echo ""
echo "👤 Testing profile creation..."
PROFILE_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/create-profile/email" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"full_name\":\"$FULL_NAME\"}")

echo "Profile Response: $PROFILE_RESPONSE"

# Test 4: Login
echo ""
echo "🔐 Testing login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

echo "Login Response: $LOGIN_RESPONSE"

# Extract JWT token
JWT_TOKEN=$(extract_json "$LOGIN_RESPONSE" "token")
echo "JWT Token (first 50 chars): ${JWT_TOKEN:0:50}..."

if [ -z "$JWT_TOKEN" ]; then
  echo "❌ Failed to get JWT token, skipping protected endpoint tests"
  exit 1
fi

# Test 5: Get User Profile
echo ""
echo "📋 Testing get user profile..."
PROFILE_GET_RESPONSE=$(curl -s -X GET "$BASE_URL/users/me" \
  -H "Authorization: Bearer $JWT_TOKEN")

echo "Profile Get Response: $PROFILE_GET_RESPONSE"

# Test 6: Update Profile
echo ""
echo "✏️ Testing update profile..."
UPDATE_PROFILE_RESPONSE=$(curl -s -X PUT "$BASE_URL/users/me" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"bio\":\"Updated bio\",\"phone_number\":\"+1234567890\"}")

echo "Update Profile Response: $UPDATE_PROFILE_RESPONSE"

# Test 7: Create Session
echo ""
echo "🔗 Testing session creation..."
SESSION_RESPONSE=$(curl -s -X POST "$BASE_URL/sessions/" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"device_info\":\"Test Device\"}")

echo "Session Response: $SESSION_RESPONSE"

# Test 8: Get Active Sessions
echo ""
echo "📱 Testing get active sessions..."
SESSIONS_GET_RESPONSE=$(curl -s -X GET "$BASE_URL/sessions/" \
  -H "Authorization: Bearer $JWT_TOKEN")

echo "Sessions Get Response: $SESSIONS_GET_RESPONSE"

# Test 9: Update Services
echo ""
echo "🛠️ Testing update services offered..."
SERVICES_RESPONSE=$(curl -s -X PUT "$BASE_URL/users/me/services" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"services\":[\"plumbing\",\"electrical\"]}")

echo "Services Response: $SERVICES_RESPONSE"

# Test 10: Update Location
echo ""
echo "📍 Testing update location..."
LOCATION_RESPONSE=$(curl -s -X PUT "$BASE_URL/users/me/location" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"latitude\":37.7749,\"longitude\":-122.4194}")

echo "Location Response: $LOCATION_RESPONSE"

# Test 11: Change Password
echo ""
echo "🔑 Testing change password..."
CHANGE_PWD_RESPONSE=$(curl -s -X PUT "$BASE_URL/users/me/password" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"current_password\":\"$PASSWORD\",\"new_password\":\"newpassword123\"}")

echo "Change Password Response: $CHANGE_PWD_RESPONSE"

# Test 12: Token Refresh
echo ""
echo "🔄 Testing token refresh..."
REFRESH_TOKEN=$(extract_json "$LOGIN_RESPONSE" "refresh_token")
if [ ! -z "$REFRESH_TOKEN" ]; then
  REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}")
  echo "Refresh Response: $REFRESH_RESPONSE"
else
  echo "No refresh token found in login response"
fi

# Test 13: Admin Stats (if implemented)
echo ""
echo "📊 Testing admin stats..."
STATS_RESPONSE=$(curl -s -X GET "$BASE_URL/admin/stats" \
  -H "Authorization: Bearer $JWT_TOKEN")

echo "Stats Response: $STATS_RESPONSE"

# Test 14: Health Check
echo ""
echo "❤️ Testing health check..."
HEALTH_RESPONSE=$(curl -s -X GET "$BASE_URL/health")

echo "Health Response: $HEALTH_RESPONSE"

# Test 15: Delete Session
echo ""
echo "🗑️ Testing delete all sessions..."
DELETE_SESSIONS_RESPONSE=$(curl -s -X DELETE "$BASE_URL/sessions/" \
  -H "Authorization: Bearer $JWT_TOKEN")

echo "Delete Sessions Response: $DELETE_SESSIONS_RESPONSE"

echo ""
echo "✅ API Tests Completed!"
echo "======================="
echo "Summary:"
echo "- Tested with email: $EMAIL"
echo "- Review the responses above to verify functionality"
echo "- Expected successful responses should have 200/201 status codes" 