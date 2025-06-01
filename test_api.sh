#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:8080/api/v1"

# Test counter
PASSED=0
FAILED=0

# Generate unique test data
TEST_EMAIL="test_$(date +%s)@example.com"
TEST_PHONE="+919876543210"

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
        ((PASSED++))
    else
        echo -e "${RED}✗ $2${NC}"
        ((FAILED++))
    fi
}

# Function to make API calls and check response
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=$4
    local description=$5
    local store_token=$6

    echo -e "\n${YELLOW}Testing: $description${NC}"
    echo "Endpoint: $method $endpoint"
    if [ ! -z "$data" ]; then
        echo "Data: $data"
    fi

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$BASE_URL$endpoint" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN")
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "$data")
    elif [ "$method" = "PUT" ]; then
        response=$(curl -s -w "\n%{http_code}" -X PUT "$BASE_URL$endpoint" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d "$data")
    elif [ "$method" = "DELETE" ]; then
        response=$(curl -s -w "\n%{http_code}" -X DELETE "$BASE_URL$endpoint" -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN")
    fi

    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    echo "Response Status: $status_code"
    echo "Response Body: $body"

    if [ "$status_code" -eq "$expected_status" ]; then
        print_result 0 "$description"
        if [ "$store_token" = "true" ]; then
            TOKEN=$(echo "$body" | jq -r '.token')
            REFRESH_TOKEN=$(echo "$body" | jq -r '.refresh_token')
            echo "Stored access token: $TOKEN"
            echo "Stored refresh token: $REFRESH_TOKEN"
        fi
    else
        print_result 1 "$description"
    fi
}

echo "Starting API Tests..."
echo "Using test email: $TEST_EMAIL"
echo "Using test phone: $TEST_PHONE"

# Test 1: Email Signup
signup_response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/auth/signup/email" -H "Content-Type: application/json" -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"password123\",\"full_name\":\"Test User\",\"role\":\"user\"}")
signup_status=$(echo "$signup_response" | tail -n1)
signup_body=$(echo "$signup_response" | sed '$d')
echo -e "\n${YELLOW}Testing: Email Signup${NC}"
echo "Endpoint: POST /auth/signup/email"
echo "Data: {\"email\":\"$TEST_EMAIL\",\"password\":\"password123\",\"full_name\":\"Test User\",\"role\":\"user\"}"
echo "Response Status: $signup_status"
echo "Response Body: $signup_body"
if [ "$signup_status" -eq 201 ]; then
    print_result 0 "Email Signup"
else
    print_result 1 "Email Signup"
fi
# Extract verification code if present
VERIFICATION_CODE=$(echo "$signup_body" | jq -r '.code // empty')

# Test 2: Email Verification
if [ -z "$VERIFICATION_CODE" ]; then
    VERIFICATION_CODE="123456"
fi
test_endpoint "POST" "/auth/verify-email" "{\"email\":\"$TEST_EMAIL\",\"code\":\"$VERIFICATION_CODE\"}" 200 "Email Verification" false

# Test 3: Create Profile
test_endpoint "POST" "/auth/create-profile/email" "{\"email\":\"$TEST_EMAIL\",\"full_name\":\"Test User\",\"role\":\"user\"}" 201 "Create Profile" false

# Test 4: Login
test_endpoint "POST" "/auth/login" "{\"email\":\"$TEST_EMAIL\",\"password\":\"password123\"}" 200 "Login" true

# Test 5: Get User Profile
test_endpoint "GET" "/users/me" "" 200 "Get User Profile" false

# Test 6: Update User Profile
test_endpoint "PUT" "/users/me" "{\"full_name\":\"Updated Test User\",\"bio\":\"Test bio\"}" 200 "Update User Profile" false

# Test 7: Create Session
test_endpoint "POST" "/sessions/" "{\"device_info\":\"Test Device\"}" 201 "Create Session" false

# Test 8: Get Sessions
test_endpoint "GET" "/sessions/" "" 200 "Get Sessions" false

# Test 9: Update User Services
test_endpoint "PUT" "/users/me/services" "{\"services\":[\"service1\",\"service2\"]}" 200 "Update User Services" false

# Test 10: Update User Location
test_endpoint "PUT" "/users/me/location" "{\"latitude\":12.34,\"longitude\":56.78}" 200 "Update User Location" false

# Test 11: Update User Password (now expect 200)
test_endpoint "PUT" "/users/me/password" "{\"current_password\":\"password123\",\"new_password\":\"newpassword123\"}" 200 "Update User Password" false

# Test 12: Refresh Token
test_endpoint "POST" "/auth/refresh" "{\"refresh_token\":\"$REFRESH_TOKEN\"}" 200 "Refresh Token" true

# Test 13: Get Admin Stats
test_endpoint "GET" "/admin/stats" "" 200 "Get Admin Stats" false

# Test 14: Health Check
test_endpoint "GET" "/health" "" 200 "Health Check" false

# Test 15: Delete Session (now expect 204)
test_endpoint "DELETE" "/sessions/" "" 204 "Delete Session" false

# Test 16: Phone Signup
test_endpoint "POST" "/auth/signup/phone" "{\"phone\":\"$TEST_PHONE\"}" 200 "Phone Signup" false

# Test 17: Verify Phone OTP
test_endpoint "POST" "/auth/verify-otp" "{\"phone\":\"$TEST_PHONE\",\"otp\":\"123456\"}" 200 "Verify Phone OTP" false

# Test 18: Create Phone Profile
PHONE_PASSWORD="phonepassword123"
test_endpoint "POST" "/auth/create-profile/phone" "{\"phone\":\"$TEST_PHONE\",\"full_name\":\"Phone User\",\"password\":\"$PHONE_PASSWORD\"}" 201 "Create Phone Profile" false

# Test 19: Phone Signin
test_endpoint "POST" "/auth/signin/phone" "{\"phone\":\"$TEST_PHONE\",\"password\":\"$PHONE_PASSWORD\"}" 200 "Phone Signin" true

# Test 20: Forgot Password
test_endpoint "POST" "/auth/forgot-password" "{\"email\":\"$TEST_EMAIL\"}" 200 "Forgot Password" false

# Test 21: Verify Reset Code
test_endpoint "POST" "/auth/verify-reset-code" "{\"email\":\"$TEST_EMAIL\",\"code\":\"123456\"}" 200 "Verify Reset Code" false

# Test 22: Reset Password
test_endpoint "POST" "/auth/reset-password" "{\"email\":\"$TEST_EMAIL\",\"code\":\"123456\",\"new_password\":\"newpassword123\"}" 200 "Reset Password" false

# Print final results
echo -e "\n${YELLOW}Test Summary:${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo -e "Total: $((PASSED + FAILED))"

# Exit with status code based on test results
if [ $FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi 