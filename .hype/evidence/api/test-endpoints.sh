#!/bin/bash
# Test all key API endpoints

BASE_URL="http://localhost:8000"
OUTPUT_DIR=".hype/evidence/api"

# Test GET endpoints
echo "Testing GET endpoints..."
curl -s -w "\n%{http_code}" "$BASE_URL/health" > "$OUTPUT_DIR/health-check.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/ready" > "$OUTPUT_DIR/ready-check.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/api/version/check-updates" > "$OUTPUT_DIR/version-check.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/api/proxies" > "$OUTPUT_DIR/proxies-list.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/api/sessions" > "$OUTPUT_DIR/sessions-list.txt"

# Test 404 behavior
echo "Testing 404 behavior..."
curl -s -w "\n%{http_code}" "$BASE_URL/api/nonexistent" > "$OUTPUT_DIR/404-test.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/api/sessions/nonexistent/config" > "$OUTPUT_DIR/404-test-session-config.txt"

# Test missing parameters (should return 422 validation error)
echo "Testing validation errors..."
curl -s -w "\n%{http_code}" "$BASE_URL/api/chats/json" > "$OUTPUT_DIR/chats-json.txt"
curl -s -w "\n%{http_code}" "$BASE_URL/api/account-info/json" > "$OUTPUT_DIR/account-info-json.txt"

# Test POST without CSRF token (should return 403)
echo "Testing CSRF protection..."
curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/sessions/upload" > "$OUTPUT_DIR/400-test.txt"
curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/sessions/auth/start" -d '{}' > "$OUTPUT_DIR/400-test-auth-start.txt"

echo "Tests complete"
