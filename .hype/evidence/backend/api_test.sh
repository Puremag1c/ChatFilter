#!/bin/bash
# Backend API Logic Test
# Tests the API endpoints for session management

BASE_URL="http://localhost:8000"
echo "=== Backend API Tests ==="
echo "Testing against: $BASE_URL"
echo

# Test 1: List sessions (should work even without sessions)
echo "Test 1: GET /api/sessions (list sessions)"
curl -s "$BASE_URL/api/sessions" | grep -o '<tr' | wc -l
echo "Expected: HTML response with table rows"
echo

# Test 2: Check if upload endpoint exists
echo "Test 2: POST /api/sessions/upload (check endpoint exists)"
curl -s -X POST "$BASE_URL/api/sessions/upload" -F "session_name=test" 2>&1 | head -5
echo

# Test 3: Check if session events SSE endpoint exists
echo "Test 3: GET /api/sessions/events (SSE endpoint)"
timeout 2 curl -s "$BASE_URL/api/sessions/events" -H "Accept: text/event-stream" &
sleep 1
echo "Expected: SSE stream (timeout after 2s)"
echo

# Test 4: Check main sessions page
echo "Test 4: GET / (main page)"
curl -s "$BASE_URL/" | grep -i "chatfilter" | head -1
echo

echo "=== API Tests Complete ==="
