#!/bin/bash

# Check status codes
echo "=== Status Code Analysis ==="
echo ""
echo "Root (/) endpoint: $(tail -1 .hype/evidence/api/root.txt)"
echo "/sessions endpoint: $(tail -1 .hype/evidence/api/sessions.txt)"
echo "/health endpoint: $(tail -1 .hype/evidence/api/health.txt)"
echo "/api/health endpoint: $(tail -1 .hype/evidence/api/api-health.txt)"
