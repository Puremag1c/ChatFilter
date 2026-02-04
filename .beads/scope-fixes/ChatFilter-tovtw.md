# Scope Fix: ChatFilter-tovtw

## Issue
Task ChatFilter-tovtw had 3 scope violations because executors tried to modify code when the task was actually an audit/verification task.

## Original Description
> Verify all POST endpoints in src/chatfilter/web/routers/sessions.py return success responses with proper HTMX attributes. files: src/chatfilter/web/routers/sessions.py (all action endpoints)

## Problem
The `files:` directive implied code modification was expected, but "Verify" indicates read-only analysis.

## Fix Applied
Added clarification in notes and design fields:
- Notes: "SCOPE CLARIFICATION: This is an AUDIT task. Do NOT modify code. Read sessions.py, analyze endpoints, report findings in notes."
- Design: "AUDIT SCOPE: Read-only analysis of 15 endpoints in sessions.py. No code changes. Report findings in notes."

## Endpoints to Audit
1. POST /api/sessions/upload
2. DELETE /api/sessions/{session_id}
3. POST /api/sessions/import/validate
4. PUT /api/sessions/{session_id}/config
5. PUT /api/sessions/{session_id}/credentials
6. POST /api/sessions/auth/start
7. POST /api/sessions/auth/code
8. POST /api/sessions/auth/2fa
9. POST /api/sessions/{session_id}/connect
10. POST /api/sessions/{session_id}/disconnect
11. POST /api/sessions/{session_id}/send-code
12. POST /api/sessions/{session_id}/reconnect/start
13. POST /api/sessions/{session_id}/verify-code
14. POST /api/sessions/{session_id}/verify-2fa
15. POST /api/sessions/import/save

## Expected Deliverable for ChatFilter-tovtw
Analysis report in notes field documenting:
- Each endpoint's current response handling
- HTMX attributes present/missing
- Recommendations (if any)
