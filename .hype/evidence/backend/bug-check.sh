#!/bin/bash

# Bug Creation Protocol Check

# 1. Google Sheets async mock issue
ISSUE_KEYWORD="google sheets async"
OPEN_BUG=$(bd list --status=open --json 2>/dev/null | jq -r ".[] | select(.title | ascii_downcase | contains(\"$ISSUE_KEYWORD\")) | .id" | head -1)

echo "=== Google Sheets Issue Check ==="
if [ -n "$OPEN_BUG" ]; then
    echo "SKIP: Similar OPEN bug exists: $OPEN_BUG"
else
    CLOSED_BUG=$(bd list --status=closed --json 2>/dev/null | jq -r ".[] | select(.title | ascii_downcase | contains(\"google\") and (.title | ascii_downcase | contains(\"sheets\") or .title | ascii_downcase | contains(\"mock\"))) | .id" | head -1)
    if [ -n "$CLOSED_BUG" ]; then
        echo "REGRESSION candidate: $CLOSED_BUG"
    else
        echo "NEW BUG: Google Sheets async mock issue"
    fi
fi

# 2. psutil missing dependency
ISSUE_KEYWORD="psutil"
OPEN_BUG=$(bd list --status=open --json 2>/dev/null | jq -r ".[] | select(.title | ascii_downcase | contains(\"$ISSUE_KEYWORD\")) | .id" | head -1)

echo ""
echo "=== psutil Missing Dependency Check ==="
if [ -n "$OPEN_BUG" ]; then
    echo "SKIP: Similar OPEN bug exists: $OPEN_BUG"
else
    CLOSED_BUG=$(bd list --status=closed --json 2>/dev/null | jq -r ".[] | select(.title | ascii_downcase | contains(\"$ISSUE_KEYWORD\")) | .id" | head -1)
    if [ -n "$CLOSED_BUG" ]; then
        echo "REGRESSION candidate: $CLOSED_BUG"
    else
        echo "NEW BUG: psutil missing dependency"
    fi
fi
