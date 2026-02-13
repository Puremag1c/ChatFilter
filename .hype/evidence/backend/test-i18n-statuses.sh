#!/bin/bash
# Test if all session statuses from templates are translated

echo "=== Checking Session Status Translations ==="
echo ""

STATUSES=(
    "Connected"
    "Disconnected"
    "Connecting"
    "Setup Required"
    "Needs API ID"
    "Phone number required"
    "Proxy error"
)

PO_FILE="src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po"

echo "Checking $PO_FILE for status translations:"
echo ""

missing=0
found=0

for status in "${STATUSES[@]}"; do
    if grep -q "msgid \"$status\"" "$PO_FILE"; then
        translation=$(grep -A1 "msgid \"$status\"" "$PO_FILE" | tail -1)
        echo "✓ $status"
        echo "  $translation"
        found=$((found + 1))
    else
        echo "✗ MISSING: $status"
        missing=$((missing + 1))
    fi
done

echo ""
echo "Found: $found/$((found + missing))"
echo "Missing: $missing"

exit $missing
