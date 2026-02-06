"""Parser for TelegramExpert JSON format account info."""

import json
import re
from typing import Optional


def validate_account_info_json(json_data: object) -> str | None:
    """Validate account info JSON from uploaded file.

    Validates:
    - Must be a dict (no arrays at root)
    - Only allowed fields: phone, first_name, last_name, twoFA
    - No nested objects or arrays as values
    - Phone must be in E.164 format (optional + prefix, 7-15 digits)

    Args:
        json_data: Parsed JSON data to validate

    Returns:
        Error message string if invalid, None if valid
    """
    # Must be a dict
    if not isinstance(json_data, dict):
        return "JSON must be an object, not an array or primitive"

    # Allowed fields only
    allowed_fields = {"phone", "first_name", "last_name", "twoFA"}
    unknown_fields = set(json_data.keys()) - allowed_fields
    if unknown_fields:
        return f"Unknown fields not allowed: {', '.join(sorted(unknown_fields))}"

    # No nested objects or arrays
    for key, value in json_data.items():
        if isinstance(value, (dict, list)):
            return f"Field '{key}' cannot contain nested objects or arrays"

    # Validate phone field (required)
    if "phone" not in json_data or not json_data["phone"]:
        return "JSON file must contain 'phone' field"

    phone = str(json_data["phone"])
    # E.164 format: optional +, then 7-15 digits
    # Examples: +14385515736, 14385515736, +79001234567
    if not re.match(r"^\+?[1-9]\d{6,14}$", phone):
        return f"Invalid phone format: '{phone}'. Expected E.164 format (e.g., +14385515736)"

    return None


def parse_telegram_expert_json(
    json_content: bytes, json_data: dict
) -> tuple[dict[str, str], Optional[str]]:
    """Parse TelegramExpert JSON format and extract account info.

    Args:
        json_content: Raw JSON bytes (for secure zeroing)
        json_data: Already parsed JSON dict

    Returns:
        Tuple of (json_account_info dict, twofa_password)

    Raises:
        ValueError: If JSON validation fails
    """
    # Validate JSON structure, fields, and phone format
    validation_error = validate_account_info_json(json_data)
    if validation_error:
        raise ValueError(validation_error)

    # Extract account info from JSON (validated above)
    json_account_info = {
        "phone": str(json_data["phone"]),
        "first_name": str(json_data.get("first_name", "")),
        "last_name": str(json_data.get("last_name", "")),
    }

    # Extract 2FA password if present (will encrypt later)
    twofa_password = None
    if "twoFA" in json_data and json_data["twoFA"]:
        twofa_password = str(json_data["twoFA"])
        # Security: Zero plaintext 2FA in JSON dict to prevent memory leaks
        json_data["twoFA"] = "\x00" * len(json_data["twoFA"])
        del json_data["twoFA"]

    # Security: Zero plaintext JSON after parsing to prevent memory dumps
    if json_content:
        json_content = b'\x00' * len(json_content)
        del json_content

    return json_account_info, twofa_password
