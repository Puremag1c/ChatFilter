"""Telegram error mapping to user-friendly messages.

Maps Telegram API errors to human-readable messages suitable for display
in the UI. Helps prevent technical error messages from confusing users.

Example:
    ```python
    from telethon.errors import FloodWaitError
    from chatfilter.telegram.error_mapping import get_user_friendly_message

    try:
        await client.send_message(...)
    except FloodWaitError as e:
        # Technical: "A wait of 3600 seconds is required"
        # User-friendly: "Rate limit exceeded. Please wait 1 hour before trying again."
        friendly_msg = get_user_friendly_message(e)
        return {"error": friendly_msg}
    ```
"""

from __future__ import annotations

import re
from typing import TypedDict


class ActionInfo(TypedDict):
    """Structure for error action information."""

    action: str
    action_type: str
    can_retry: bool


def _format_duration(seconds: int) -> str:
    """Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Human-readable duration string (e.g., "5 minutes", "1 hour")

    Examples:
        >>> _format_duration(30)
        '30 seconds'
        >>> _format_duration(120)
        '2 minutes'
        >>> _format_duration(3600)
        '1 hour'
        >>> _format_duration(7200)
        '2 hours'
    """
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"


def _extract_wait_time(error: Exception) -> int | None:
    """Extract wait time from FloodWaitError.

    Args:
        error: Exception that might contain wait time info

    Returns:
        Wait time in seconds, or None if not found

    Examples:
        >>> from telethon.errors import FloodWaitError
        >>> err = FloodWaitError(request=None, capture=3600)
        >>> _extract_wait_time(err)
        3600
    """
    # FloodWaitError stores wait time in the 'seconds' attribute
    if hasattr(error, "seconds"):
        return int(error.seconds)

    # Fallback: try to extract from error message
    error_msg = str(error)
    match = re.search(r"(\d+)\s*seconds?", error_msg, re.IGNORECASE)
    if match:
        return int(match.group(1))

    return None


# Error type to user-friendly message mappings
ERROR_MESSAGES = {
    # Authentication & Session Errors
    "SessionExpiredError": "Your session has expired. Please log in again with a new session file.",
    "AuthKeyUnregisteredError": "Your session has expired or been revoked. Please log in again with a new session file.",
    "SessionRevokedError": "Your session has been logged out from another device. Please upload a new session file.",
    "AuthKeyDuplicatedError": "This session is being used on another device. Please use a unique session file.",
    "UnauthorizedError": "Authentication failed. Please verify your session and try again.",
    "UserDeactivatedError": "Your Telegram account has been deactivated. Please contact Telegram support.",
    "UserDeactivatedBanError": "Your Telegram account has been banned. Please contact Telegram support.",
    # Access Denied Errors
    "ChatForbiddenError": "Access to this chat is restricted. You may have been removed or the chat was deleted.",
    "ChannelPrivateError": "This channel is private. You need an invite link to access it.",
    "ChatRestrictedError": "This chat is restricted and cannot be accessed.",
    "ChannelBannedError": "You have been banned from this channel.",
    "UserBannedInChannelError": "You have been banned from this chat.",
    "ChatAdminRequiredError": "This action requires administrator privileges.",
    "ChatWriteForbiddenError": "You don't have permission to send messages in this chat.",
    # Rate Limiting (FloodWaitError is handled specially below)
    "SlowModeWaitError": "Slow mode is enabled in this chat. Please wait before sending another message.",
    # Network & Connection Errors
    "NetworkError": "Network connection error. Please check your internet connection and try again.",
    "TimeoutError": "Request timed out. Please try again.",
    "ConnectionError": "Failed to connect to Telegram servers. Please check your connection and try again.",
    # DC Migration Errors (usually handled automatically, users should retry)
    "FileMigrateError": "The file has been migrated to another data center. Please try again.",
    "NetworkMigrateError": "Network migration in progress. Please try again in a moment.",
    "PhoneMigrateError": "Your account is being migrated to another data center. Please try again.",
    "UserMigrateError": "Your account is being migrated to another data center. Please try again.",
    "StatsMigrateError": "Statistics are being migrated to another data center. Please try again.",
    # RPC & Server Errors
    "RpcCallFailError": "Telegram server request failed. Please try again.",
    "ServerError": "Telegram server encountered an error. Please try again.",
    # Invalid Input Errors
    "UsernameInvalidError": "Invalid username. Please check the username and try again.",
    "UsernameNotOccupiedError": "Username not found. Please verify the username is correct.",
    "InviteHashInvalidError": "Invalid invite link. The link may have expired or been revoked.",
    "InviteHashExpiredError": "This invite link has expired. Please request a new invite link.",
    "PeerIdInvalidError": "Chat or user not found. The ID may be incorrect or the chat may have been deleted.",
    "ChatIdInvalidError": "Invalid chat ID. The chat may have been deleted or is not accessible.",
    "MessageIdInvalidError": "Message not found. It may have been deleted.",
    # File & Media Errors
    "FilePartsInvalidError": "File upload failed. Please try uploading the file again.",
    "FileReferenceExpiredError": "File reference has expired. Please try again.",
    # Phone & 2FA Errors
    "PhoneNumberInvalidError": "Invalid phone number format. Please check the number and try again.",
    "PhoneCodeInvalidError": "Invalid verification code. Please check the code and try again.",
    "PhoneCodeExpiredError": "Verification code has expired. Please request a new code.",
    "PasswordHashInvalidError": "Incorrect password. Please try again.",
    "SessionPasswordNeededError": "Two-factor authentication is enabled. Please provide your password.",
    # Other Common Errors
    "ChatNotModifiedError": "No changes were made. The data is already up to date.",
    "MessageNotModifiedError": "Message was not modified. The content is the same as before.",
    "UserAlreadyParticipantError": "You are already a member of this chat.",
    "BotMethodInvalidError": "This action cannot be performed by bots.",
}


# Action guidance for each error type
# Maps error types to structured action recommendations
ERROR_ACTIONS: dict[str, ActionInfo] = {
    # Authentication & Session Errors
    "SessionExpiredError": {
        "action": "Upload a new session file from your Sessions page",
        "action_type": "reauth",
        "can_retry": False,
    },
    "AuthKeyUnregisteredError": {
        "action": "Upload a new session file from your Sessions page",
        "action_type": "reauth",
        "can_retry": False,
    },
    "SessionRevokedError": {
        "action": "Upload a new session file from your Sessions page",
        "action_type": "reauth",
        "can_retry": False,
    },
    "AuthKeyDuplicatedError": {
        "action": "Upload a different session file that isn't being used elsewhere",
        "action_type": "reauth",
        "can_retry": False,
    },
    "UnauthorizedError": {
        "action": "Verify your session file is valid or upload a new one",
        "action_type": "reauth",
        "can_retry": False,
    },
    "UserDeactivatedError": {
        "action": "Contact Telegram support to reactivate your account",
        "action_type": "contact_support",
        "can_retry": False,
    },
    "UserDeactivatedBanError": {
        "action": "Contact Telegram support to appeal your ban",
        "action_type": "contact_support",
        "can_retry": False,
    },
    # Access Denied Errors
    "ChatForbiddenError": {
        "action": "Try a different chat or check your Telegram app to verify membership",
        "action_type": "skip",
        "can_retry": False,
    },
    "ChannelPrivateError": {
        "action": "Request an invite link from the channel admin or try a different chat",
        "action_type": "skip",
        "can_retry": False,
    },
    "ChatRestrictedError": {
        "action": "Contact the chat administrator or try a different chat",
        "action_type": "skip",
        "can_retry": False,
    },
    "ChannelBannedError": {
        "action": "Contact the channel admin to appeal or select a different channel",
        "action_type": "skip",
        "can_retry": False,
    },
    "UserBannedInChannelError": {
        "action": "Contact the chat admin to appeal or select a different chat",
        "action_type": "skip",
        "can_retry": False,
    },
    "ChatAdminRequiredError": {
        "action": "Request admin privileges or perform this action as an admin",
        "action_type": "skip",
        "can_retry": False,
    },
    "ChatWriteForbiddenError": {
        "action": "Request write permissions from chat admin or skip this chat",
        "action_type": "skip",
        "can_retry": False,
    },
    # Rate Limiting
    "SlowModeWaitError": {
        "action": "Wait for the specified duration before trying again",
        "action_type": "wait",
        "can_retry": True,
    },
    # Network & Connection Errors
    "NetworkError": {
        "action": "Check your internet connection and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    "TimeoutError": {
        "action": "Check your connection speed and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    "ConnectionError": {
        "action": "Verify your internet connection is stable and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    # DC Migration Errors
    "FileMigrateError": {
        "action": "Click 'Retry' - this should resolve automatically",
        "action_type": "retry",
        "can_retry": True,
    },
    "NetworkMigrateError": {
        "action": "Wait a moment and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    "PhoneMigrateError": {
        "action": "Click 'Retry' - migration will complete automatically",
        "action_type": "retry",
        "can_retry": True,
    },
    "UserMigrateError": {
        "action": "Click 'Retry' - migration will complete automatically",
        "action_type": "retry",
        "can_retry": True,
    },
    "StatsMigrateError": {
        "action": "Click 'Retry' - migration will complete automatically",
        "action_type": "retry",
        "can_retry": True,
    },
    # RPC & Server Errors
    "RpcCallFailError": {
        "action": "Wait a moment and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    "ServerError": {
        "action": "Wait a few moments and click 'Retry'",
        "action_type": "retry",
        "can_retry": True,
    },
    # Invalid Input Errors
    "UsernameInvalidError": {
        "action": "Verify the username format is correct (e.g., @username)",
        "action_type": "check_input",
        "can_retry": False,
    },
    "UsernameNotOccupiedError": {
        "action": "Double-check the username spelling or try a different username",
        "action_type": "check_input",
        "can_retry": False,
    },
    "InviteHashInvalidError": {
        "action": "Request a new invite link or verify the link is correct",
        "action_type": "check_input",
        "can_retry": False,
    },
    "InviteHashExpiredError": {
        "action": "Request a new invite link from the chat admin",
        "action_type": "check_input",
        "can_retry": False,
    },
    "PeerIdInvalidError": {
        "action": "Verify the chat ID or try accessing the chat by username instead",
        "action_type": "check_input",
        "can_retry": False,
    },
    "ChatIdInvalidError": {
        "action": "Check the chat ID is correct or try accessing by username",
        "action_type": "check_input",
        "can_retry": False,
    },
    "MessageIdInvalidError": {
        "action": "The message may have been deleted - try refreshing the chat",
        "action_type": "skip",
        "can_retry": False,
    },
    # File & Media Errors
    "FilePartsInvalidError": {
        "action": "Re-upload the file or try a different file",
        "action_type": "retry",
        "can_retry": True,
    },
    "FileReferenceExpiredError": {
        "action": "Click 'Retry' to refresh the file reference",
        "action_type": "retry",
        "can_retry": True,
    },
    # Phone & 2FA Errors
    "PhoneNumberInvalidError": {
        "action": "Verify phone number format includes country code (e.g., +1234567890)",
        "action_type": "check_input",
        "can_retry": False,
    },
    "PhoneCodeInvalidError": {
        "action": "Check the verification code from Telegram and try again",
        "action_type": "check_input",
        "can_retry": False,
    },
    "PhoneCodeExpiredError": {
        "action": "Request a new verification code and try again",
        "action_type": "check_input",
        "can_retry": False,
    },
    "PasswordHashInvalidError": {
        "action": "Verify your two-factor authentication password and try again",
        "action_type": "check_input",
        "can_retry": False,
    },
    "SessionPasswordNeededError": {
        "action": "Provide your two-factor authentication password to continue",
        "action_type": "check_input",
        "can_retry": False,
    },
    # Other Common Errors
    "ChatNotModifiedError": {
        "action": "No action needed - the data is already up to date",
        "action_type": "skip",
        "can_retry": False,
    },
    "MessageNotModifiedError": {
        "action": "No action needed - the message content is unchanged",
        "action_type": "skip",
        "can_retry": False,
    },
    "UserAlreadyParticipantError": {
        "action": "No action needed - you are already a member",
        "action_type": "skip",
        "can_retry": False,
    },
    "BotMethodInvalidError": {
        "action": "This operation is not available for bot accounts",
        "action_type": "skip",
        "can_retry": False,
    },
}


def get_actionable_error_info(error: Exception) -> dict[str, str | bool | int | None]:
    """Get comprehensive error information with actionable guidance.

    Returns structured error information that tells users both WHAT happened
    and WHAT TO DO about it.

    Args:
        error: Exception from Telegram API (Telethon errors)

    Returns:
        Dictionary with:
            - message: User-friendly error message
            - action: Specific action user should take
            - action_type: Category of action (retry, reauth, check_input, skip, wait, contact_support)
            - can_retry: Whether retrying might resolve the error
            - wait_duration: Seconds to wait (for rate limits), None otherwise

    Examples:
        >>> from telethon.errors import FloodWaitError
        >>> err = FloodWaitError(request=None, capture=300)
        >>> info = get_actionable_error_info(err)
        >>> info['message']
        'Rate limit exceeded. Please wait 5 minutes before trying again.'
        >>> info['action']
        'Wait 5 minutes and then click 'Retry''
        >>> info['action_type']
        'wait'
        >>> info['can_retry']
        True
        >>> info['wait_duration']
        300

        >>> from telethon.errors import SessionExpiredError
        >>> err = SessionExpiredError(request=None)
        >>> info = get_actionable_error_info(err)
        >>> info['action']
        'Upload a new session file from your Sessions page'
        >>> info['action_type']
        'reauth'
        >>> info['can_retry']
        False
    """
    error_class = type(error).__name__
    wait_duration = None

    # Special handling for FloodWaitError (includes wait time)
    if error_class == "FloodWaitError":
        wait_duration = _extract_wait_time(error)
        if wait_duration:
            duration_str = _format_duration(wait_duration)
            message = f"Rate limit exceeded. Please wait {duration_str} before trying again."
            action = f"Wait {duration_str} and then click 'Retry'"
        else:
            message = "Rate limit exceeded. Please wait before trying again."
            action = "Wait a few minutes and then click 'Retry'"

        return {
            "message": message,
            "action": action,
            "action_type": "wait",
            "can_retry": True,
            "wait_duration": wait_duration,
        }

    # Special handling for SlowModeWaitError (includes wait time)
    if error_class == "SlowModeWaitError":
        wait_duration = _extract_wait_time(error)
        if wait_duration:
            duration_str = _format_duration(wait_duration)
            message = (
                f"Slow mode is enabled. Please wait {duration_str} before sending another message."
            )
            action = f"Wait {duration_str} before trying again"
        else:
            message = ERROR_MESSAGES.get(
                error_class, "Slow mode is enabled. Please wait before sending another message."
            )
            action = "Wait for the slow mode cooldown before trying again"

        return {
            "message": message,
            "action": action,
            "action_type": "wait",
            "can_retry": True,
            "wait_duration": wait_duration,
        }

    # Get message from mapping or use fallback
    message = get_user_friendly_message(error)

    # Get action guidance if available
    action_info = ERROR_ACTIONS.get(error_class)
    if action_info:
        return {
            "message": message,
            "action": action_info["action"],
            "action_type": action_info["action_type"],
            "can_retry": action_info["can_retry"],
            "wait_duration": wait_duration,
        }

    # Fallback action guidance based on error category
    category = get_error_category(error)
    if category == "network":
        action = "Check your internet connection and click 'Retry'"
        action_type = "retry"
        can_retry = True
    elif category == "auth":
        action = "Upload a new session file from your Sessions page"
        action_type = "reauth"
        can_retry = False
    elif category == "access":
        action = "Try a different chat or verify your access permissions"
        action_type = "skip"
        can_retry = False
    elif category == "invalid_input":
        action = "Check your input and try again with correct information"
        action_type = "check_input"
        can_retry = False
    elif category == "rate_limit":
        action = "Wait a few minutes and click 'Retry'"
        action_type = "wait"
        can_retry = True
    else:
        action = "Try again or contact support if the issue persists"
        action_type = "retry"
        can_retry = True

    return {
        "message": message,
        "action": action,
        "action_type": action_type,
        "can_retry": can_retry,
        "wait_duration": wait_duration,
    }


def get_user_friendly_message(error: Exception) -> str:
    """Convert a Telegram API exception to a user-friendly message.

    Args:
        error: Exception from Telegram API (Telethon errors)

    Returns:
        User-friendly error message suitable for display in UI

    Examples:
        >>> from telethon.errors import ChatForbiddenError
        >>> err = ChatForbiddenError(request=None)
        >>> get_user_friendly_message(err)
        'Access to this chat is restricted. You may have been removed or the chat was deleted.'

        >>> from telethon.errors import FloodWaitError
        >>> err = FloodWaitError(request=None, capture=3600)
        >>> get_user_friendly_message(err)
        'Rate limit exceeded. Please wait 1 hour before trying again.'
    """
    error_class = type(error).__name__

    # Special handling for FloodWaitError (includes wait time)
    if error_class == "FloodWaitError":
        wait_time = _extract_wait_time(error)
        if wait_time:
            duration_str = _format_duration(wait_time)
            return f"Rate limit exceeded. Please wait {duration_str} before trying again."
        return "Rate limit exceeded. Please wait before trying again."

    # Special handling for SlowModeWaitError (includes wait time)
    if error_class == "SlowModeWaitError":
        wait_time = _extract_wait_time(error)
        if wait_time:
            duration_str = _format_duration(wait_time)
            return (
                f"Slow mode is enabled. Please wait {duration_str} before sending another message."
            )
        return ERROR_MESSAGES.get(
            error_class, "Slow mode is enabled. Please wait before sending another message."
        )

    # Look up in mapping
    if error_class in ERROR_MESSAGES:
        return ERROR_MESSAGES[error_class]

    # Fallback: try to make the technical error more readable
    error_msg = str(error)

    # Handle common patterns in error messages
    if "flood" in error_msg.lower():
        # Try to extract wait time from message
        match = re.search(r"(\d+)\s*seconds?", error_msg, re.IGNORECASE)
        if match:
            wait_seconds = int(match.group(1))
            duration_str = _format_duration(wait_seconds)
            return f"Rate limit exceeded. Please wait {duration_str} before trying again."
        return "Rate limit exceeded. Please wait before trying again."

    if "session" in error_msg.lower() and (
        "expired" in error_msg.lower() or "revoked" in error_msg.lower()
    ):
        return "Your session has expired. Please log in again with a new session file."

    if "banned" in error_msg.lower() or "kicked" in error_msg.lower():
        return "Access denied. You may have been banned or removed from this chat."

    if "private" in error_msg.lower() or "forbidden" in error_msg.lower():
        return "Access to this resource is restricted."

    if "timeout" in error_msg.lower():
        return "Request timed out. Please try again."

    if "network" in error_msg.lower() or "connection" in error_msg.lower():
        return "Network connection error. Please check your internet connection and try again."

    if "invalid" in error_msg.lower() and (
        "username" in error_msg.lower() or "peer" in error_msg.lower()
    ):
        return "Chat or user not found. Please verify the information is correct."

    # Default fallback for unknown errors
    # Include the error class name to help with debugging
    return f"An error occurred: {error_class}. Please try again or contact support if the issue persists."


def get_error_category(error: Exception) -> str:
    """Get the category of an error for logging and analytics.

    Args:
        error: Exception from Telegram API

    Returns:
        Error category string (auth, access, rate_limit, network, invalid_input, other)

    Examples:
        >>> from telethon.errors import SessionExpiredError
        >>> get_error_category(SessionExpiredError(request=None))
        'auth'

        >>> from telethon.errors import FloodWaitError
        >>> get_error_category(FloodWaitError(request=None, capture=60))
        'rate_limit'
    """
    error_class = type(error).__name__

    # Authentication & Session
    if error_class in {
        "SessionExpiredError",
        "AuthKeyUnregisteredError",
        "SessionRevokedError",
        "AuthKeyDuplicatedError",
        "UnauthorizedError",
        "UserDeactivatedError",
        "UserDeactivatedBanError",
        "PasswordHashInvalidError",
        "SessionPasswordNeededError",
    }:
        return "auth"

    # Access Denied
    if error_class in {
        "ChatForbiddenError",
        "ChannelPrivateError",
        "ChatRestrictedError",
        "ChannelBannedError",
        "UserBannedInChannelError",
        "ChatAdminRequiredError",
        "ChatWriteForbiddenError",
    }:
        return "access"

    # Rate Limiting
    if error_class in {"FloodWaitError", "SlowModeWaitError"}:
        return "rate_limit"

    # Network & Connection (including DC migration and RPC errors)
    if error_class in {
        "NetworkError",
        "TimeoutError",
        "ConnectionError",
        "FileMigrateError",
        "NetworkMigrateError",
        "PhoneMigrateError",
        "UserMigrateError",
        "StatsMigrateError",
        "RpcCallFailError",
        "ServerError",
    }:
        return "network"

    # Invalid Input
    if error_class in {
        "UsernameInvalidError",
        "UsernameNotOccupiedError",
        "InviteHashInvalidError",
        "InviteHashExpiredError",
        "PeerIdInvalidError",
        "ChatIdInvalidError",
        "MessageIdInvalidError",
        "PhoneNumberInvalidError",
        "PhoneCodeInvalidError",
        "PhoneCodeExpiredError",
    }:
        return "invalid_input"

    return "other"


def should_retry_on_error(error: Exception) -> bool:
    """Determine if an operation should be retried based on the error type.

    Args:
        error: Exception from Telegram API

    Returns:
        True if the operation can be retried, False otherwise

    Examples:
        >>> from telethon.errors import FloodWaitError, SessionExpiredError
        >>> should_retry_on_error(FloodWaitError(request=None, capture=5))
        True
        >>> should_retry_on_error(SessionExpiredError(request=None))
        False
    """
    category = get_error_category(error)

    # Retry on network errors and some rate limits
    if category in {"network"}:
        return True

    # Don't retry on auth failures (user needs to re-authenticate)
    if category == "auth":
        return False

    # Don't retry on access denied (permanent restriction)
    if category == "access":
        return False

    # Don't retry on invalid input (user needs to fix input)
    if category == "invalid_input":
        return False

    # For rate limits, retry is possible but should respect wait time
    if category == "rate_limit":
        # Could potentially retry with exponential backoff
        # But FloodWait requires specific wait time
        error_class = type(error).__name__
        if error_class == "FloodWaitError":
            # Should wait for the specified time before retry
            return True
        if error_class == "SlowModeWaitError":
            # Should respect slow mode wait time
            return True

    # Unknown errors - safer not to retry
    return False
