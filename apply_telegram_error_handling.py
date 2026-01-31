#!/usr/bin/env python3
"""
Comprehensive script to add Telegram error handling to all auth endpoints in sessions.py
"""

# Read the file
with open("/Users/m/Zen/Code/ChatFilter/src/chatfilter/web/routers/sessions.py", "r") as f:
    content = f.read()

# 1. Update imports for send_code endpoints (2 occurrences)
content = content.replace(
    """    from telethon import TelegramClient
    from telethon.errors import (
        ApiIdInvalidError,
        FloodWaitError,
        PhoneNumberBannedError,
        PhoneNumberInvalidError,
    )""",
    """    from telethon import TelegramClient
    from telethon.errors import (
        ApiIdInvalidError,
        AuthKeyUnregisteredError,
        FloodWaitError,
        PhoneNumberBannedError,
        PhoneNumberFloodError,
        PhoneNumberInvalidError,
        SessionExpiredError,
        SessionRevokedError,
    )""",
)

# 2. Update imports for verify_code endpoints (2 occurrences)
content = content.replace(
    """    from telethon.errors import (
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )""",
    """    from telethon.errors import (
        AuthKeyUnregisteredError,
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionExpiredError,
        SessionPasswordNeededError,
        SessionRevokedError,
    )""",
)

# 3. Update imports for verify_2fa endpoint (submit_auth_2fa - old API)
content = content.replace(
    """    from telethon.errors import PasswordHashInvalidError

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager""",
    """    from telethon.errors import (
        AuthKeyUnregisteredError,
        PasswordHashInvalidError,
        SessionExpiredError,
        SessionRevokedError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager""",
)

# 4. Add error handlers after FloodWaitError in send_code endpoints
send_code_error_handlers = """    except PhoneNumberFloodError:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Too many phone number operations. Please wait a few hours before trying again."),
            },
        )
    except SessionRevokedError:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("This session has been revoked. Please delete and recreate the session."),
            },
        )
    except SessionExpiredError:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session has expired. Please delete and recreate the session."),
            },
        )
    except AuthKeyUnregisteredError:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Authorization key is unregistered. Please delete and recreate the session."),
            },
        )
"""

content = content.replace(
    """    except FloodWaitError as e:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _(
                    "Too many requests. Please wait {seconds} seconds before trying again."
                ).format(seconds=e.seconds),
            },
        )
    except (OSError, ConnectionError, ConnectionRefusedError) as e:""",
    """    except FloodWaitError as e:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _(
                    "Too many requests. Please wait {seconds} seconds before trying again."
                ).format(seconds=e.seconds),
            },
        )
""" + send_code_error_handlers + """    except (OSError, ConnectionError, ConnectionRefusedError) as e:""",
)

# 5. Add error handlers after PhoneCodeExpiredError in verify_code endpoints
verify_code_error_handlers = """    except SessionRevokedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("This session has been revoked. Please start over."),
            },
        )
    except SessionExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session has expired. Please start over."),
            },
        )
    except AuthKeyUnregisteredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Authorization key is unregistered. Please start over."),
            },
        )
"""

content = content.replace(
    """    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
        )

    except PhoneCodeEmptyError:""",
    """    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
        )
""" + verify_code_error_handlers + """

    except PhoneCodeEmptyError:""",
)

# 6. Add error handlers after PasswordHashInvalidError in verify_2fa endpoint (old API)
verify_2fa_error_handlers = """    except SessionRevokedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("This session has been revoked. Please start over."),
            },
        )
    except SessionExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session has expired. Please start over."),
            },
        )
    except AuthKeyUnregisteredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Authorization key is unregistered. Please start over."),
            },
        )
"""

content = content.replace(
    """    except PasswordHashInvalidError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Incorrect password. Please try again."),
            },
        )

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",""",
    """    except PasswordHashInvalidError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Incorrect password. Please try again."),
            },
        )
""" + verify_2fa_error_handlers + """

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",""",
)

# Write the updated content
with open("/Users/m/Zen/Code/ChatFilter/src/chatfilter/web/routers/sessions.py", "w") as f:
    f.write(content)

print("✓ Telegram error handling successfully added!")
print("\nChanges made:")
print("  1. Updated imports in send_code endpoints (2 occurrences)")
print("  2. Updated imports in verify_code endpoints (2 occurrences)")
print("  3. Updated imports in verify_2fa endpoint (1 occurrence)")
print("  4. Added error handlers for:")
print("     - PhoneNumberFloodError")
print("     - SessionRevokedError")
print("     - SessionExpiredError")
print("     - AuthKeyUnregisteredError")
print("  5. Applied handlers to all relevant endpoints")
