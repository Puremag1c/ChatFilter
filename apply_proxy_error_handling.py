#!/usr/bin/env python3
"""Apply proxy connection error handling to all auth endpoints."""

import re

file_path = 'src/chatfilter/web/routers/sessions.py'

# Read the file
with open(file_path, 'r') as f:
    content = f.read()

# Patch 1: Add OSError/ConnectionError handler after FloodWaitError in both send_code endpoints
flood_wait_pattern = r'''(    except FloodWaitError as e:
        if "client" in dir\(\) and client\.is_connected\(\):
            await client\.disconnect\(\)
        secure_delete_dir\(temp_dir\)
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_result\.html",
            context=\{
                "success": False,
                "error": _\(
                    "Too many requests\. Please wait \{seconds\} seconds before trying again\."
                \)\.format\(seconds=e\.seconds\),
            \},
        \)
)(    except TimeoutError:)'''

flood_wait_replacement = r'''\1    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed: {type(e).__name__}"
        save_account_info(session_dir, account_info)

        logger.error(f"Proxy connection failed for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )
\2'''

content = re.sub(flood_wait_pattern, flood_wait_replacement, content)

# Patch 2: Update TimeoutError handlers in send_code to save session state
timeout_pattern_send = r'''(    except TimeoutError:
        if "client" in dir\(\) and client\.is_connected\(\):
            await client\.disconnect\(\)
        secure_delete_dir\(temp_dir\)
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_result\.html",
            context=\{
                "success": False,
                "error": _\("Connection timeout\. Please check your proxy settings and try again\."\),
            \},
        \))'''

timeout_replacement_send = r'''    except TimeoutError:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout"
        save_account_info(session_dir, account_info)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection timeout. Please check your proxy settings and try again."),
            },
        )'''

content = re.sub(timeout_pattern_send, timeout_replacement_send, content)

# Patch 3: Add proxy error handling to verify_code
# Find TimeoutError in verify_code (returns auth_code_form, not auth_result)
verify_code_timeout_pattern = r'''(    except PhoneCodeEmptyError:
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_code_form\.html",
            context=\{
                "auth_id": auth_id,
                "phone": auth_state\.phone,
                "session_name": safe_name,
                "error": _\("Please enter the verification code\."\),
            \},
        \)
)
(    except TimeoutError:
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_code_form\.html",
            context=\{
                "auth_id": auth_id,
                "phone": auth_state\.phone,
                "session_name": safe_name,
                "error": _\("Request timeout\. Please try again\."\),
            \},
        \))'''

verify_code_timeout_replacement = r'''\1
    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during code verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)

        logger.error(f"Proxy connection failed during code verification for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )

    except TimeoutError:
        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during code verification"
        save_account_info(session_dir, account_info)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "error": _("Request timeout. Please try again."),
            },
        )'''

content = re.sub(verify_code_timeout_pattern, verify_code_timeout_replacement, content, flags=re.DOTALL)

# Patch 4: Add proxy error handling to verify_2fa
verify_2fa_password_pattern = r'''(    except PasswordHashInvalidError:
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_2fa_form\.html",
            context=\{
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _\("Incorrect password\. Please try again\."\),
            \},
        \)
)
(    except TimeoutError:
        return templates\.TemplateResponse\(
            request=request,
            name="partials/auth_2fa_form\.html",
            context=\{
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _\("Request timeout\. Please try again\."\),
            \},
        \))'''

verify_2fa_password_replacement = r'''\1
    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during 2FA verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)

        logger.error(f"Proxy connection failed during 2FA verification for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )

    except TimeoutError:
        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during 2FA verification"
        save_account_info(session_dir, account_info)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Request timeout. Please try again."),
            },
        )'''

content = re.sub(verify_2fa_password_pattern, verify_2fa_password_replacement, content, flags=re.DOTALL)

# Write back
with open(file_path, 'w') as f:
    f.write(content)

print("Successfully applied proxy connection error handling to all auth endpoints")
