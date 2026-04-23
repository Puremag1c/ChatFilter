"""File upload and import endpoints for sessions."""

from __future__ import annotations

import contextlib
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.parsers.telegram_expert import (
    parse_telegram_expert_json,
    validate_account_info_json,
)
from chatfilter.telegram.client.config import TelegramConfigError
from chatfilter.utils.disk import DiskSpaceError
from chatfilter.web.dependencies import get_owner_key, get_pool_scope, get_proxy_scope

from . import router
from .io import (
    MAX_CONFIG_SIZE,
    MAX_JSON_SIZE,
    MAX_SESSION_SIZE,
    _save_session_to_disk,
    ensure_data_dir,
    find_duplicate_accounts,
    get_account_info_from_session,
    load_account_info,
    read_upload_with_size_limit,
    save_account_info,
)
from .validation import (
    sanitize_session_name,
    validate_config_file_format,
    validate_session_file_format,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@router.post("/api/sessions/upload", response_class=HTMLResponse)
async def upload_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    config_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Upload a new session with config file.

    Args:
        json_file: Optional JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Pool scope decides the on-disk subdirectory: "admin" for shared
        # admin uploads (URL /admin/*), "user_<id>" for personal uploads.
        pool_scope = get_pool_scope(request)
        # Atomically create session directory to prevent TOCTOU race
        session_dir = ensure_data_dir(pool_scope) / safe_name
        try:
            session_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Read and validate config file with size limit enforcement
        try:
            config_content = await read_upload_with_size_limit(
                config_file, MAX_CONFIG_SIZE, "config"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_config_file_format(config_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid config: {error}").format(error=e)},
            )

        # Parse JSON file if provided (TelegramExpert format)
        json_account_info: dict[str, int | str] | None = None
        twofa_password = None
        if json_file:
            try:
                # Read JSON with size limit (10KB max)
                json_content = await read_upload_with_size_limit(json_file, MAX_JSON_SIZE, "JSON")
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": str(e)},
                )

            try:
                json_data = json.loads(json_content)
                # Security: Zero plaintext JSON after parsing to prevent memory dumps
                json_content = b"\x00" * len(json_content)
                del json_content
            except json.JSONDecodeError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={
                        "success": False,
                        "error": _("Invalid JSON format: {error}").format(error=str(e)),
                    },
                )

            # Validate JSON structure, fields, and phone format
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": _(validation_error)},
                )

            # Extract account info from JSON (validated above)
            json_account_info = {
                "phone": str(json_data["phone"]),
                "first_name": str(json_data.get("first_name", "")),
                "last_name": str(json_data.get("last_name", "")),
            }

            # Extract 2FA password if present (will encrypt later)
            if "twoFA" in json_data and json_data["twoFA"]:
                twofa_password = str(json_data["twoFA"])
                # Security: Zero plaintext 2FA in JSON dict to prevent memory leaks
                json_data["twoFA"] = "\x00" * len(json_data["twoFA"])
                del json_data["twoFA"]

        # Extract account info from session to check for duplicates

        account_info = None
        duplicate_sessions = []

        # Create a temporary session file to test connection
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            # Try to get account info from the session using global telegram config
            account_info = await get_account_info_from_session(tmp_session_path)

            if account_info:
                # Check for duplicate accounts
                user_id = account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(
                        user_id, exclude_session=safe_name, web_user_id=pool_scope
                    )
        finally:
            # Clean up temporary session file
            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session with atomic transaction (no orphaned files on failure)
        # session_dir already created (mkdir exist_ok=False) to prevent TOCTOU race
        # _save_session_to_disk() creates temp dir, writes files, then renames over empty session_dir
        try:
            # proxy_id is None - user must configure it after upload
            # source is 'file' because config was uploaded
            # Use json_account_info if provided, otherwise use account_info from session
            final_account_info = json_account_info if json_account_info else account_info

            # Stamp the pool owner onto the account_info so the scheduler
            # routes analyses correctly. Admin uploads feed the shared
            # "admin" pool; non-admin uploads go to the uploader's private
            # "user:{id}" pool.
            owner_key = get_owner_key(request)
            if final_account_info is not None:
                final_account_info = {**final_account_info, "owner": owner_key}

            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                proxy_id=None,
                account_info=final_account_info,
                source="file",
                web_user_id=pool_scope,
            )

        except DiskSpaceError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Insufficient disk space. Please free up disk space and try again."),
                },
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _(
                        "Configuration error. Please check your session file and credentials."
                    ),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' uploaded successfully")

        # Store encrypted 2FA password if provided in JSON
        if twofa_password:
            try:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA password for session: {safe_name}")
            except Exception:
                logger.exception("Failed to store 2FA password")
                # Don't fail the upload if 2FA storage fails
            finally:
                # Security: Zero plaintext 2FA password in memory after encryption
                if twofa_password:
                    twofa_password = "\x00" * len(twofa_password)
                    del twofa_password

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' uploaded successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session upload")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during upload. Please try again."),
            },
        )


@router.post("/api/sessions/import/validate", response_class=HTMLResponse)
async def validate_import_session(
    request: Request,
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Validate session and JSON files for import.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with validation result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate session file format
        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate JSON file
        try:
            json_content = await read_upload_with_size_limit(json_file, MAX_JSON_SIZE, "JSON")
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Validate JSON structure and fields using dedicated parser module
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/import_validation_result.html",
                    context={"success": False, "error": validation_error},
                )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={
                    "success": False,
                    "error": _("Invalid JSON format: {error}").format(error=str(e)),
                },
            )

        logger.info("Session and JSON files validated successfully for import")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={
                "success": True,
            },
        )

    except Exception:
        logger.exception("Unexpected error during session validation")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during validation."),
            },
        )


@router.post("/api/sessions/import/save", response_class=HTMLResponse)
async def save_import_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Save an imported session with configuration.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with save result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Check if session already exists
        from chatfilter.web.dependencies import get_pool_scope

        web_user_id = get_pool_scope(request)  # "admin" or "user_<id>"
        session_dir = ensure_data_dir(web_user_id) / safe_name
        if session_dir.exists():
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Validate proxy exists — use the proxy-scope key (admin / user_<id>)
        # matching what /api/proxies writes, not the session-pool scope.
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        try:
            get_proxy_by_id(proxy_id, get_proxy_scope(request))
        except StorageNotFoundError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Selected proxy not found. Please select a valid proxy."),
                },
            )

        # Parse JSON file for account info (TelegramExpert format)
        twofa_password = None

        try:
            json_content = await read_upload_with_size_limit(json_file, MAX_JSON_SIZE, "JSON")
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Parse and validate JSON using dedicated parser module
            _account_info_str, twofa_password = parse_telegram_expert_json(json_content, json_data)
            account_info: dict[str, int | str] = dict(_account_info_str)

        except ValueError as e:
            # Validation error from parser
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Invalid JSON format: {error}").format(error=str(e)),
                },
            )

        # Try to get user_id from session for duplicate check
        # JSON account_info is already prepared above as primary source

        duplicate_sessions = []

        # Create a temporary session file to try extracting user_id
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            # Try to get user_id from session (best effort)
            session_account_info = await get_account_info_from_session(tmp_session_path)

            # Add user_id to account_info if available from session
            if session_account_info and "user_id" in session_account_info:
                account_info["user_id"] = str(session_account_info["user_id"])

                # Check for duplicate accounts only if we have user_id
                user_id = session_account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(
                        user_id, exclude_session=safe_name, web_user_id=web_user_id
                    )

        finally:
            # Clean up temporary session file
            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session files (directory created atomically by _save_session_to_disk)
        try:
            # source is 'file' because session was imported from file
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                proxy_id=proxy_id,
                account_info=account_info,
                source="file",
                web_user_id=web_user_id,
            )

            # Encrypt and save 2FA password if provided in JSON
            if twofa_password:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir.parent
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA for session: {safe_name}")

                # Update account_info to indicate 2FA is available
                if account_info:
                    account_info_data = load_account_info(session_dir) or {}
                    account_info_data["has_2fa"] = True
                    save_account_info(session_dir, account_info_data)

        except DiskSpaceError:
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Insufficient disk space. Please free up disk space and try again."),
                },
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _(
                        "Configuration error. Please check your session file and credentials."
                    ),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' imported successfully")

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' imported successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session import")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during import. Please try again."),
            },
        )
