// Sessions list page logic: SSE handling, modals, operation tracking
(function() {
    // Wait for DOM and check if we're on sessions page
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    function init() {
        // Only initialize if sessions table exists
        if (!document.querySelector('.accounts-table-container')) {
            return;
        }

        setupSessionsListLogic();
    }

    function setupSessionsListLogic() {
        // Local i18n helper
        const t = (key) => {
            if (typeof window.i18n !== 'undefined' && window.i18n.t) {
                return window.i18n.t(key);
            }
            console.warn('[sessions-list] i18n not available, key:', key);
            return key;
        };

        // SSE event handling: HTMX SSE extension receives HTML with hx-swap-oob="true"
        // OOB (Out-of-Band) swaps update individual session rows by ID
        // hx-swap="none" prevents replacing the container - only OOB elements are updated

        // Timeout feedback for long-running operations (10s+ shows "Still working...", 30s+ shows elapsed time)
        const operationTimers = new Map();

        // SSE connection error debouncing - only show banner after 5s disconnect
        var disconnectTimer = null;
        var isDisconnected = false;

        function showTimeoutFeedback(element, sessionId, startTime) {
            if (!element || !element.isConnected) return;
            const spinner = element.querySelector('.htmx-indicator, .spinner');
            if (!spinner) return;

            const elapsed = Math.floor((Date.now() - startTime) / 1000);

            // Create or update feedback message
            let feedback = spinner.querySelector('.operation-feedback');
            if (!feedback) {
                feedback = document.createElement('span');
                feedback.className = 'operation-feedback';
                feedback.style.marginLeft = '8px';
                feedback.style.fontSize = '0.875rem';
                feedback.style.color = 'var(--text-secondary, #666)';
                spinner.appendChild(feedback);
            }

            if (elapsed >= 30) {
                // Show elapsed time for very long operations
                feedback.textContent = `(${elapsed}s)`;
            } else if (elapsed >= 10) {
                // Show "Still working..." after 10 seconds
                feedback.textContent = t('sessions_list.messages.still_working');
            }
        }

        // Start tracking operation on HTMX request
        document.body.addEventListener('htmx:beforeRequest', function(evt) {
            const element = evt.detail.elt;
            if (!element) return;

            // Only track session action buttons (Connect/Disconnect/Send Code)
            if (!element.classList.contains('session-connect-btn') &&
                !element.classList.contains('session-disconnect-btn') &&
                !element.classList.contains('session-code-modal-btn') &&
                !element.classList.contains('session-2fa-modal-btn')) {
                return;
            }

            // Find session ID
            const sessionId = element.dataset.sessionId ||
                             element.closest('[data-session-id]')?.dataset.sessionId ||
                             element.closest('[id^="session-"]')?.id.replace('session-', '');

            if (!sessionId) return;

            // Explicitly hide Connect/Disconnect buttons during operation
            if (element.classList.contains('session-connect-btn') ||
                element.classList.contains('session-disconnect-btn')) {
                element.style.display = 'none';
            }

            const startTime = Date.now();
            operationTimers.set(sessionId, {
                startTime: startTime,
                element: element,
                interval: null
            });

            // Set up interval to check elapsed time every second
            const timer = operationTimers.get(sessionId);
            timer.interval = setInterval(() => {
                showTimeoutFeedback(element, sessionId, startTime);
            }, 1000);
        });

        // Clear tracking on completion or error
        function clearOperationTimer(sessionId) {
            const timer = operationTimers.get(sessionId);
            if (timer) {
                if (timer.interval) {
                    clearInterval(timer.interval);
                }

                // Only manipulate DOM if element is still connected
                if (timer.element && timer.element.isConnected) {
                    // Clean up feedback message
                    const feedback = timer.element.querySelector('.operation-feedback');
                    if (feedback) {
                        feedback.remove();
                    }
                    // Reset button visibility
                    timer.element.style.display = '';
                }

                operationTimers.delete(sessionId);
            }
        }

        // Clear on successful response
        document.body.addEventListener('htmx:afterRequest', function(evt) {
            const element = evt.detail.elt;
            // Guard: element may have been removed from DOM by outerHTML swap
            if (!element || !element.isConnected) return;

            const sessionId = element.dataset.sessionId ||
                             element.closest('[data-session-id]')?.dataset.sessionId ||
                             element.closest('[id^="session-"]')?.id.replace('session-', '');

            if (sessionId) {
                clearOperationTimer(sessionId);
            }
        });

        // Handle SSE connection errors with debouncing - only show banner after 5s disconnect
        document.body.addEventListener('htmx:sseError', function(evt) {
            // Don't log as error yet — brief disconnects are normal during SSE reconnect
            console.warn('[SSE] Connection interrupted, waiting 5s before alerting...');

            // Clear any existing timer
            if (disconnectTimer) {
                clearTimeout(disconnectTimer);
                disconnectTimer = null;
            }

            // Start 5-second timer before showing banner
            disconnectTimer = setTimeout(function() {
                isDisconnected = true;
                console.error('[SSE] Connection lost (>5s disconnect):', evt.detail);

                // Mark SSE as disconnected (used by polling logic)
                document.body.classList.add('sse-disconnected');

                // Show persistent banner after 5s disconnect
                if (typeof SSEStatusBanner !== 'undefined') {
                    SSEStatusBanner.show();
                }

                // Show warning toast
                if (typeof ToastManager !== 'undefined') {
                    ToastManager.warning(t('sessions_list.messages.connection_lost_realtime_paused'), {
                        duration: 4000
                    });
                }
            }, 5000);
        });

        // Handle reconnection
        document.body.addEventListener('htmx:sseOpen', function(evt) {
            console.log('[SSE] Connection restored');

            // Clear the disconnect timer (reconnect within 5s)
            if (disconnectTimer) {
                clearTimeout(disconnectTimer);
                disconnectTimer = null;
            }

            // Clear SSE disconnected flag
            document.body.classList.remove('sse-disconnected');

            // If we were showing the banner, hide it and show reconnected toast
            if (isDisconnected) {
                isDisconnected = false;

                if (typeof SSEStatusBanner !== 'undefined') {
                    SSEStatusBanner.hide();
                }

                if (typeof ToastManager !== 'undefined') {
                    ToastManager.success(t('sessions_list.messages.reconnected'), {
                        duration: 2000
                    });
                }
            }
        });

        // Toggle config panel visibility when HTMX loads content
        document.body.addEventListener('htmx:afterSettle', function(evt) {
            const target = evt.detail.target;

            // Check if this is a config panel swap (target id starts with session-config-)
            if (target && target.id && target.id.startsWith('session-config-')) {
                const sessionId = target.id.replace('session-config-', '');
                const configRow = document.getElementById('session-config-row-' + sessionId);
                const btn = document.querySelector(`[data-session-id="${sessionId}"].session-config-btn`);

                if (target.innerHTML.trim() && configRow) {
                    configRow.style.display = 'table-row';
                    if (btn) btn.setAttribute('aria-expanded', 'true');
                    console.log('[sessions-list] Config panel shown for:', sessionId);
                }
            }
        });

        // Toggle panel on button click (hide if already shown)
        document.body.addEventListener('click', function(e) {
            const configBtn = e.target.closest('.session-config-btn');
            if (!configBtn) return;

            const sessionId = configBtn.dataset.sessionId;
            const panel = document.getElementById('session-config-' + sessionId);
            const configRow = document.getElementById('session-config-row-' + sessionId);

            if (panel && configRow && configRow.style.display !== 'none' && panel.innerHTML.trim()) {
                // Panel is visible, hide it
                configRow.style.display = 'none';
                panel.innerHTML = '';
                configBtn.setAttribute('aria-expanded', 'false');
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
            // Otherwise let HTMX handle it (fetch and show)
        });

        // Handle HTMX errors for non-modal actions (Connect/Disconnect/Edit)
        document.body.addEventListener('htmx:responseError', function(evt) {
            const status = evt.detail.xhr?.status;
            const action = getActionName(evt.detail.elt);

            if (typeof ToastManager !== 'undefined') {
                let message;
                if (status === 500) {
                    message = `${t('sessions_list.errors.server_error_while')} ${action}. ${t('sessions_list.errors.please_try_again')}`;
                } else if (status === 503) {
                    message = `${t('sessions_list.errors.service_unavailable_while')} ${action}. ${t('sessions_list.errors.please_try_again_later')}`;
                } else if (status >= 400 && status < 500) {
                    message = `${t('sessions_list.errors.request_failed_while')} ${action}. ${t('sessions_list.errors.please_check_and_retry')}`;
                } else {
                    message = `${t('sessions_list.errors.network_error_while')} ${action}. ${t('sessions_list.errors.please_try_again')}`;
                }
                ToastManager.error(message, { duration: 5000 });
            }
        });

        // Handle HTMX timeout errors
        document.body.addEventListener('htmx:timeout', function(evt) {
            const action = getActionName(evt.detail.elt);

            if (typeof ToastManager !== 'undefined') {
                ToastManager.error(
                    `${t('sessions_list.errors.timeout_while')} ${action}. ${t('sessions_list.errors.check_connection_and_retry')}`,
                    { duration: 5000 }
                );
            }
        });

        // Handle general HTMX errors (network failures, etc.)
        document.body.addEventListener('htmx:sendError', function(evt) {
            const action = getActionName(evt.detail.elt);

            if (typeof ToastManager !== 'undefined') {
                ToastManager.error(
                    `${t('sessions_list.errors.connection_failed_while')} ${action}. ${t('sessions_list.errors.check_network_and_retry')}`,
                    { duration: 5000 }
                );
            }
        });

        // Handle successful action completion for Connect/Disconnect/Retry buttons
        document.body.addEventListener('htmx:afterSwap', function(evt) {
            // Only handle session row updates (not config panels or other swaps)
            if (!evt.detail.target.id || !evt.detail.target.id.startsWith('session-')) {
                return;
            }

            const triggerElement = evt.detail.elt;
            // Guard: trigger element may have been removed from DOM by OOB swap
            if (!triggerElement || !triggerElement.isConnected) return;

            // Determine which action succeeded based on button class
            let successMessage = null;

            if (triggerElement.classList.contains('session-connect-btn') ||
                triggerElement.closest('.session-connect-btn')) {
                // Check if it's a retry button by looking at button text or state
                const buttonText = triggerElement.textContent?.trim() || '';
                if (buttonText.toLowerCase().includes('retry') || buttonText.toLowerCase().includes('повтор')) {
                    successMessage = t('sessions_list.messages.retry_initiated');
                } else {
                    successMessage = t('sessions_list.messages.connected_successfully');
                }
            } else if (triggerElement.classList.contains('session-disconnect-btn') ||
                       triggerElement.closest('.session-disconnect-btn')) {
                successMessage = t('sessions_list.messages.disconnected_successfully');
            }

            // Show success toast if action was identified
            if (successMessage && typeof ToastManager !== 'undefined') {
                ToastManager.success(successMessage, { duration: 3000 });
            }
        });

        // Helper: Extract action name from button element
        function getActionName(element) {
            if (!element || !element.isConnected) return t('sessions_list.operations.processing_request');

            if (element.classList.contains('session-connect-btn') ||
                element.closest('.session-connect-btn')) {
                return t('sessions_list.operations.connecting');
            }
            if (element.classList.contains('session-disconnect-btn') ||
                element.closest('.session-disconnect-btn')) {
                return t('sessions_list.operations.disconnecting');
            }
            if (element.classList.contains('session-config-btn') ||
                element.closest('.session-config-btn')) {
                return t('sessions_list.operations.loading_configuration');
            }
            return t('sessions_list.operations.processing_request');
        }

        // Modal button handlers
        document.body.addEventListener('click', function(e) {
            const codeBtn = e.target.closest('.session-code-modal-btn');
            if (codeBtn) {
                const sessionId = codeBtn.dataset.sessionId;
                const authId = codeBtn.dataset.authId;
                const modal = document.getElementById('code-modal');
                if (modal) {
                    modal.classList.add('show');
                    modal.dataset.sessionId = sessionId;
                    modal.dataset.authId = authId;
                    // Clear previous input and result
                    const input = modal.querySelector('#code-modal-input');
                    const result = modal.querySelector('#code-modal-result');
                    if (input) {
                        input.value = "";
                        input.focus();
                    }
                    if (result) result.textContent = '';
                    // Reset button state (in case it was disabled from previous submit)
                    const submitBtn = modal.querySelector('#code-modal-submit');
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = t('sessions_list.auth.verify');
                    }
                }
                return;
            }

            const twoFaBtn = e.target.closest('.session-2fa-modal-btn');
            if (twoFaBtn) {
                const sessionId = twoFaBtn.dataset.sessionId;
                const authId = twoFaBtn.dataset.authId;
                const modal = document.getElementById('twofa-modal');
                if (modal) {
                    modal.classList.add('show');
                    modal.dataset.sessionId = sessionId;
                    modal.dataset.authId = authId;
                    // Clear previous input and result
                    const input = modal.querySelector('#twofa-modal-input');
                    const result = modal.querySelector('#twofa-modal-result');
                    if (input) input.value = '';
                    if (result) result.textContent = '';
                    // Reset button state (in case it was disabled from previous submit)
                    const submitBtn = modal.querySelector('#twofa-modal-submit');
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = t('sessions_list.auth.verify');
                    }
                }
                return;
            }
        });

        // Modal close handlers
        document.body.addEventListener('click', function(e) {
            const cancelBtn = e.target.closest('.modal-button.secondary');
            if (cancelBtn) {
                const modal = cancelBtn.closest('.modal-overlay');
                if (modal) {
                    // Show cancellation feedback before closing
                    const isCodeModal = modal.id === 'code-modal';
                    const isTwoFaModal = modal.id === 'twofa-modal';

                    if (isCodeModal || isTwoFaModal) {
                        const resultDiv = modal.querySelector('.modal-result');
                        if (resultDiv) {
                            resultDiv.textContent = t('sessions_list.auth.cancelled');
                            resultDiv.className = 'modal-result info';

                            // Close modal after brief delay to show message
                            setTimeout(() => {
                                modal.classList.remove('show');
                                // Clear message for next time
                                setTimeout(() => {
                                    resultDiv.textContent = '';
                                    resultDiv.className = 'modal-result';
                                }, 300); // After modal close animation
                            }, 1500);
                        } else {
                            // Fallback: close immediately if no result div found
                            modal.classList.remove('show');
                        }
                    } else {
                        // For other modals, close immediately
                        modal.classList.remove('show');
                    }
                }
            }
        });

        // Code modal submit handler
        let codeModalProcessing = false;
        document.body.addEventListener('click', async function(e) {
            const submitBtn = e.target.closest('#code-modal-submit');
            if (!submitBtn) return;

            // Prevent double-submit: check if already processing
            if (codeModalProcessing || submitBtn.disabled) {
                return;
            }

            // Set flag and disable button immediately to block rapid clicks
            codeModalProcessing = true;
            submitBtn.disabled = true;
            submitBtn.textContent = t('sessions_list.auth.verifying');

            const modal = document.getElementById('code-modal');
            const sessionId = modal.dataset.sessionId;
            const authId = modal.dataset.authId;
            const input = modal.querySelector('#code-modal-input');
            const result = modal.querySelector('#code-modal-result');
            const code = input.value.trim();

            // Validate inputs
            if (!authId) {
                result.textContent = t('sessions_list.auth.auth_id_not_found');
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                codeModalProcessing = false;
                return;
            }

            if (!code) {
                result.textContent = t('sessions_list.auth.enter_verification_code');
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                codeModalProcessing = false;
                return;
            }

            // Clear result text after validation passes
            result.textContent = '';

            try {
                // Send POST request with 10s timeout
                const formData = new FormData();
                formData.append('auth_id', authId);
                formData.append('code', code);

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);

                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                const response = await fetch(`/api/sessions/${sessionId}/verify-code`, {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-CSRF-Token': csrfToken },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                const html = await response.text();

                if (response.ok) {
                    // Determine response type: <tr> (needs_2fa) or <div> (full success)
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const firstElement = doc.body.firstElementChild;

                    if (firstElement && firstElement.tagName === 'TR') {
                        // Response is a table row (needs_2fa case)
                        // Replace the session row and close modal
                        const sessionRow = document.getElementById(`session-${sessionId}`);
                        if (sessionRow) {
                            sessionRow.outerHTML = html;
                        }
                        modal.classList.remove('show');
                        // Show info toast: code accepted but needs 2FA
                        if (typeof ToastManager !== 'undefined') {
                            ToastManager.info(t('sessions_list.auth.code_verified_enter_2fa'), {
                                duration: 4000
                            });
                        }
                    } else {
                        // Response is success notification (full success case)
                        // Insert the success div (contains script that triggers refresh)
                        modal.classList.remove('show');
                        const modalContainer = modal.parentElement;
                        if (modalContainer) {
                            // Insert success notification after modal
                            const tempDiv = document.createElement('div');
                            tempDiv.innerHTML = html;
                            modalContainer.appendChild(tempDiv.firstChild);
                        }
                        // Don't show additional toast - success template handles it
                    }
                    // Note: button stays disabled, modal closes
                    codeModalProcessing = false;
                } else {
                    // Error - show in modal and re-enable button for retry
                    result.innerHTML = html;
                    result.className = 'modal-result error';
                    submitBtn.disabled = false;
                    submitBtn.textContent = t('sessions_list.auth.verify');
                    codeModalProcessing = false;
                }
            } catch (error) {
                // Network error or timeout - re-enable button for retry
                const errorMsg = error.name === 'AbortError'
                    ? t('sessions_list.auth.request_timeout')
                    : `Error: ${error.message}`;
                result.textContent = errorMsg;
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                codeModalProcessing = false;
            }
        });

        // 2FA modal submit handler
        let twofaModalProcessing = false;
        document.body.addEventListener('click', async function(e) {
            const submitBtn = e.target.closest('#twofa-modal-submit');
            if (!submitBtn) return;

            // Prevent double-submit: check if already processing
            if (twofaModalProcessing || submitBtn.disabled) {
                return;
            }

            // Set flag and disable button immediately to block rapid clicks
            twofaModalProcessing = true;
            submitBtn.disabled = true;
            submitBtn.textContent = t('sessions_list.auth.verifying');

            const modal = document.getElementById('twofa-modal');
            const sessionId = modal.dataset.sessionId;
            const authId = modal.dataset.authId;
            const input = modal.querySelector('#twofa-modal-input');
            const result = modal.querySelector('#twofa-modal-result');
            const password = input.value;

            // Validate inputs
            if (!authId) {
                result.textContent = t('sessions_list.auth.auth_id_not_found');
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                twofaModalProcessing = false;
                return;
            }

            if (!password) {
                result.textContent = t('sessions_list.auth.enter_2fa_password');
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                twofaModalProcessing = false;
                return;
            }

            // Clear result text after validation passes
            result.textContent = '';

            try {
                // Send POST request with 10s timeout
                const formData = new FormData();
                formData.append('auth_id', authId);
                formData.append('password', password);

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);

                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                const response = await fetch(`/api/sessions/${sessionId}/verify-2fa`, {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-CSRF-Token': csrfToken },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                const html = await response.text();

                if (response.ok) {
                    // Success - update the session row and close modal
                    const sessionRow = document.getElementById(`session-${sessionId}`);
                    if (sessionRow) {
                        sessionRow.outerHTML = html;
                    }
                    modal.classList.remove('show');
                    // Show success toast notification
                    if (typeof ToastManager !== 'undefined') {
                        ToastManager.success(t('sessions_list.auth.twofa_accepted'), {
                            duration: 4000
                        });
                    }
                    // Note: button stays disabled, modal closes
                    twofaModalProcessing = false;
                } else {
                    // Error - show in modal and re-enable button for retry
                    result.innerHTML = html;
                    result.className = 'modal-result error';
                    submitBtn.disabled = false;
                    submitBtn.textContent = t('sessions_list.auth.verify');
                    twofaModalProcessing = false;
                }
            } catch (error) {
                // Network error or timeout - re-enable button for retry
                const errorMsg = error.name === 'AbortError'
                    ? t('sessions_list.auth.request_timeout')
                    : `Error: ${error.message}`;
                result.textContent = errorMsg;
                result.className = 'modal-result error';
                submitBtn.disabled = false;
                submitBtn.textContent = t('sessions_list.auth.verify');
                twofaModalProcessing = false;
            }
        });

        // Show toast notification when session transitions to needs_code
        // User must explicitly click "Enter Verification Code" button to open modal
        const needsCodeTracker = new Set(); // Track which sessions we've already shown feedback for

        const sessionObserver = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList' || mutation.type === 'attributes') {
                    // Check all session rows for needs_code state
                    const sessionRows = document.querySelectorAll('[id^="session-"]');
                    sessionRows.forEach(function(row) {
                        const sessionId = row.id.replace('session-', '');
                        const statusElement = row.querySelector('.account-status');

                        if (!statusElement) return;

                        // Check if session is in needs_code state
                        const isNeedsCode = statusElement.classList.contains('status-needs_code');

                        if (isNeedsCode && !needsCodeTracker.has(sessionId)) {
                            // First time seeing this session in needs_code state
                            needsCodeTracker.add(sessionId);

                            // Show explanatory toast (only for dynamic transitions, not initial page load)
                            if (mutation.type !== 'childList' || mutation.addedNodes.length === 0) {
                                if (typeof ToastManager !== 'undefined') {
                                    ToastManager.info(t('sessions_list.messages.requires_verification'), {
                                        duration: 5000
                                    });
                                }
                            }

                            // User must explicitly click "Enter Verification Code" button
                            // Modal no longer auto-opens to avoid blocking the page on load
                        }

                        // Clean up tracker if session leaves needs_code state
                        if (!isNeedsCode && needsCodeTracker.has(sessionId)) {
                            needsCodeTracker.delete(sessionId);
                        }
                    });
                }
            });
        });

        // Observe the sessions table for changes
        const sessionsTable = document.querySelector('.accounts-table-container');
        if (sessionsTable) {
            sessionObserver.observe(sessionsTable, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['class']
            });
        }
    }
})();
