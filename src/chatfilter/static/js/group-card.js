/**
 * Group Card SSE Handler
 * Handles SSE events for in_progress/waiting_for_accounts group cards
 * - Progress updates, elapsed timer, FloodWait countdown
 * - Stale connection detection, error handling
 */

(function() {
    'use strict';

    const STALE_THRESHOLD_MS = 60 * 1000; // 60 seconds
    const STALE_CHECK_INTERVAL_MS = 5000; // 5 seconds

    /**
     * Initialize a single group card
     * @param {HTMLElement} cardEl - The group card element
     */
    function initGroupCard(cardEl) {
        const groupId = cardEl.dataset.groupId;
        const groupStatus = cardEl.dataset.groupStatus;

        // Validation: only init for in_progress/waiting_for_accounts
        if (!groupStatus || (groupStatus !== 'in_progress' && groupStatus !== 'waiting_for_accounts')) {
            return; // Not an active card
        }

        // Validation: ensure groupId exists
        if (!groupId) {
            console.warn('group-card.js: Missing data-group-id on card element', cardEl);
            return;
        }

        // AbortController for cleanup - abort() removes ALL listeners with this signal
        const abortController = new AbortController();
        const signal = abortController.signal;

        // DO NOT cache DOM references - look them up fresh on each event
        // This prevents stale references when refreshGroups() swaps innerHTML
        function getElements() {
            return {
                processedEl: document.getElementById('processed-' + groupId),
                errorEl: document.getElementById('error-' + groupId),
                currentChatEl: document.getElementById('current-chat-' + groupId),
                elapsedEl: document.getElementById('elapsed-' + groupId),
                progressFillEl: document.getElementById('progress-fill-' + groupId),
                errorWarningEl: document.getElementById('error-warning-' + groupId),
                errorMessageEl: document.getElementById('error-message-' + groupId),
                staleWarningEl: document.getElementById('stale-warning-' + groupId),
                floodWaitEl: document.getElementById('flood-wait-' + groupId),
                floodWaitTimeEl: document.getElementById('flood-wait-time-' + groupId),
                floodWaitCountdownEl: document.getElementById('flood-wait-countdown-' + groupId),
                statusBadgeEl: document.querySelector('#group-' + groupId + ' .status-badge'),
                cardEl: document.getElementById('group-' + groupId)
            };
        }

        // Parse started_at from data-attr (ISO 8601 format)
        let startTime = Date.now(); // Default fallback
        const startedAtStr = cardEl.dataset.startedAt;
        if (startedAtStr) {
            const parsedDate = new Date(startedAtStr);
            if (!isNaN(parsedDate.getTime())) {
                startTime = parsedDate.getTime();
            } else {
                console.warn('group-card.js: Invalid data-started-at:', startedAtStr);
            }
        }

        let elapsedTimer = null;
        let staleCheckTimer = null;
        let floodWaitTimer = null;
        let floodWaitTarget = null; // Date object for flood_wait_until
        let lastEventTime = Date.now();
        let sseConnected = false; // Track if SSE connection has been established

        // Parse flood_wait_until from data-attr if present
        const floodWaitUntilStr = cardEl.dataset.floodWaitUntil;
        if (floodWaitUntilStr) {
            const parsedDate = new Date(floodWaitUntilStr);
            if (!isNaN(parsedDate.getTime())) {
                floodWaitTarget = parsedDate;
            } else {
                console.warn('group-card.js: Invalid data-flood-wait-until:', floodWaitUntilStr);
            }
        }

        // Format elapsed time as M:SS
        function formatElapsed(seconds) {
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            return mins + ':' + (secs < 10 ? '0' : '') + secs;
        }

        // Format time as HH:MM
        function formatTime(date) {
            const h = date.getHours();
            const m = date.getMinutes();
            return (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m;
        }

        // Update elapsed time every second
        function startElapsedTimer() {
            if (elapsedTimer) return; // Already running
            elapsedTimer = setInterval(function() {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                const els = getElements();
                if (els.elapsedEl) {
                    els.elapsedEl.textContent = formatElapsed(elapsed);
                }
            }, 1000);
        }

        function stopElapsedTimer() {
            if (elapsedTimer) {
                clearInterval(elapsedTimer);
                elapsedTimer = null;
            }
        }

        // FloodWait countdown timer
        function startFloodWaitCountdown(untilDate) {
            floodWaitTarget = untilDate;
            stopFloodWaitCountdown();

            const els = getElements();
            if (els.floodWaitTimeEl) {
                els.floodWaitTimeEl.textContent = formatTime(untilDate);
            }
            if (els.floodWaitEl) {
                els.floodWaitEl.style.display = 'block';
            }

            floodWaitTimer = setInterval(function() {
                const remaining = Math.max(0, Math.floor((floodWaitTarget.getTime() - Date.now()) / 1000));
                const els = getElements();
                if (els.floodWaitCountdownEl) {
                    if (remaining > 0) {
                        els.floodWaitCountdownEl.textContent = formatElapsed(remaining);
                    } else {
                        els.floodWaitCountdownEl.textContent = 'скоро...';
                        stopFloodWaitCountdown();
                    }
                }
            }, 1000);
        }

        function stopFloodWaitCountdown() {
            if (floodWaitTimer) {
                clearInterval(floodWaitTimer);
                floodWaitTimer = null;
            }
        }

        function hideFloodWait() {
            stopFloodWaitCountdown();
            floodWaitTarget = null;
            const els = getElements();
            if (els.floodWaitEl) {
                els.floodWaitEl.style.display = 'none';
            }
        }

        // Update status badge dynamically
        function updateStatusBadge(status) {
            const els = getElements();
            if (!els.statusBadgeEl) return;
            // Remove old status classes
            els.statusBadgeEl.className = 'status-badge ' + status;
            if (status === 'waiting_for_accounts') {
                els.statusBadgeEl.textContent = 'Ожидание аккаунтов';
            } else if (status === 'in_progress') {
                els.statusBadgeEl.textContent = 'In progress';
            }
        }

        // Check for stale SSE connection (no events for >60s)
        function checkStaleConnection() {
            const timeSinceLastEvent = Date.now() - lastEventTime;
            if (timeSinceLastEvent > STALE_THRESHOLD_MS) {
                // Show stale warning
                const els = getElements();
                if (els.staleWarningEl) {
                    els.staleWarningEl.style.display = 'block';
                }
            }
        }

        // Start stale check timer (runs every 5s)
        function startStaleCheckTimer() {
            if (staleCheckTimer) return; // Already running
            staleCheckTimer = setInterval(checkStaleConnection, STALE_CHECK_INTERVAL_MS);
        }

        function stopStaleCheckTimer() {
            if (staleCheckTimer) {
                clearInterval(staleCheckTimer);
                staleCheckTimer = null;
            }
        }

        // Record SSE event received (dismisses stale warning)
        function recordSseEvent() {
            lastEventTime = Date.now();

            // Start stale check on first SSE event (prevents false positives before connection)
            if (!sseConnected) {
                sseConnected = true;
                startStaleCheckTimer();
            }

            // Hide stale warning if visible
            const els = getElements();
            if (els.staleWarningEl) {
                els.staleWarningEl.style.display = 'none';
            }
        }

        // Named SSE handler function for proper cleanup
        // Use named function so we can remove it later with removeEventListener
        function handleSseMessage(event) {
            if (!event || !event.detail) return;

            // The SSE extension passes the raw event in event.detail
            const sseEvent = event.detail;

            // Record ANY SSE event (including ping) to track liveness
            recordSseEvent();

            // Handle ping (heartbeat) events - no data processing needed
            if (sseEvent.type === 'ping') {
                return; // Just update lastEventTime, no UI update
            }

            try {
                // Parse the data from the SSE event
                const data = JSON.parse(sseEvent.data);

                // Guard: only process events for this group
                if (data.group_id !== groupId) return;

                // Lookup fresh DOM elements on each event (prevents stale references)
                const els = getElements();

                // Handle init event (sent on SSE connection open)
                if (sseEvent.type === 'init') {
                    // Update startTime from server's started_at
                    if (data.started_at) {
                        startTime = new Date(data.started_at).getTime();
                    } else {
                        // Fallback to current time if no started_at
                        startTime = Date.now();
                    }

                    // Update initial progress from DB
                    if (data.processed !== undefined && data.total !== undefined) {
                        const percent = data.total > 0 ? Math.round((data.processed / data.total) * 100) : 0;

                        if (els.processedEl) {
                            els.processedEl.textContent = data.processed + ' / ' + data.total;
                        }
                        if (els.progressFillEl) {
                            els.progressFillEl.style.width = percent + '%';
                        }
                    }

                    // Handle flood_wait_until in init event
                    if (data.status === 'waiting_for_accounts' && data.flood_wait_until) {
                        updateStatusBadge('waiting_for_accounts');
                        startFloodWaitCountdown(new Date(data.flood_wait_until));
                    }
                    return;
                }

                // Handle progress event
                if (sseEvent.type === 'progress' || !sseEvent.type) {
                    // Update progress from global DB-based counts
                    if (data.processed !== undefined && data.total !== undefined) {
                        const percent = data.total > 0 ? Math.round((data.processed / data.total) * 100) : 0;

                        if (els.processedEl) {
                            els.processedEl.textContent = data.processed + ' / ' + data.total;
                        }
                        if (els.progressFillEl) {
                            els.progressFillEl.style.width = percent + '%';
                        }
                    }

                    // Handle status transitions
                    if (data.status === 'waiting_for_accounts') {
                        updateStatusBadge('waiting_for_accounts');
                        if (data.flood_wait_until) {
                            startFloodWaitCountdown(new Date(data.flood_wait_until));
                        }
                    } else if (data.status === 'in_progress') {
                        // Transitioned back from waiting → in_progress
                        updateStatusBadge('in_progress');
                        hideFloodWait();
                    }

                    // Update status badges from breakdown
                    if (data.breakdown) {
                        const badgeTypes = ['pending', 'done', 'error', 'dead'];
                        badgeTypes.forEach(badgeType => {
                            const badgeEl = document.getElementById('badge-' + badgeType + '-' + groupId);
                            if (badgeEl) {
                                const count = data.breakdown[badgeType] || 0;
                                const countEl = badgeEl.querySelector('[data-badge-count]');
                                if (countEl) {
                                    countEl.textContent = count;
                                }
                                // Show/hide badge based on count
                                badgeEl.style.display = count > 0 ? 'inline' : 'none';
                            }
                        });

                        // Update error count in stats section
                        if (els.errorEl && data.breakdown.error !== undefined) {
                            els.errorEl.textContent = data.breakdown.error;
                        }
                    }

                    // Update current chat (check for presence, not truthiness — "" is valid)
                    if ('chat_title' in data && els.currentChatEl) {
                        els.currentChatEl.textContent = data.chat_title || '—';
                        els.currentChatEl.title = data.chat_title || '';
                    }
                }

                // Handle error event
                if (sseEvent.type === 'error') {
                    stopElapsedTimer();
                    stopStaleCheckTimer();
                    hideFloodWait();

                    // Hide current chat on error
                    if (els.currentChatEl) {
                        els.currentChatEl.textContent = '—';
                        els.currentChatEl.title = '';
                    }

                    // Update status badge to show error
                    if (els.statusBadgeEl) {
                        els.statusBadgeEl.className = 'status-badge failed';
                        els.statusBadgeEl.textContent = 'Error';
                    }

                    // Show error message if provided
                    if (data.error && els.errorWarningEl && els.errorMessageEl) {
                        els.errorMessageEl.textContent = data.error;
                        els.errorWarningEl.style.display = 'block';
                    }

                    // DO NOT trigger refreshGroups - keep card for debugging
                    // User can see error state and manually refresh if needed
                }

                // Handle complete event
                if (sseEvent.type === 'complete') {
                    stopElapsedTimer();
                    stopStaleCheckTimer();
                    hideFloodWait();

                    // Hide current chat on completion
                    if (els.currentChatEl) {
                        els.currentChatEl.textContent = '—';
                        els.currentChatEl.title = '';
                    }

                    // Trigger group refresh to show completed state
                    document.body.dispatchEvent(new CustomEvent('refreshGroups'));
                }
            } catch (e) {
                console.error('Failed to parse SSE event:', e);
            }
        }

        // Listen for htmx:sseMessage events (fired by HTMX SSE extension)
        // SSE connection is now on page-level container, listen globally
        // Use signal for automatic cleanup when abortController.abort() is called
        document.body.addEventListener('htmx:sseMessage', handleSseMessage, {signal});

        // Start elapsed timer when card initializes
        startElapsedTimer();
        // NOTE: stale check timer starts on first SSE event (see recordSseEvent)

        // Start FloodWait countdown if floodWaitTarget was parsed from data-attr
        if (floodWaitTarget && groupStatus === 'waiting_for_accounts') {
            startFloodWaitCountdown(floodWaitTarget);
        }

        // Cleanup on card removal (HTMX swap or DOM removal)
        // Use htmx:beforeSwap as primary cleanup - fires reliably before HTMX swaps
        function cleanupOnSwap(event) {
            // Check if the swap target is our container or parent
            if (event.detail.target && (
                event.detail.target.id === 'groups-container' ||
                event.detail.target.id === 'groups-list'
            )) {
                stopElapsedTimer();
                stopStaleCheckTimer();
                stopFloodWaitCountdown();
                // CRITICAL: Abort signal removes ALL listeners registered with this signal
                // This includes the SSE listener AND this cleanup listener
                abortController.abort();
            }
        }
        document.body.addEventListener('htmx:beforeSwap', cleanupOnSwap, {signal});

        // Fallback: MutationObserver for non-HTMX removal
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                mutation.removedNodes.forEach(function(node) {
                    const els = getElements();
                    if (node === els.cardEl || (node.contains && els.cardEl && node.contains(els.cardEl))) {
                        stopElapsedTimer();
                        stopStaleCheckTimer();
                        stopFloodWaitCountdown();
                        // CRITICAL: Abort signal removes ALL listeners registered with this signal
                        abortController.abort();
                        observer.disconnect();
                    }
                });
            });
        });

        const initialEls = getElements();
        if (initialEls.cardEl && initialEls.cardEl.parentNode) {
            observer.observe(initialEls.cardEl.parentNode, { childList: true });
        }
    }

    /**
     * Initialize all group cards on the page
     */
    function initAllGroupCards() {
        const cards = document.querySelectorAll('[data-group-id]');
        cards.forEach(function(card) {
            initGroupCard(card);
        });
    }

    // Initialize on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAllGroupCards);
    } else {
        initAllGroupCards();
    }

    // Re-initialize after HTMX swaps (for dynamically added cards)
    document.body.addEventListener('htmx:afterSwap', function(event) {
        // Only re-init if the swap target contains group cards
        if (event.detail.target) {
            const newCards = event.detail.target.querySelectorAll('[data-group-id]');
            newCards.forEach(function(card) {
                initGroupCard(card);
            });
        }
    });
})();
