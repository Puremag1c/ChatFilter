// Chats page: SSE error/reconnect handling + vanilla JS polling
// Extracted from chats.html inline scripts
(function() {
    'use strict';

    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    // --- SSE connection error handling with 5s debounce ---
    var disconnectTimer = null;
    var isDisconnected = false;
    var sseHasConnected = false;
    var connectionCheckTimer = null;
    const SSE_CONNECTION_TIMEOUT = 10000; // 10 seconds

    // Start 10-second SSE connection check
    console.log('[SSE] Starting connection check (10s timeout)');
    connectionCheckTimer = setTimeout(function() {
        if (!sseHasConnected) {
            console.error('[SSE] Connection failed - no connection within 10s');
            document.body.classList.add('sse-disconnected');

            if (typeof SSEStatusBanner !== 'undefined') {
                SSEStatusBanner.show();
            }

            if (typeof ToastManager !== 'undefined') {
                ToastManager.warning(t('sessions.messages.connection_lost_realtime_paused'), {
                    duration: 4000
                });
            }
        }
    }, SSE_CONNECTION_TIMEOUT);

    document.body.addEventListener('htmx:sseError', function(evt) {
        console.warn('[SSE] Connection interrupted, waiting 5s before alerting...');

        if (disconnectTimer) {
            clearTimeout(disconnectTimer);
            disconnectTimer = null;
        }

        disconnectTimer = setTimeout(function() {
            isDisconnected = true;
            console.error('[SSE] Connection lost (>5s disconnect):', evt.detail);

            document.body.classList.add('sse-disconnected');

            if (typeof SSEStatusBanner !== 'undefined') {
                SSEStatusBanner.show();
            }

            if (typeof ToastManager !== 'undefined') {
                ToastManager.warning(t('sessions.messages.connection_lost_realtime_paused'), {
                    duration: 4000
                });
            }
        }, 5000);
    });

    document.body.addEventListener('htmx:sseOpen', function() {
        console.log('[SSE] Connection established - first event received');

        // Mark SSE as connected for early failure detection
        if (!sseHasConnected) {
            sseHasConnected = true;
            if (connectionCheckTimer) {
                clearTimeout(connectionCheckTimer);
                connectionCheckTimer = null;
            }
            console.log('[SSE] Connection verified (within timeout)');
        }

        if (disconnectTimer) {
            clearTimeout(disconnectTimer);
            disconnectTimer = null;
        }

        document.body.classList.remove('sse-disconnected');

        if (isDisconnected) {
            isDisconnected = false;

            if (typeof SSEStatusBanner !== 'undefined') {
                SSEStatusBanner.hide();
            }

            if (typeof ToastManager !== 'undefined') {
                ToastManager.success(t('chats.reconnected'), {
                    duration: 2000
                });
            }
        }
    });

    // --- Vanilla JS polling ---
    var container = document.getElementById('groups-container');
    var pollTimer = null;
    var isRefreshing = false;

    function refreshGroups() {
        if (isRefreshing) return;
        isRefreshing = true;

        var currentInProgress = new Set();
        container.querySelectorAll('.group-card').forEach(function(card) {
            var statusBadge = card.querySelector('.status-badge.in_progress') || card.querySelector('.status-badge.waiting_for_accounts');
            if (statusBadge && card.id) {
                currentInProgress.add(card.id);
            }
        });

        fetch('/api/groups')
            .then(function(resp) { return resp.text(); })
            .then(function(html) {
                var tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;

                morphdom(container, tempDiv, {
                    childrenOnly: true,
                    onBeforeElUpdated: function(fromEl) {
                        // Skip updating group cards with active SSE (in_progress/waiting_for_accounts)
                        // to prevent DOM jitter and timer resets
                        if (fromEl.classList && fromEl.classList.contains('group-card')) {
                            var statusBadge = fromEl.querySelector('.status-badge.in_progress, .status-badge.waiting_for_accounts, .status-badge.scraping');
                            if (statusBadge) {
                                // Active card — skip update to prevent jitter
                                return false;
                            }
                        }
                        return true;
                    }
                });

                htmx.process(container);

                container.querySelectorAll('.group-card').forEach(function(card) {
                    var completedBadge = card.querySelector('.status-badge.completed');
                    var pausedBadge = card.querySelector('.status-badge.paused');

                    if ((completedBadge || pausedBadge) && card.id && currentInProgress.has(card.id)) {
                        ToastManager.success(t('analysis.complete'));
                    }
                });

                schedulePoll();
            })
            .catch(function() { schedulePoll(); })
            .finally(function() { isRefreshing = false; });
    }

    function schedulePoll() {
        if (pollTimer) clearTimeout(pollTimer);

        var hasActive = container.querySelector('.status-badge.in_progress') || container.querySelector('.status-badge.waiting_for_accounts') || container.querySelector('.status-badge.scraping');
        var isSseConnected = !(document.body.classList && document.body.classList.contains('sse-disconnected'));

        var pollInterval;
        if (hasActive) {
            if (isSseConnected) {
                pollInterval = 60000;
            } else {
                pollInterval = 30000;
            }
        } else {
            pollInterval = 10000;
        }

        pollTimer = setTimeout(refreshGroups, pollInterval);
    }

    document.body.addEventListener('refreshGroups', function() {
        refreshGroups();
    });

    var SPINNER_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="animation: spin 1s linear infinite;">' +
        '<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" stroke-opacity="0.25"/>' +
        '<path d="M12 2 A10 10 0 0 1 22 12" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>' +
        '</svg>';

    function addSpinner(btn, label) {
        btn.dataset.originalHtml = btn.innerHTML;
        btn.innerHTML = '<span style="display: inline-flex; align-items: center; gap: 0.5rem;">' +
            SPINNER_SVG + '<span></span></span>';
        btn.querySelector('span > span:last-child').textContent = label;
    }

    function restoreButton(btn) {
        if (btn.dataset && btn.dataset.originalHtml !== undefined) {
            btn.innerHTML = btn.dataset.originalHtml;
            delete btn.dataset.originalHtml;
        }
    }

    // Button loading states
    document.body.addEventListener('htmx:beforeRequest', function(event) {
        var target = event.detail.elt;
        if (!target || target.tagName !== 'BUTTON') return;

        var path = event.detail.requestConfig && event.detail.requestConfig.path;
        if (!path) return;

        if (path.match(/\/api\/groups\/[^\/]+\/resume$/)) {
            addSpinner(target, t('chats.resuming'));
            var card = target.closest('.group-card');
            if (card) card.classList.add('card-loading');
        } else if (path.match(/\/api\/groups\/[^\/]+\/start$/)) {
            addSpinner(target, target.textContent.trim());
            var card = target.closest('.group-card');
            if (card) card.classList.add('card-loading');
        } else if (path.match(/\/api\/groups\/[^\/]+\/reanalyze/)) {
            addSpinner(target, target.textContent.trim());
            var card = target.closest('.group-card');
            if (card) card.classList.add('card-loading');
        } else if (path.match(/\/api\/groups\/[^\/]+\/stop$/)) {
            addSpinner(target, target.textContent.trim());
        } else if (path.match(/\/api\/groups\/[^\/]+$/) && event.detail.requestConfig.verb === 'delete') {
            addSpinner(target, target.textContent.trim());
        }
    });

    // Clear loading state after card swap
    document.body.addEventListener('htmx:afterSwap', function(event) {
        if (event.detail.target && event.detail.target.id &&
            event.detail.target.id.match(/^group-/)) {
            // Card was swapped — loading state gone with old card
        }
    });

    // Toast on analysis start; restore button and clear overlay on error
    document.body.addEventListener('htmx:afterRequest', function(event) {
        var xhr = event.detail.xhr;
        var requestConfig = event.detail.requestConfig;
        var target = event.detail.elt;

        if (xhr.status === 204 && requestConfig && requestConfig.path &&
            requestConfig.path.match(/\/api\/groups\/[^\/]+\/(start|reanalyze)(\?|$)/)) {
            ToastManager.info(t('analysis.started'));
        }

        // Restore button and remove loading overlay on error (4xx/5xx)
        if (!event.detail.successful && target) {
            if (target.dataset && target.dataset.originalHtml !== undefined) {
                restoreButton(target);
            }
            var card = target.closest ? target.closest('.group-card') : null;
            if (card) card.classList.remove('card-loading');
            if (typeof ToastManager !== 'undefined') {
                ToastManager.warning(t('chats.request_failed'));
            }
        }
    });

    // Initial load
    refreshGroups();
})();
