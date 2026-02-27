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
        console.log('[SSE] Connection restored');

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

    function executeScripts(el) {
        var scripts = el.querySelectorAll('script');
        scripts.forEach(function(oldScript) {
            var newScript = document.createElement('script');
            Array.from(oldScript.attributes).forEach(function(attr) {
                newScript.setAttribute(attr.name, attr.value);
            });
            newScript.textContent = oldScript.textContent;
            oldScript.parentNode.replaceChild(newScript, oldScript);
        });
    }

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
                            var statusBadge = fromEl.querySelector('.status-badge.in_progress, .status-badge.waiting_for_accounts');
                            if (statusBadge) {
                                // Active card — skip update to prevent jitter
                                return false;
                            }
                        }
                        return true;
                    }
                });

                htmx.process(container);
                executeScripts(container);

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

        var hasActive = container.querySelector('.status-badge.in_progress') || container.querySelector('.status-badge.waiting_for_accounts');
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

    // Resume button loading state
    document.body.addEventListener('htmx:beforeRequest', function(event) {
        var target = event.detail.elt;

        if (target && target.tagName === 'BUTTON' &&
            event.detail.requestConfig &&
            event.detail.requestConfig.path &&
            event.detail.requestConfig.path.match(/\/api\/groups\/[^\/]+\/resume$/)) {

            var card = target.closest('.group-card');
            if (!card) return;

            target.setAttribute('data-original-text', target.textContent);

            target.innerHTML = '<span style="display: inline-flex; align-items: center; gap: 0.5rem;">' +
                '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="animation: spin 1s linear infinite;">' +
                '<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" stroke-opacity="0.25"/>' +
                '<path d="M12 2 A10 10 0 0 1 22 12" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>' +
                '</svg>' +
                '<span>' + t('chats.resuming') + '</span>' +
                '</span>';
        }
    });

    // Clear loading state after card swap
    document.body.addEventListener('htmx:afterSwap', function(event) {
        if (event.detail.target && event.detail.target.id &&
            event.detail.target.id.match(/^group-/)) {
            // Card was swapped — loading state gone with old card
        }
    });

    // Toast on analysis start
    document.body.addEventListener('htmx:afterRequest', function(event) {
        var xhr = event.detail.xhr;
        var requestConfig = event.detail.requestConfig;

        if (xhr.status === 204 && requestConfig && requestConfig.path &&
            requestConfig.path.match(/\/api\/groups\/[^\/]+\/(start|reanalyze)(\?|$)/)) {
            ToastManager.info(t('analysis.started'));
        }
    });

    // Initial load
    refreshGroups();
})();
