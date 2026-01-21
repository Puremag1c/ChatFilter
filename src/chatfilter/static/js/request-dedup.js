/**
 * Request Deduplication Manager
 * Prevents duplicate API requests across multiple browser tabs
 * Integrates with HTMX and TabSync for cross-tab coordination
 */

const RequestDedup = (function() {
    'use strict';

    // In-flight requests tracked by unique key
    const inFlightRequests = new Map();

    // Request timeout (consider request failed after this time)
    const REQUEST_TIMEOUT = 30000; // 30 seconds

    // Cleanup interval for stale requests
    const CLEANUP_INTERVAL = 60000; // 1 minute

    /**
     * Generate unique key for a request
     * @param {string} method - HTTP method (GET, POST, etc.)
     * @param {string} url - Request URL
     * @param {object} params - Request parameters/body
     * @returns {string} Unique request key
     */
    function getRequestKey(method, url, params = null) {
        const paramsStr = params ? JSON.stringify(params) : '';
        return `${method}:${url}:${paramsStr}`;
    }

    /**
     * Check if request is currently in flight (this tab or others)
     * @param {string} key - Request key
     * @returns {boolean}
     */
    function isRequestInFlight(key) {
        const request = inFlightRequests.get(key);
        if (!request) return false;

        // Check if request has timed out
        const now = Date.now();
        if (now - request.startTime > REQUEST_TIMEOUT) {
            inFlightRequests.delete(key);
            return false;
        }

        return true;
    }

    /**
     * Mark request as started
     * @param {string} key - Request key
     * @param {string} tabId - ID of tab making the request
     */
    function markRequestStarted(key, tabId) {
        const requestInfo = {
            key,
            tabId,
            startTime: Date.now()
        };

        inFlightRequests.set(key, requestInfo);

        // Broadcast to other tabs
        if (typeof TabSync !== 'undefined') {
            TabSync.broadcast('request_started', requestInfo);
        }
    }

    /**
     * Mark request as completed
     * @param {string} key - Request key
     * @param {boolean} success - Whether request succeeded
     * @param {any} result - Request result (optional)
     */
    function markRequestCompleted(key, success = true, result = null) {
        inFlightRequests.delete(key);

        // Broadcast completion to other tabs
        if (typeof TabSync !== 'undefined') {
            TabSync.broadcast('request_completed', {
                key,
                success,
                result,
                timestamp: Date.now()
            });
        }
    }

    /**
     * Get unique tab ID for this tab
     * @returns {string}
     */
    function getTabId() {
        if (!window.chatfilter_tab_id) {
            window.chatfilter_tab_id = 'tab_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
        }
        return window.chatfilter_tab_id;
    }

    /**
     * Initialize HTMX integration
     */
    function initHtmxIntegration() {
        if (typeof htmx === 'undefined') {
            console.warn('HTMX not found, request deduplication disabled');
            return;
        }

        // Before sending request, check if duplicate
        document.body.addEventListener('htmx:beforeRequest', function(event) {
            const xhr = event.detail.xhr;
            const method = xhr._method || 'GET';
            const url = xhr._url || event.detail.pathInfo.requestPath;

            // Generate request key
            const key = getRequestKey(method, url, xhr._body);

            // Check if request is already in flight
            if (isRequestInFlight(key)) {
                const request = inFlightRequests.get(key);

                // If another tab is making the request, cancel this one
                if (request && request.tabId !== getTabId()) {
                    console.log(`Request deduplicated (in flight in another tab): ${key}`);
                    event.preventDefault();

                    // Show toast notification
                    if (typeof ToastManager !== 'undefined') {
                        ToastManager.info('Request is already being processed in another tab', {
                            duration: 3000
                        });
                    }
                    return;
                }

                // If this tab is making duplicate request, also cancel
                if (request && request.tabId === getTabId()) {
                    console.log(`Request deduplicated (already in flight): ${key}`);
                    event.preventDefault();

                    if (typeof ToastManager !== 'undefined') {
                        ToastManager.warning('Please wait for the previous request to complete', {
                            duration: 3000
                        });
                    }
                    return;
                }
            }

            // Mark request as started
            markRequestStarted(key, getTabId());

            // Store key on xhr for later retrieval
            xhr._requestKey = key;
        });

        // After request completes (success or error)
        document.body.addEventListener('htmx:afterRequest', function(event) {
            const xhr = event.detail.xhr;
            const key = xhr._requestKey;

            if (key) {
                const success = event.detail.successful;
                markRequestCompleted(key, success);
            }
        });
    }

    /**
     * Initialize TabSync integration
     */
    function initTabSyncIntegration() {
        if (typeof TabSync === 'undefined') {
            console.warn('TabSync not found, cross-tab deduplication disabled');
            return;
        }

        // Listen for requests started in other tabs
        TabSync.on('request_started', function(data) {
            if (data && data.key && data.tabId !== getTabId()) {
                // Another tab started a request, track it
                inFlightRequests.set(data.key, {
                    key: data.key,
                    tabId: data.tabId,
                    startTime: data.startTime || Date.now()
                });
            }
        });

        // Listen for requests completed in other tabs
        TabSync.on('request_completed', function(data) {
            if (data && data.key) {
                // Remove from tracking
                inFlightRequests.delete(data.key);

                // If we're waiting for this request, trigger UI update
                if (data.success && data.result) {
                    // Dispatch custom event for UI to handle
                    const event = new CustomEvent('request-dedup:completed', {
                        detail: data
                    });
                    document.dispatchEvent(event);
                }
            }
        });
    }

    /**
     * Cleanup stale requests periodically
     */
    function startCleanupTimer() {
        setInterval(function() {
            const now = Date.now();
            for (const [key, request] of inFlightRequests.entries()) {
                if (now - request.startTime > REQUEST_TIMEOUT) {
                    console.log(`Cleaning up stale request: ${key}`);
                    inFlightRequests.delete(key);
                }
            }
        }, CLEANUP_INTERVAL);
    }

    /**
     * Initialize request deduplication
     */
    function init() {
        initHtmxIntegration();
        initTabSyncIntegration();
        startCleanupTimer();
        console.log('Request deduplication initialized');
    }

    /**
     * Public API for manual request tracking
     */
    return {
        init,
        getRequestKey,
        isRequestInFlight,
        markRequestStarted,
        markRequestCompleted,
        getTabId
    };
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', RequestDedup.init);
} else {
    RequestDedup.init();
}
