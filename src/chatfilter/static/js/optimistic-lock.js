/**
 * Optimistic Locking Manager
 * Prevents race conditions in multi-tab scenarios by tracking operation versions
 * and detecting conflicts before they occur
 */

const OptimisticLock = (function() {
    'use strict';

    // Track active operations across tabs
    const activeOperations = new Map();

    // Lock timeout (auto-release after this time)
    const LOCK_TIMEOUT = 30000; // 30 seconds

    // Cleanup interval
    const CLEANUP_INTERVAL = 60000; // 1 minute

    /**
     * Get unique tab ID
     * @returns {string}
     */
    function getTabId() {
        if (!window.chatfilter_tab_id) {
            window.chatfilter_tab_id = 'tab_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
        }
        return window.chatfilter_tab_id;
    }

    /**
     * Generate operation key
     * @param {string} resourceType - Type of resource (e.g., 'analysis', 'session')
     * @param {string} resourceId - ID of the resource
     * @param {string} operation - Operation type (e.g., 'cancel', 'delete')
     * @returns {string}
     */
    function getOperationKey(resourceType, resourceId, operation) {
        return `${resourceType}:${resourceId}:${operation}`;
    }

    /**
     * Try to acquire lock for an operation
     * @param {string} resourceType
     * @param {string} resourceId
     * @param {string} operation
     * @returns {boolean} true if lock acquired, false if locked by another tab
     */
    function tryAcquireLock(resourceType, resourceId, operation) {
        const key = getOperationKey(resourceType, resourceId, operation);
        const existing = activeOperations.get(key);

        // Check if lock exists and is not expired
        if (existing) {
            const now = Date.now();
            if (now - existing.timestamp < LOCK_TIMEOUT) {
                // Lock is held by another tab
                if (existing.tabId !== getTabId()) {
                    console.log(`Lock denied: ${key} (held by ${existing.tabId})`);
                    return false;
                }
                // Same tab trying to acquire again - allow it (idempotent)
                return true;
            }
            // Lock expired, remove it
            activeOperations.delete(key);
        }

        // Acquire lock
        const lockInfo = {
            key,
            resourceType,
            resourceId,
            operation,
            tabId: getTabId(),
            timestamp: Date.now()
        };

        activeOperations.set(key, lockInfo);

        // Broadcast lock acquisition to other tabs
        if (typeof TabSync !== 'undefined') {
            TabSync.broadcast('lock_acquired', lockInfo);
        }

        console.log(`Lock acquired: ${key}`);
        return true;
    }

    /**
     * Release lock for an operation
     * @param {string} resourceType
     * @param {string} resourceId
     * @param {string} operation
     */
    function releaseLock(resourceType, resourceId, operation) {
        const key = getOperationKey(resourceType, resourceId, operation);
        const existing = activeOperations.get(key);

        // Only release if we own the lock
        if (existing && existing.tabId === getTabId()) {
            activeOperations.delete(key);

            // Broadcast lock release to other tabs
            if (typeof TabSync !== 'undefined') {
                TabSync.broadcast('lock_released', {
                    key,
                    resourceType,
                    resourceId,
                    operation,
                    tabId: getTabId()
                });
            }

            console.log(`Lock released: ${key}`);
        }
    }

    /**
     * Check if operation is locked by another tab
     * @param {string} resourceType
     * @param {string} resourceId
     * @param {string} operation
     * @returns {boolean}
     */
    function isLockedByOtherTab(resourceType, resourceId, operation) {
        const key = getOperationKey(resourceType, resourceId, operation);
        const existing = activeOperations.get(key);

        if (!existing) return false;

        // Check if lock is expired
        const now = Date.now();
        if (now - existing.timestamp >= LOCK_TIMEOUT) {
            activeOperations.delete(key);
            return false;
        }

        // Check if locked by different tab
        return existing.tabId !== getTabId();
    }

    /**
     * Get lock info for an operation
     * @param {string} resourceType
     * @param {string} resourceId
     * @param {string} operation
     * @returns {object|null}
     */
    function getLockInfo(resourceType, resourceId, operation) {
        const key = getOperationKey(resourceType, resourceId, operation);
        return activeOperations.get(key) || null;
    }

    /**
     * Initialize HTMX integration
     * Automatically handles locking for critical operations
     */
    function initHtmxIntegration() {
        if (typeof htmx === 'undefined') {
            console.warn('HTMX not found, optimistic locking disabled');
            return;
        }

        // Before sending critical requests, check for locks
        document.body.addEventListener('htmx:configRequest', function(event) {
            const target = event.detail.elt;

            // Check if this request requires locking
            const lockAttr = target.getAttribute('data-lock');
            if (!lockAttr) return;

            // Parse lock attribute: "resourceType:resourceId:operation"
            const parts = lockAttr.split(':');
            if (parts.length < 3) {
                console.warn('Invalid data-lock format:', lockAttr);
                return;
            }

            const [resourceType, resourceId, operation] = parts;

            // Try to acquire lock
            if (!tryAcquireLock(resourceType, resourceId, operation)) {
                // Lock denied, cancel request
                event.preventDefault();

                const lockInfo = getLockInfo(resourceType, resourceId, operation);
                const message = lockInfo
                    ? `This operation is being performed in another tab (${Math.round((Date.now() - lockInfo.timestamp) / 1000)}s ago)`
                    : 'This operation is being performed in another tab';

                if (typeof ToastManager !== 'undefined') {
                    ToastManager.warning(message, {
                        title: 'Operation in Progress',
                        duration: 5000
                    });
                }

                console.log('Request blocked due to optimistic lock:', lockAttr);
            } else {
                // Lock acquired, store lock info on element for cleanup
                target._lockInfo = { resourceType, resourceId, operation };
            }
        });

        // After request completes, release lock
        document.body.addEventListener('htmx:afterRequest', function(event) {
            const target = event.detail.elt;
            const lockInfo = target._lockInfo;

            if (lockInfo) {
                releaseLock(lockInfo.resourceType, lockInfo.resourceId, lockInfo.operation);
                delete target._lockInfo;
            }
        });
    }

    /**
     * Initialize TabSync integration
     */
    function initTabSyncIntegration() {
        if (typeof TabSync === 'undefined') {
            console.warn('TabSync not found, cross-tab locking disabled');
            return;
        }

        // Listen for locks acquired in other tabs
        TabSync.on('lock_acquired', function(data) {
            if (data && data.key && data.tabId !== getTabId()) {
                activeOperations.set(data.key, data);
                console.log(`Remote lock acquired: ${data.key} by ${data.tabId}`);
            }
        });

        // Listen for locks released in other tabs
        TabSync.on('lock_released', function(data) {
            if (data && data.key) {
                activeOperations.delete(data.key);
                console.log(`Remote lock released: ${data.key}`);

                // Dispatch event for UI to handle
                const event = new CustomEvent('optimistic-lock:released', {
                    detail: data
                });
                document.dispatchEvent(event);
            }
        });
    }

    /**
     * Cleanup expired locks
     */
    function cleanupExpiredLocks() {
        const now = Date.now();
        for (const [key, lock] of activeOperations.entries()) {
            if (now - lock.timestamp >= LOCK_TIMEOUT) {
                console.log(`Cleaning up expired lock: ${key}`);
                activeOperations.delete(key);
            }
        }
    }

    /**
     * Start cleanup timer
     */
    function startCleanupTimer() {
        setInterval(cleanupExpiredLocks, CLEANUP_INTERVAL);
    }

    /**
     * Initialize optimistic locking
     */
    function init() {
        initHtmxIntegration();
        initTabSyncIntegration();
        startCleanupTimer();
        console.log('Optimistic locking initialized');
    }

    /**
     * Public API
     */
    return {
        init,
        tryAcquireLock,
        releaseLock,
        isLockedByOtherTab,
        getLockInfo,
        getTabId
    };
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', OptimisticLock.init);
} else {
    OptimisticLock.init();
}
