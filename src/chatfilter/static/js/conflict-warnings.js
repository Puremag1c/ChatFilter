/**
 * Conflict Warning System
 * Detects and warns users about potential multi-tab conflicts
 * Integrates with TabSync, TabActivity, RequestDedup, and OptimisticLock
 */

const ConflictWarnings = (function() {
    'use strict';

    // Track active tabs
    const activeTabs = new Map();

    // Warning thresholds
    const MAX_TABS_WARNING = 5;
    const STALE_STATE_THRESHOLD = 300000; // 5 minutes

    // Configuration
    let config = {
        enableTabCountWarning: true,
        enableStaleStateWarning: true,
        enableConcurrentOpWarning: true,
        maxTabs: MAX_TABS_WARNING
    };

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
     * Check and warn about tab count
     */
    function checkTabCount() {
        if (!config.enableTabCountWarning) return;

        const tabCount = activeTabs.size + 1; // +1 for current tab

        if (tabCount >= config.maxTabs) {
            const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
            if (typeof ToastManager !== 'undefined') {
                ToastManager.warning(
                    t('warnings.tabs_open', { count: tabCount }),
                    {
                        title: t('warnings.multiple_tabs'),
                        duration: 10000,
                        actions: [{
                            label: t('common.got_it'),
                            class: 'dismiss',
                            action: 'dismiss'
                        }]
                    }
                );
            }

            console.warn(`Multiple tabs detected: ${tabCount} tabs open`);
        }
    }

    /**
     * Check if state might be stale
     */
    function checkStaleState() {
        if (!config.enableStaleStateWarning) return;
        if (typeof TabActivity === 'undefined') return;

        const timeSinceActivity = TabActivity.getTimeSinceLastActivity();

        if (timeSinceActivity > STALE_STATE_THRESHOLD && !document.hidden) {
            const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
            if (typeof ToastManager !== 'undefined') {
                ToastManager.info(
                    t('warnings.stale_state'),
                    {
                        title: t('warnings.stale_state_title'),
                        duration: 8000,
                        actions: [{
                            label: t('common.reload_page'),
                            class: 'retry',
                            action: 'reload',
                            callback: () => window.location.reload()
                        }, {
                            label: t('common.continue'),
                            class: 'dismiss',
                            action: 'dismiss'
                        }]
                    }
                );
            }
        }
    }

    /**
     * Handle tab activity from other tabs
     * @param {object} data
     */
    function handleTabActivity(data) {
        if (!data || !data.tabId || data.tabId === getTabId()) return;

        // Update active tabs registry
        activeTabs.set(data.tabId, {
            tabId: data.tabId,
            state: data.state,
            lastSeen: data.timestamp || Date.now()
        });

        // Clean up stale tabs (haven't seen in 1 minute)
        const now = Date.now();
        for (const [tabId, info] of activeTabs.entries()) {
            if (now - info.lastSeen > 60000) {
                activeTabs.delete(tabId);
            }
        }

        // Check tab count periodically
        if (activeTabs.size >= config.maxTabs - 1) {
            checkTabCount();
        }
    }

    /**
     * Handle request started in another tab
     * @param {object} data
     */
    function handleRequestStarted(data) {
        if (!config.enableConcurrentOpWarning) return;
        if (!data || data.tabId === getTabId()) return;

        // Only warn about certain types of operations
        const warningOperations = ['/api/analysis/start', '/api/sessions', '/api/chatlist'];
        const shouldWarn = warningOperations.some(op => data.key && data.key.includes(op));

        if (shouldWarn) {
            console.log('Concurrent operation detected in another tab:', data.key);
        }
    }

    /**
     * Handle lock acquisition in another tab
     * @param {object} data
     */
    function handleLockAcquired(data) {
        if (!config.enableConcurrentOpWarning) return;
        if (!data || data.tabId === getTabId()) return;

        console.log('Lock acquired in another tab:', data.key);

        // Show notification for critical operations
        const criticalOps = ['delete', 'cancel', 'force-cancel'];
        if (criticalOps.includes(data.operation)) {
            const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
            if (typeof ToastManager !== 'undefined') {
                ToastManager.info(
                    t('warnings.concurrent_operation', { operation: data.operation, resourceType: data.resourceType }),
                    {
                        title: t('warnings.concurrent_operation_title'),
                        duration: 5000
                    }
                );
            }
        }
    }

    /**
     * Warn about potential data loss on page close
     */
    function setupUnloadWarning() {
        // Check if there are any pending operations
        window.addEventListener('beforeunload', function(e) {
            // Check if any forms have unsaved changes
            const forms = document.querySelectorAll('form');
            let hasUnsavedChanges = false;

            for (const form of forms) {
                const inputs = form.querySelectorAll('input[type="checkbox"]:checked');
                if (inputs.length > 0) {
                    hasUnsavedChanges = true;
                    break;
                }
            }

            if (hasUnsavedChanges) {
                // Modern browsers show a generic message
                e.preventDefault();
                e.returnValue = '';
                return '';
            }
        });
    }

    /**
     * Setup periodic stale state checks
     */
    function setupStaleStateCheck() {
        // Check when tab becomes visible
        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                setTimeout(checkStaleState, 1000);
            }
        });

        // Check when tab becomes active
        window.addEventListener('focus', function() {
            setTimeout(checkStaleState, 1000);
        });
    }

    /**
     * Initialize conflict warning system
     */
    function init(options = {}) {
        // Merge config
        config = { ...config, ...options };

        console.log('Conflict warnings initialized');

        // Listen for tab activity
        if (typeof TabSync !== 'undefined') {
            TabSync.on('tab_activity', handleTabActivity);
            TabSync.on('request_started', handleRequestStarted);
            TabSync.on('lock_acquired', handleLockAcquired);
        }

        // Setup unload warning
        setupUnloadWarning();

        // Setup stale state checks
        setupStaleStateCheck();

        // Announce this tab to others
        if (typeof TabSync !== 'undefined') {
            TabSync.broadcast('tab_activity', {
                tabId: getTabId(),
                state: 'active',
                timestamp: Date.now()
            });
        }

        // Initial tab count check (delayed to let other tabs respond)
        setTimeout(checkTabCount, 2000);
    }

    /**
     * Show custom conflict warning
     * @param {string} message
     * @param {object} options
     */
    function showWarning(message, options = {}) {
        const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
        if (typeof ToastManager !== 'undefined') {
            ToastManager.warning(message, {
                title: options.title || t('warnings.conflict_title'),
                duration: options.duration || 8000,
                actions: options.actions || [{
                    label: t('common.dismiss'),
                    class: 'dismiss',
                    action: 'dismiss'
                }]
            });
        } else {
            console.warn('Conflict Warning:', message);
        }
    }

    /**
     * Public API
     */
    return {
        init,
        showWarning,
        checkTabCount,
        checkStaleState,
        getTabId,
        getActiveTabCount: () => activeTabs.size + 1,
        configure: (options) => {
            config = { ...config, ...options };
        }
    };
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        ConflictWarnings.init();
    });
} else {
    ConflictWarnings.init();
}
