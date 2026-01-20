/**
 * Tab Synchronization Module
 *
 * Provides cross-tab communication using localStorage and storage events.
 * When a user has multiple tabs open, this module ensures that state changes
 * in one tab are reflected in all other tabs.
 *
 * Features:
 * - Broadcast state changes to other tabs
 * - Listen for state changes from other tabs
 * - Automatic UI updates when state changes
 * - Debouncing to prevent excessive updates
 *
 * Usage:
 *   TabSync.broadcast('session_selected', { sessionId: 'my_session' });
 *   TabSync.on('session_selected', function(data) {
 *     console.log('Session selected in another tab:', data.sessionId);
 *     // Update UI accordingly
 *   });
 */

const TabSync = (function() {
    'use strict';

    // Storage key prefix to avoid conflicts
    const STORAGE_PREFIX = 'chatfilter_sync_';
    const LAST_UPDATE_KEY = STORAGE_PREFIX + 'last_update';

    // Event handlers registry
    const eventHandlers = {};

    // Debounce timer
    let debounceTimer = null;
    const DEBOUNCE_MS = 100;

    /**
     * Initialize tab synchronization
     * Sets up storage event listener for cross-tab communication
     */
    function init() {
        // Listen for storage events from other tabs
        window.addEventListener('storage', function(event) {
            // Only process our events
            if (!event.key || !event.key.startsWith(STORAGE_PREFIX)) {
                return;
            }

            // Ignore last_update events
            if (event.key === LAST_UPDATE_KEY) {
                return;
            }

            // Extract event type from key
            const eventType = event.key.substring(STORAGE_PREFIX.length);

            // Parse new value
            let data = null;
            if (event.newValue) {
                try {
                    data = JSON.parse(event.newValue);
                } catch (e) {
                    console.error('Failed to parse sync data:', e);
                    return;
                }
            }

            // Trigger registered handlers
            trigger(eventType, data);
        });

        console.log('TabSync initialized');
    }

    /**
     * Broadcast an event to all other tabs
     *
     * @param {string} eventType - Type of event to broadcast
     * @param {*} data - Data to send with the event
     */
    function broadcast(eventType, data) {
        if (!eventType) {
            console.error('TabSync.broadcast: eventType is required');
            return;
        }

        const key = STORAGE_PREFIX + eventType;
        const value = JSON.stringify(data);

        try {
            // Set the value in localStorage
            // This triggers storage event in other tabs
            localStorage.setItem(key, value);

            // Update last modified timestamp
            localStorage.setItem(LAST_UPDATE_KEY, Date.now().toString());

            console.log('TabSync broadcast:', eventType, data);
        } catch (e) {
            console.error('Failed to broadcast event:', e);
        }
    }

    /**
     * Register an event handler
     *
     * @param {string} eventType - Type of event to listen for
     * @param {Function} handler - Handler function to call when event occurs
     */
    function on(eventType, handler) {
        if (!eventType || typeof handler !== 'function') {
            console.error('TabSync.on: eventType and handler function are required');
            return;
        }

        if (!eventHandlers[eventType]) {
            eventHandlers[eventType] = [];
        }

        eventHandlers[eventType].push(handler);
        console.log('TabSync registered handler for:', eventType);
    }

    /**
     * Unregister an event handler
     *
     * @param {string} eventType - Type of event
     * @param {Function} handler - Handler function to remove
     */
    function off(eventType, handler) {
        if (!eventHandlers[eventType]) {
            return;
        }

        const index = eventHandlers[eventType].indexOf(handler);
        if (index > -1) {
            eventHandlers[eventType].splice(index, 1);
            console.log('TabSync unregistered handler for:', eventType);
        }
    }

    /**
     * Trigger all handlers for an event type
     *
     * @param {string} eventType - Type of event that occurred
     * @param {*} data - Event data
     */
    function trigger(eventType, data) {
        const handlers = eventHandlers[eventType];
        if (!handlers || handlers.length === 0) {
            return;
        }

        // Debounce rapid events
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(function() {
            console.log('TabSync trigger:', eventType, data);
            handlers.forEach(function(handler) {
                try {
                    handler(data);
                } catch (e) {
                    console.error('Error in TabSync handler:', e);
                }
            });
        }, DEBOUNCE_MS);
    }

    /**
     * Get current value for an event type from localStorage
     *
     * @param {string} eventType - Type of event
     * @returns {*} Current value or null if not found
     */
    function get(eventType) {
        const key = STORAGE_PREFIX + eventType;
        const value = localStorage.getItem(key);

        if (!value) {
            return null;
        }

        try {
            return JSON.parse(value);
        } catch (e) {
            console.error('Failed to parse stored value:', e);
            return null;
        }
    }

    /**
     * Clear all sync data from localStorage
     */
    function clear() {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(STORAGE_PREFIX)) {
                keys.push(key);
            }
        }

        keys.forEach(function(key) {
            localStorage.removeItem(key);
        });

        console.log('TabSync cleared');
    }

    // Public API
    return {
        init: init,
        broadcast: broadcast,
        on: on,
        off: off,
        get: get,
        clear: clear
    };
})();

// Auto-initialize when script loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        TabSync.init();
    });
} else {
    TabSync.init();
}

// Make TabSync globally accessible
window.TabSync = TabSync;
