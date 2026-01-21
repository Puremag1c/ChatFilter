/**
 * Tab Activity Tracker
 * Tracks tab visibility, focus, and activity state
 * Broadcasts activity changes to other tabs for coordination
 */

const TabActivity = (function() {
    'use strict';

    // Tab states
    const STATE = {
        ACTIVE: 'active',        // Tab is visible and focused
        VISIBLE: 'visible',      // Tab is visible but not focused
        HIDDEN: 'hidden',        // Tab is hidden
        INACTIVE: 'inactive'     // Tab has been inactive for a while
    };

    // Current state
    let currentState = STATE.HIDDEN;
    let lastActivityTime = Date.now();
    let inactivityTimeout = null;
    let heartbeatInterval = null;

    // Configuration
    const INACTIVITY_THRESHOLD = 60000; // 1 minute
    const HEARTBEAT_INTERVAL = 5000;    // 5 seconds

    // Listeners for state changes
    const stateListeners = [];

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
     * Determine current tab state
     * @returns {string}
     */
    function determineState() {
        // Check if tab is hidden
        if (document.hidden) {
            return STATE.HIDDEN;
        }

        // Check if tab is focused
        if (document.hasFocus()) {
            return STATE.ACTIVE;
        }

        // Tab is visible but not focused
        return STATE.VISIBLE;
    }

    /**
     * Update current state
     * @param {string} newState
     */
    function updateState(newState) {
        if (newState === currentState) return;

        const oldState = currentState;
        currentState = newState;

        console.log(`Tab state changed: ${oldState} → ${newState}`);

        // Broadcast state change
        broadcastState();

        // Notify listeners
        notifyListeners(newState, oldState);
    }

    /**
     * Broadcast current state to other tabs
     */
    function broadcastState() {
        if (typeof TabSync === 'undefined') return;

        TabSync.broadcast('tab_activity', {
            tabId: getTabId(),
            state: currentState,
            timestamp: Date.now()
        });
    }

    /**
     * Notify all listeners of state change
     * @param {string} newState
     * @param {string} oldState
     */
    function notifyListeners(newState, oldState) {
        stateListeners.forEach(listener => {
            try {
                listener(newState, oldState);
            } catch (error) {
                console.error('Error in state listener:', error);
            }
        });
    }

    /**
     * Record user activity
     */
    function recordActivity() {
        lastActivityTime = Date.now();

        // Clear existing inactivity timeout
        if (inactivityTimeout) {
            clearTimeout(inactivityTimeout);
        }

        // Set new inactivity timeout
        inactivityTimeout = setTimeout(() => {
            if (currentState === STATE.ACTIVE || currentState === STATE.VISIBLE) {
                updateState(STATE.INACTIVE);
            }
        }, INACTIVITY_THRESHOLD);

        // Update state if currently inactive
        if (currentState === STATE.INACTIVE) {
            updateState(determineState());
        }
    }

    /**
     * Handle visibility change
     */
    function handleVisibilityChange() {
        const newState = determineState();
        updateState(newState);

        if (!document.hidden) {
            recordActivity();
        }
    }

    /**
     * Handle focus change
     */
    function handleFocusChange() {
        const newState = determineState();
        updateState(newState);
        recordActivity();
    }

    /**
     * Handle blur
     */
    function handleBlur() {
        const newState = determineState();
        updateState(newState);
    }

    /**
     * Send periodic heartbeat
     */
    function sendHeartbeat() {
        if (currentState === STATE.ACTIVE || currentState === STATE.VISIBLE) {
            broadcastState();
        }
    }

    /**
     * Initialize event listeners
     */
    function initEventListeners() {
        // Visibility API
        document.addEventListener('visibilitychange', handleVisibilityChange);

        // Focus events
        window.addEventListener('focus', handleFocusChange);
        window.addEventListener('blur', handleBlur);

        // User activity events (for inactivity detection)
        const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
        activityEvents.forEach(event => {
            document.addEventListener(event, recordActivity, { passive: true });
        });

        // Listen for activity from other tabs
        if (typeof TabSync !== 'undefined') {
            TabSync.on('tab_activity', handleOtherTabActivity);
        }
    }

    /**
     * Handle activity broadcast from other tabs
     * @param {object} data
     */
    function handleOtherTabActivity(data) {
        if (!data || data.tabId === getTabId()) return;

        // Dispatch custom event for components to handle
        const event = new CustomEvent('tab-activity:other-tab', {
            detail: data
        });
        document.dispatchEvent(event);
    }

    /**
     * Start heartbeat interval
     */
    function startHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
        }

        heartbeatInterval = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);
    }

    /**
     * Stop heartbeat interval
     */
    function stopHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
        }
    }

    /**
     * Initialize tab activity tracking
     */
    function init() {
        // Set initial state
        currentState = determineState();
        console.log(`Tab activity tracker initialized (state: ${currentState})`);

        // Initialize event listeners
        initEventListeners();

        // Start heartbeat
        startHeartbeat();

        // Record initial activity
        recordActivity();

        // Broadcast initial state
        broadcastState();

        // Stop heartbeat when page unloads
        window.addEventListener('beforeunload', stopHeartbeat);
    }

    /**
     * Public API
     */
    return {
        init,
        getTabId,
        getState: () => currentState,
        isActive: () => currentState === STATE.ACTIVE,
        isVisible: () => currentState === STATE.ACTIVE || currentState === STATE.VISIBLE,
        isHidden: () => currentState === STATE.HIDDEN,
        isInactive: () => currentState === STATE.INACTIVE,
        getLastActivityTime: () => lastActivityTime,
        getTimeSinceLastActivity: () => Date.now() - lastActivityTime,

        /**
         * Register listener for state changes
         * @param {function} callback - Called with (newState, oldState)
         */
        onStateChange(callback) {
            if (typeof callback === 'function') {
                stateListeners.push(callback);
            }
        },

        /**
         * Unregister listener
         * @param {function} callback
         */
        offStateChange(callback) {
            const index = stateListeners.indexOf(callback);
            if (index > -1) {
                stateListeners.splice(index, 1);
            }
        },

        // Export state constants
        STATE
    };
})();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', TabActivity.init);
} else {
    TabActivity.init();
}
