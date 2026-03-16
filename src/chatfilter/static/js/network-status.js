/**
 * Network Connectivity Status Monitor
 * Monitors network status via /health endpoint and browser events.
 * Depends on: window.ToastManager, window.i18n, window.TabSync (optional)
 */
(function() {
    'use strict';

    // i18n helper
    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    var NetworkStatusMonitor = {
        pollInterval: 30000, // Poll every 30 seconds (less frequent than Telegram)
        timeoutId: null,
        lastStatus: null,
        consecutiveErrors: 0,
        maxErrors: 2,
        isOnline: true,

        async checkStatus() {
            try {
                var response = await fetch('/health', {
                    method: 'GET',
                    cache: 'no-cache',
                    signal: AbortSignal.timeout(10000) // 10 second timeout (server may be slow under load)
                });

                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }

                var data = await response.json();
                this.consecutiveErrors = 0;

                var networkOnline = data.network && data.network.online;
                this.updateUI(networkOnline, null);
                this.notifyStatusChange(networkOnline);

            } catch (error) {
                // If SSE is connected, server is reachable — skip error counting.
                // During heavy analysis /health may timeout but SSE stays alive.
                var sseConnected = document.body.classList &&
                    !document.body.classList.contains('sse-disconnected');
                if (sseConnected) {
                    console.warn('Network status check failed but SSE connected, ignoring:', error.message);
                    // Don't count this as an error — SSE proves connectivity
                } else {
                    console.error('Network status check failed:', error);
                    this.consecutiveErrors++;

                    // After multiple failures, assume offline
                    if (this.consecutiveErrors >= this.maxErrors) {
                        this.updateUI(false, t('errors.unable_to_connect'));
                        this.notifyStatusChange(false);
                    }
                }
            }

            // Schedule next poll
            this.timeoutId = setTimeout(function() { NetworkStatusMonitor.checkStatus(); }, this.pollInterval);
        },

        updateUI: function(online, error) {
            var indicator = document.getElementById('network-indicator');
            var text = document.getElementById('network-text');
            var container = document.getElementById('network-status');

            if (!indicator || !text || !container) return;

            // Remove all status classes
            container.classList.remove('status-connected', 'status-disconnected', 'status-error');

            if (error) {
                // Error state (offline)
                container.classList.add('status-error');
                text.textContent = window.i18n.t('status.offline');
                container.title = window.i18n.t('status.network_disconnected') + ': ' + error;
            } else if (online) {
                // Online state
                container.classList.add('status-connected');
                text.textContent = window.i18n.t('status.online');
                container.title = window.i18n.t('status.network_connected');
            } else {
                // Offline state
                container.classList.add('status-disconnected');
                text.textContent = window.i18n.t('status.offline');
                container.title = window.i18n.t('status.network_disconnected');
            }
        },

        notifyStatusChange: function(isOnline) {
            // Only notify on actual state changes
            if (this.lastStatus === null) {
                this.lastStatus = isOnline;
                return;
            }

            if (this.lastStatus !== isOnline) {
                if (!isOnline) {
                    // Network went offline
                    ToastManager.error(
                        t('network.offline_toast'),
                        {
                            title: t('network.no_internet'),
                            duration: 0, // Persist until dismissed or network restored
                            actions: [{
                                label: t('network.check_now'),
                                class: 'retry',
                                action: 'check',
                                callback: function() { NetworkStatusMonitor.checkStatus(); }
                            }, {
                                label: t('toast.dismiss'),
                                class: 'dismiss',
                                action: 'dismiss'
                            }]
                        }
                    );

                    // Broadcast to other tabs
                    if (typeof TabSync !== 'undefined') {
                        TabSync.broadcast('network-status', { online: false });
                    }
                } else {
                    // Network came back online
                    ToastManager.success(
                        t('network.back_online_message'),
                        {
                            title: t('network.back_online'),
                            duration: 3000
                        }
                    );

                    // Broadcast to other tabs
                    if (typeof TabSync !== 'undefined') {
                        TabSync.broadcast('network-status', { online: true });
                    }
                }
            }

            this.lastStatus = isOnline;
        },

        start: function() {
            console.log('Starting network status monitor');
            this.checkStatus();

            // Also monitor browser online/offline events
            window.addEventListener('online', function() {
                console.log('Browser reports: online');
                NetworkStatusMonitor.checkStatus(); // Verify with server
            });

            window.addEventListener('offline', function() {
                console.log('Browser reports: offline');
                NetworkStatusMonitor.updateUI(false, t('network.no_internet'));
                NetworkStatusMonitor.notifyStatusChange(false);
            });

            // Listen for status updates from other tabs
            if (typeof TabSync !== 'undefined') {
                TabSync.on('network-status', function(data) {
                    console.log('Received network status update from another tab:', data);
                    NetworkStatusMonitor.checkStatus(); // Verify
                });
            }
        },

        stop: function() {
            console.log('Stopping network status monitor');
            if (this.timeoutId) {
                clearTimeout(this.timeoutId);
                this.timeoutId = null;
            }
        }
    };

    // Start monitoring when page loads
    document.addEventListener('DOMContentLoaded', function() {
        NetworkStatusMonitor.start();
    });

    // Stop monitoring when page unloads
    window.addEventListener('beforeunload', function() {
        NetworkStatusMonitor.stop();
    });

    // Handle page visibility changes
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            NetworkStatusMonitor.stop();
        } else {
            NetworkStatusMonitor.start();
        }
    });

    // Make monitor globally accessible
    window.NetworkStatusMonitor = NetworkStatusMonitor;
})();
