/**
 * Version Check Manager for ChatFilter
 * Periodically checks for application updates and displays notifications
 */

const VersionCheckManager = {
    checkInterval: null,
    checkIntervalMs: 60 * 60 * 1000, // 1 hour in milliseconds
    notificationElement: null,
    lastCheckTime: null,
    updateInfo: null,

    /**
     * Initialize the version check system
     */
    init() {
        console.log('Initializing version check system');

        // Create notification element
        this.createNotificationElement();

        // Perform initial check
        this.checkForUpdates();

        // Set up periodic checks (every hour)
        this.checkInterval = setInterval(() => {
            this.checkForUpdates();
        }, this.checkIntervalMs);

        console.log('Version check system initialized');
    },

    /**
     * Create the update notification element
     */
    createNotificationElement() {
        // Check if notification already exists
        if (document.getElementById('update-notification')) {
            this.notificationElement = document.getElementById('update-notification');
            return;
        }

        // Create notification element
        const notification = document.createElement('div');
        notification.id = 'update-notification';
        notification.className = 'update-notification';
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'polite');
        notification.style.display = 'none';

        const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
        notification.innerHTML = `
            <div class="update-notification-content">
                <div class="update-notification-icon">
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 1.414L10.586 9H7a1 1 0 100 2h3.586l-1.293 1.293a1 1 0 101.414 1.414l3-3a1 1 0 000-1.414z" clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="update-notification-message">
                    <strong class="update-notification-title">${t('updates.available')}</strong>
                    <span class="update-notification-version"></span>
                </div>
                <div class="update-notification-actions">
                    <a href="#" class="update-notification-link" target="_blank" rel="noopener noreferrer">${t('updates.view_release')}</a>
                    <button class="update-notification-dismiss" aria-label="${t('common.dismiss')}">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                            <path fill-rule="evenodd" d="M4.646 4.646a.5.5 0 01.708 0L8 7.293l2.646-2.647a.5.5 0 01.708.708L8.707 8l2.647 2.646a.5.5 0 01-.708.708L8 8.707l-2.646 2.647a.5.5 0 01-.708-.708L7.293 8 4.646 5.354a.5.5 0 010-.708z" clip-rule="evenodd" />
                        </svg>
                    </button>
                </div>
            </div>
        `;

        // Add to page (prepend to body or to a specific container)
        const container = document.querySelector('.container') || document.body;
        if (container.firstChild) {
            container.insertBefore(notification, container.firstChild);
        } else {
            container.appendChild(notification);
        }

        this.notificationElement = notification;

        // Set up dismiss button
        const dismissButton = notification.querySelector('.update-notification-dismiss');
        dismissButton.addEventListener('click', () => this.hideNotification());
    },

    /**
     * Check for application updates
     */
    async checkForUpdates() {
        try {
            console.log('Checking for updates...');
            this.lastCheckTime = new Date();

            const response = await fetch('/api/version/check-updates');

            if (!response.ok) {
                console.error('Failed to check for updates:', response.statusText);
                return;
            }

            const updateInfo = await response.json();
            this.updateInfo = updateInfo;

            console.log('Update check result:', updateInfo);

            // Show notification if update is available
            if (updateInfo.update_available) {
                this.showNotification(updateInfo);
            } else {
                this.hideNotification();
            }
        } catch (error) {
            console.error('Error checking for updates:', error);
        }
    },

    /**
     * Show update notification
     */
    showNotification(updateInfo) {
        if (!this.notificationElement) {
            return;
        }

        // Update notification content
        const versionElement = this.notificationElement.querySelector('.update-notification-version');
        const linkElement = this.notificationElement.querySelector('.update-notification-link');

        const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
        versionElement.textContent = t('updates.version_info', { latest: updateInfo.latest_version, current: updateInfo.current_version });

        if (updateInfo.release_url) {
            linkElement.href = updateInfo.release_url;
            linkElement.style.display = '';
        } else {
            linkElement.style.display = 'none';
        }

        // Show notification with animation
        this.notificationElement.style.display = 'block';

        // Add show class after a short delay for animation
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                this.notificationElement.classList.add('show');
            });
        });
    },

    /**
     * Hide update notification
     */
    hideNotification() {
        if (!this.notificationElement) {
            return;
        }

        this.notificationElement.classList.remove('show');

        // Hide element after animation completes
        setTimeout(() => {
            this.notificationElement.style.display = 'none';
        }, 300); // Match CSS transition duration
    },

    /**
     * Force a manual update check
     */
    async forceCheck() {
        try {
            console.log('Forcing update check...');
            const response = await fetch('/api/version/check-updates?force=true');

            if (!response.ok) {
                console.error('Failed to check for updates:', response.statusText);
                return null;
            }

            const updateInfo = await response.json();
            this.updateInfo = updateInfo;
            this.lastCheckTime = new Date();

            console.log('Forced update check result:', updateInfo);

            // Show notification if update is available
            if (updateInfo.update_available) {
                this.showNotification(updateInfo);
            }

            return updateInfo;
        } catch (error) {
            console.error('Error forcing update check:', error);
            return null;
        }
    },

    /**
     * Get current update info
     */
    getUpdateInfo() {
        return this.updateInfo;
    },

    /**
     * Get last check time
     */
    getLastCheckTime() {
        return this.lastCheckTime;
    },

    /**
     * Clean up (stop periodic checks)
     */
    destroy() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }
};

// Initialize version check when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => VersionCheckManager.init());
} else {
    VersionCheckManager.init();
}

// Make VersionCheckManager globally accessible
window.VersionCheckManager = VersionCheckManager;
