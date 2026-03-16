/**
 * SSE Connection Status Banner Manager
 * Manages visibility of the SSE connection status banner when connection is lost
 */
(function() {
    'use strict';

    const SSEStatusBanner = {
        banner: null,
        visible: false,

        init() {
            this.banner = document.getElementById('sse-status-banner');
        },

        show() {
            if (!this.banner) this.init();
            if (!this.banner || this.visible) return;

            this.banner.style.display = 'block';
            this.visible = true;

            console.log('[SSE Banner] Shown - connection lost');
        },

        hide() {
            if (!this.banner || !this.visible) return;

            this.banner.style.display = 'none';
            this.visible = false;
            console.log('[SSE Banner] Hidden');
        },

        isVisible() {
            return this.visible;
        }
    };

    // Make globally accessible
    window.SSEStatusBanner = SSEStatusBanner;

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        SSEStatusBanner.init();
    });
})();
