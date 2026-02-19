/**
 * Proxy Pool UI interactions
 *
 * Handles:
 * - Spinner cleanup after HTMX retest requests
 * - Fallback mechanism if HTMX swap fails or is slow
 */

document.addEventListener('DOMContentLoaded', function() {
    /**
     * Force-clear spinner after HTMX request completes
     *
     * This is a fallback mechanism in case HTMX swap fails or backend returns
     * JSON instead of HTML. Ensures spinner never gets stuck.
     *
     * Primary mechanism: HTMX swap replaces entire <tr> (removes spinner)
     * Fallback: This handler removes .htmx-request class after request completes
     */
    document.addEventListener('htmx:afterRequest', function(event) {
        const target = event.detail.target;

        // Only handle proxy row retests
        // Target will be the <tr id="proxy-row-{id}"> element
        if (!target.id || !target.id.startsWith('proxy-row-')) {
            return;
        }

        // Find and clear spinner in the row
        const spinner = target.querySelector('.status-loading-spinner');
        if (spinner) {
            // Remove htmx-request class to hide spinner (via CSS)
            spinner.classList.remove('htmx-request');
        }

        // Also clear from button if still present
        const retestBtn = target.querySelector('.proxy-retest-btn');
        if (retestBtn && retestBtn.classList.contains('htmx-request')) {
            retestBtn.classList.remove('htmx-request');
        }
    });
});
