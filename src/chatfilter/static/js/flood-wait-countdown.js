/**
 * FloodWait countdown timer
 * Extracts flood_wait_until timestamp from badge data attributes and updates countdown display
 */
(function() {
    function formatCountdown(remainingMs) {
        const remainingSec = Math.floor(remainingMs / 1000);

        if (remainingSec < 10) return "скоро";
        if (remainingSec < 60) return remainingSec + "с";

        const minutes = Math.floor(remainingSec / 60);
        const seconds = remainingSec % 60;

        if (remainingSec < 3600) {
            return minutes + "м " + seconds + "с";
        }

        const hours = Math.floor(minutes / 60);
        const mins = minutes % 60;
        return hours + "ч " + mins + "м";
    }

    function initCountdownBadge(badgeEl) {
        // Defensive: null-check and validate dataset
        if (!badgeEl || !badgeEl.dataset) {
            return;
        }

        const floodWaitUntil = badgeEl.dataset.floodWaitUntil;
        const sessionId = badgeEl.dataset.sessionId;

        if (!floodWaitUntil) {
            console.warn("flood-wait-countdown: Missing data-flood-wait-until attribute");
            return;
        }

        // Validate ISO date
        let expiryMs;
        try {
            expiryMs = new Date(floodWaitUntil).getTime();
            if (isNaN(expiryMs)) {
                console.warn("flood-wait-countdown: Invalid ISO date in data-flood-wait-until:", floodWaitUntil);
                return;
            }
        } catch (e) {
            console.warn("flood-wait-countdown: Error parsing date:", e);
            return;
        }

        const timeEl = badgeEl.querySelector(".countdown-time");
        if (!timeEl) {
            return;
        }

        function updateCountdown() {
            const now = Date.now();
            const remaining = expiryMs - now;

            if (remaining <= 0) {
                // Timer expired - remove badge
                badgeEl.style.display = "none";
                return;
            }

            timeEl.textContent = formatCountdown(remaining);
        }

        // Update immediately
        updateCountdown();

        // Update every 10 seconds
        const intervalId = setInterval(updateCountdown, 10000);

        // Cleanup on row removal
        const row = badgeEl.closest("tr");
        if (row) {
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    mutation.removedNodes.forEach(function(node) {
                        if (node === row || node.contains(row)) {
                            clearInterval(intervalId);
                            observer.disconnect();
                        }
                    });
                });
            });
            observer.observe(row.parentNode, { childList: true });
        }
    }

    function initAllCountdowns() {
        const badges = document.querySelectorAll("[data-flood-wait-until]");
        badges.forEach(initCountdownBadge);
    }

    // Initialize on page load
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initAllCountdowns);
    } else {
        // Already loaded
        initAllCountdowns();
    }

    // Re-initialize on HTMX swap (new rows added via AJAX)
    document.addEventListener("htmx:afterSwap", initAllCountdowns);
})();
