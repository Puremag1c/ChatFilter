/**
 * Theme Switcher
 * Handles dark/light theme toggling with persistence and cross-tab synchronization
 */

(function() {
    'use strict';

    const THEME_KEY = 'chatfilter-theme';
    const THEME_DARK = 'dark';
    const THEME_LIGHT = 'light';

    // Theme icons
    const ICON_DARK = '🌙';  // Moon for dark mode
    const ICON_LIGHT = '☀️';  // Sun for light mode

    /**
     * Get the current theme from localStorage or system preference
     */
    function getCurrentTheme() {
        // Check localStorage first
        const savedTheme = localStorage.getItem(THEME_KEY);
        if (savedTheme === THEME_DARK || savedTheme === THEME_LIGHT) {
            return savedTheme;
        }

        // Fall back to system preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return THEME_DARK;
        }

        return THEME_LIGHT;
    }

    /**
     * Apply theme to the document
     */
    function applyTheme(theme) {
        const root = document.documentElement;
        const themeIcon = document.querySelector('.theme-icon');

        if (theme === THEME_DARK) {
            root.setAttribute('data-theme', THEME_DARK);
            if (themeIcon) {
                themeIcon.textContent = ICON_LIGHT; // Show sun when in dark mode
            }
        } else {
            root.removeAttribute('data-theme');
            if (themeIcon) {
                themeIcon.textContent = ICON_DARK; // Show moon when in light mode
            }
        }
    }

    /**
     * Toggle theme and save to localStorage
     */
    function toggleTheme() {
        const currentTheme = getCurrentTheme();
        const newTheme = currentTheme === THEME_DARK ? THEME_LIGHT : THEME_DARK;

        // Save to localStorage
        localStorage.setItem(THEME_KEY, newTheme);

        // Apply the theme
        applyTheme(newTheme);

        // Broadcast theme change to other tabs
        if (window.TabSync) {
            window.TabSync.broadcast('theme-changed', { theme: newTheme });
        }

        return newTheme;
    }

    /**
     * Initialize theme on page load
     */
    function initTheme() {
        const currentTheme = getCurrentTheme();
        applyTheme(currentTheme);

        // Set up toggle button
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function() {
                toggleTheme();
            });
        }

        // Listen for system theme changes
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

            // Modern browsers
            if (mediaQuery.addEventListener) {
                mediaQuery.addEventListener('change', function(e) {
                    // Only apply system preference if user hasn't set a preference
                    if (!localStorage.getItem(THEME_KEY)) {
                        const newTheme = e.matches ? THEME_DARK : THEME_LIGHT;
                        applyTheme(newTheme);
                    }
                });
            }
            // Fallback for older browsers
            else if (mediaQuery.addListener) {
                mediaQuery.addListener(function(e) {
                    if (!localStorage.getItem(THEME_KEY)) {
                        const newTheme = e.matches ? THEME_DARK : THEME_LIGHT;
                        applyTheme(newTheme);
                    }
                });
            }
        }

        // Listen for theme changes from other tabs
        if (window.TabSync) {
            window.TabSync.on('theme-changed', function(data) {
                if (data && data.theme) {
                    applyTheme(data.theme);
                }
            });
        }
    }

    // Initialize theme immediately (before DOMContentLoaded) to prevent flash
    const currentTheme = getCurrentTheme();
    applyTheme(currentTheme);

    // Set up event listeners when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTheme);
    } else {
        initTheme();
    }

    // Export for potential use by other scripts
    window.ThemeSwitcher = {
        getCurrentTheme: getCurrentTheme,
        toggleTheme: toggleTheme,
        applyTheme: applyTheme
    };
})();
