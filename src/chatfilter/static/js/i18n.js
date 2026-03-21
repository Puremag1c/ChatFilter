/**
 * Simple i18n (internationalization) utility for ChatFilter frontend.
 *
 * Reads translations from window.__i18n__ (injected server-side in base.html)
 * and provides translation functions for JavaScript code.
 */

class I18n {
    constructor() {
        this.translations = {};
        this.currentLocale = 'en';
        this.fallbackLocale = 'en';
        this.initialized = false;
    }

    /**
     * Initialize i18n with inline translations from window.__i18n__
     */
    init() {
        this.currentLocale = this.detectLocale();

        if (window.__i18n__ && typeof window.__i18n__ === 'object') {
            this.translations = window.__i18n__;
            this.initialized = true;
        } else {
            console.warn('i18n: window.__i18n__ not found, translations unavailable');
        }
    }

    /**
     * Detect the current locale from cookie or document
     * @returns {string} Detected locale code
     */
    detectLocale() {
        // 1. Check cookie
        const cookieMatch = document.cookie.match(/lang=([^;]+)/);
        if (cookieMatch) {
            return cookieMatch[1];
        }

        // 2. Check document lang attribute
        const docLang = document.documentElement.lang;
        if (docLang) {
            return docLang;
        }

        // 3. Fallback
        return this.fallbackLocale;
    }

    /**
     * Translate a message key to the current locale
     * @param {string} key - Translation key (e.g., 'error.connection_failed')
     * @param {Object} [params] - Optional parameters for interpolation
     * @returns {string} Translated message
     */
    t(key, params = {}) {
        if (!this.initialized) {
            console.warn('i18n not initialized, returning key:', key);
            return key;
        }

        // Get translation by nested key (e.g., 'error.connection_failed')
        let translation = this.translations;
        const keys = key.split('.');

        for (const k of keys) {
            if (translation && typeof translation === 'object' && k in translation) {
                translation = translation[k];
            } else {
                console.warn(`Translation missing for key: ${key}`);
                return key;
            }
        }

        // If translation is not a string, return the key
        if (typeof translation !== 'string') {
            console.warn(`Translation for key ${key} is not a string:`, translation);
            return key;
        }

        // Simple parameter interpolation: {paramName}
        let result = translation;
        for (const [paramKey, paramValue] of Object.entries(params)) {
            const placeholder = `{${paramKey}}`;
            result = result.replace(new RegExp(placeholder, 'g'), String(paramValue));
        }

        return result;
    }

    /**
     * Get the current locale
     * @returns {string} Current locale code
     */
    getLocale() {
        return this.currentLocale;
    }

    /**
     * Switch to a different locale — sets cookie and reloads page so server
     * renders new inline translations.
     * @param {string} locale - New locale code
     */
    setLocale(locale) {
        if (locale === this.currentLocale) {
            return;
        }

        // Set cookie to persist preference
        document.cookie = `lang=${locale}; path=/; max-age=31536000; SameSite=Lax`;

        // Dispatch event for any listeners before reload
        window.dispatchEvent(new CustomEvent('localechange', { detail: { locale } }));

        // Reload so server re-renders page with new locale translations
        window.location.reload();
    }
}

// Create global instance
const i18n = new I18n();

// Initialize synchronously (data is already in window.__i18n__)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => i18n.init());
} else {
    i18n.init();
}

// Export for use in other scripts
window.i18n = i18n;
