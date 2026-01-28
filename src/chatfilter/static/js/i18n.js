/**
 * Simple i18n (internationalization) utility for ChatFilter frontend.
 *
 * Loads translation files based on the current locale and provides
 * translation functions for JavaScript code.
 */

class I18n {
    constructor() {
        this.translations = {};
        this.currentLocale = 'en';
        this.fallbackLocale = 'en';
        this.initialized = false;
        // Promise that resolves when i18n is ready
        this._readyResolve = null;
        this.ready = new Promise((resolve) => {
            this._readyResolve = resolve;
        });
    }

    /**
     * Initialize i18n with the current locale from cookie or document attribute
     * @returns {Promise<void>}
     */
    async init() {
        // Get locale from cookie, document attribute, or default to 'en'
        this.currentLocale = this.detectLocale();

        try {
            await this.loadTranslations(this.currentLocale);
            this.initialized = true;
            this._readyResolve();
        } catch (error) {
            console.error(`Failed to load translations for ${this.currentLocale}:`, error);

            // Try fallback locale if not already trying it
            if (this.currentLocale !== this.fallbackLocale) {
                try {
                    await this.loadTranslations(this.fallbackLocale);
                    this.currentLocale = this.fallbackLocale;
                    this.initialized = true;
                    this._readyResolve();
                } catch (fallbackError) {
                    console.error(`Failed to load fallback translations:`, fallbackError);
                    // Resolve anyway to not block forever
                    this._readyResolve();
                }
            } else {
                // Resolve anyway to not block forever
                this._readyResolve();
            }
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
     * Load translation file for the specified locale
     * @param {string} locale - Locale code (e.g., 'en', 'ru')
     * @returns {Promise<void>}
     */
    async loadTranslations(locale) {
        const response = await fetch(`/static/js/locales/${locale}.json`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        this.translations = await response.json();
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
     * Switch to a different locale
     * @param {string} locale - New locale code
     * @returns {Promise<void>}
     */
    async setLocale(locale) {
        if (locale === this.currentLocale) {
            return;
        }

        await this.loadTranslations(locale);
        this.currentLocale = locale;

        // Set cookie to persist preference
        document.cookie = `lang=${locale}; path=/; max-age=31536000; SameSite=Lax`;

        // Update document lang attribute
        document.documentElement.lang = locale;

        // Dispatch event for other components to react to locale change
        window.dispatchEvent(new CustomEvent('localechange', { detail: { locale } }));
    }
}

// Create global instance
const i18n = new I18n();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        i18n.init().catch(error => {
            console.error('Failed to initialize i18n:', error);
        });
    });
} else {
    // DOM already loaded
    i18n.init().catch(error => {
        console.error('Failed to initialize i18n:', error);
    });
}

// Export for use in other scripts
window.i18n = i18n;
