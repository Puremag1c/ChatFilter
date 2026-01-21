/**
 * Language Switcher
 * Handles language switching between supported locales
 */

(function() {
    'use strict';

    const SUPPORTED_LANGUAGES = ['en', 'ru'];
    const LANGUAGE_NAMES = {
        'en': 'English',
        'ru': 'Русский'
    };

    // Initialize language switcher when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initLanguageSwitcher);
    } else {
        initLanguageSwitcher();
    }

    function initLanguageSwitcher() {
        const languageButton = document.getElementById('language-toggle');
        if (!languageButton) {
            console.warn('Language toggle button not found');
            return;
        }

        // Set up click handler
        languageButton.addEventListener('click', toggleLanguage);

        // Update button text with current language
        updateLanguageButton();

        // Listen for locale changes from other sources
        window.addEventListener('localechange', function(event) {
            updateLanguageButton();
        });
    }

    function toggleLanguage() {
        const currentLocale = getCurrentLocale();
        const nextLocale = getNextLocale(currentLocale);

        // Switch language using i18n utility
        if (window.i18n) {
            window.i18n.setLocale(nextLocale).then(() => {
                // Reload page to apply new locale on server-rendered content
                window.location.reload();
            }).catch(error => {
                console.error('Failed to switch language:', error);
                // Try to reload anyway, as cookie might be set
                window.location.reload();
            });
        } else {
            // If i18n not loaded yet, just set cookie and reload
            document.cookie = `lang=${nextLocale}; path=/; max-age=31536000; SameSite=Lax`;
            window.location.reload();
        }
    }

    function getCurrentLocale() {
        // Try to get from i18n utility
        if (window.i18n && window.i18n.initialized) {
            return window.i18n.getLocale();
        }

        // Try cookie
        const cookieMatch = document.cookie.match(/lang=([^;]+)/);
        if (cookieMatch) {
            return cookieMatch[1];
        }

        // Try document lang
        const docLang = document.documentElement.lang;
        if (docLang && SUPPORTED_LANGUAGES.includes(docLang)) {
            return docLang;
        }

        // Default
        return 'en';
    }

    function getNextLocale(currentLocale) {
        const currentIndex = SUPPORTED_LANGUAGES.indexOf(currentLocale);
        const nextIndex = (currentIndex + 1) % SUPPORTED_LANGUAGES.length;
        return SUPPORTED_LANGUAGES[nextIndex];
    }

    function updateLanguageButton() {
        const languageButton = document.getElementById('language-toggle');
        if (!languageButton) {
            return;
        }

        const currentLocale = getCurrentLocale();
        const languageIcon = languageButton.querySelector('.language-icon');

        if (languageIcon) {
            languageIcon.textContent = currentLocale.toUpperCase();
        }

        // Update aria-label
        const languageName = LANGUAGE_NAMES[currentLocale] || currentLocale;
        const nextLocale = getNextLocale(currentLocale);
        const nextLanguageName = LANGUAGE_NAMES[nextLocale] || nextLocale;
        languageButton.setAttribute('aria-label', `Current language: ${languageName}. Click to switch to ${nextLanguageName}`);

        // Update tooltip
        languageButton.setAttribute('data-tooltip', `Switch to ${nextLanguageName}`);
    }
})();
