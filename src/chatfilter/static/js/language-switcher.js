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

        // Set language cookie
        document.cookie = `lang=${nextLocale}; path=/; max-age=31536000; SameSite=Lax`;

        // Update visual state before reload
        updateLanguageButton();

        // Notify any listeners before reload
        window.dispatchEvent(new CustomEvent('localechange', { detail: { locale: nextLocale } }));

        // Reload so server renders new translations inline
        window.location.reload();
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
        const t = (key, params) => window.i18n ? window.i18n.t(key, params) : key;
        languageButton.setAttribute('aria-label', t('language.current_aria', { languageName, nextLanguageName }));

    }
})();
