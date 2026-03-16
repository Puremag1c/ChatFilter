/**
 * HTMX Error Handler
 * Extracted from base.html inline script.
 * Handles htmx:responseError, htmx:sendError, htmx:timeout,
 * htmx:beforeSwap, htmx:swapError and showToast custom event bridge.
 *
 * Dependencies: ToastManager (window.ToastManager), i18n (window.i18n)
 * Must be loaded AFTER toast-manager.js
 */
(function() {
    'use strict';

    // i18n helper
    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    // Guard: ToastManager must be available
    if (typeof window.ToastManager === 'undefined') {
        console.error('htmx-error-handler.js: ToastManager is not defined. Load toast-manager.js first.');
        return;
    }

    var ToastManager = window.ToastManager;

    // Helper: build retry + dismiss actions for a target element
    function buildActions(target) {
        var canRetry = target && (target.tagName === 'FORM' || target.hasAttribute('hx-get') || target.hasAttribute('hx-post'));
        var actions = [];
        if (canRetry) {
            actions.push({
                label: t('errors.retry'),
                class: 'retry',
                action: 'retry',
                callback: function() {
                    htmx.trigger(target, target.tagName === 'FORM' ? 'submit' : 'click');
                }
            });
        }
        actions.push({
            label: t('toast.dismiss'),
            class: 'dismiss',
            action: 'dismiss'
        });
        return actions;
    }

    // HTMX Error Handling Configuration
    document.body.addEventListener('htmx:responseError', function(event) {
        var status = event.detail.xhr.status;
        var statusText = event.detail.xhr.statusText;
        var message = t('errors.unknown_error');
        var title = t('errors.request_failed');

        // Parse error response if JSON
        try {
            var response = JSON.parse(event.detail.xhr.responseText);
            if (response.detail) {
                message = response.detail;
            }
        } catch (e) {
            // If not JSON, use status text
            if (status === 404) {
                message = t('errors.not_found_message');
                title = t('errors.not_found');
            } else if (status === 403) {
                message = t('errors.access_denied_message');
                title = t('errors.access_denied');
            } else if (status === 422) {
                message = t('errors.validation_error_message');
                title = t('errors.validation_error');
            } else if (status >= 500) {
                message = t('errors.server_error_message');
                title = t('errors.server_error');
            } else if (statusText) {
                message = statusText;
            }
        }

        ToastManager.error(message, {
            title: title,
            duration: 8000,
            actions: buildActions(event.detail.target)
        });
    });

    // HTMX network error (timeout, connection failed, etc.)
    document.body.addEventListener('htmx:sendError', function(event) {
        ToastManager.error(
            t('errors.unable_to_connect'),
            {
                title: t('errors.connection_error'),
                duration: 8000,
                actions: buildActions(event.detail.target)
            }
        );
    });

    // HTMX timeout error
    document.body.addEventListener('htmx:timeout', function(event) {
        ToastManager.error(
            t('errors.request_timeout_message'),
            {
                title: t('errors.request_timeout_title'),
                duration: 8000,
                actions: buildActions(event.detail.target)
            }
        );
    });

    // Cancel HTMX swap if target element was already replaced by SSE OOB swap.
    // When SSE OOB and HTMX response both target the same element, the SSE swap
    // replaces the DOM node first, leaving the HTMX response targeting a detached
    // element. Without this guard, htmx throws "Cannot read properties of null
    // (reading 'querySelector')" during outerHTML swap on the detached node.
    document.body.addEventListener('htmx:beforeSwap', function(event) {
        var target = event.detail.target;
        if (target && !target.isConnected) {
            console.log('HTMX swap cancelled: target already replaced by SSE');
            event.detail.shouldSwap = false;
        }
    });

    // HTMX swap error (invalid response format)
    document.body.addEventListener('htmx:swapError', function(event) {
        var target = event.detail.target;
        if (target && !target.isConnected) {
            // Race condition: SSE OOB swap already replaced the element
            console.log('HTMX swap race (suppressed): target already replaced by SSE');
            return;
        }

        console.error('HTMX swap error:', event.detail);

        ToastManager.error(
            t('errors.unexpected_format'),
            {
                title: t('errors.response_error'),
                duration: 8000
            }
        );
    });

    // Handle custom HX-Trigger events (showToast)
    document.body.addEventListener('showToast', function(event) {
        var detail = event.detail;
        if (detail) {
            ToastManager.show({
                type: detail.type || 'info',
                title: detail.title,
                message: detail.message,
                duration: detail.duration || 5000
            });
        }
    });
})();
