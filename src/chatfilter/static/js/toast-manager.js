/**
 * Toast Notification System
 *
 * Provides a global ToastManager for displaying toast notifications.
 * Includes global error/rejection handlers.
 *
 * Dependencies: i18n.js (must be loaded first)
 * Exposes: window.ToastManager
 */
(function() {
    'use strict';

    // i18n helper - fallback to key if i18n not loaded
    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    // Toast Notification System
    const ToastManager = {
        container: null,
        queue: [],
        maxToasts: 3,
        defaultDuration: 5000,

        init() {
            this.container = document.getElementById('toast-container');
            if (!this.container) {
                this.container = document.createElement('div');
                this.container.id = 'toast-container';
                document.body.appendChild(this.container);
            }
        },

        show(options) {
            if (!this.container) this.init();

            const toast = {
                id: Date.now() + Math.random(),
                type: options.type || 'info',
                title: options.title || this.getDefaultTitle(options.type),
                message: options.message || '',
                duration: options.duration !== undefined ? options.duration : this.defaultDuration,
                actions: options.actions || [],
                onClose: options.onClose
            };

            this.queue.push(toast);
            this.render();

            if (toast.duration > 0) {
                setTimeout(() => this.hide(toast.id), toast.duration);
            }

            return toast.id;
        },

        hide(toastId) {
            const toast = this.queue.find(t => t.id === toastId);
            if (!toast) return;

            const element = document.querySelector(`[data-toast-id="${toastId}"]`);
            if (element) {
                element.classList.add('hiding');
                setTimeout(() => {
                    this.queue = this.queue.filter(t => t.id !== toastId);
                    this.render();
                    if (toast.onClose) toast.onClose();
                }, 300);
            }
        },

        hideAll() {
            const toastIds = this.queue.map(t => t.id);
            toastIds.forEach(id => this.hide(id));
        },

        render() {
            const visibleToasts = this.queue.slice(-this.maxToasts);
            this.container.innerHTML = visibleToasts.map(toast => this.createToastHTML(toast)).join('');

            // Set translated text via DOM APIs to prevent XSS through translation strings
            visibleToasts.forEach(toast => {
                const el = this.container.querySelector(`[data-toast-id="${toast.id}"]`);
                if (!el) return;
                el.querySelector('.toast-title').textContent = toast.title;
                const msgEl = el.querySelector('.toast-message');
                if (msgEl) msgEl.textContent = toast.message;
                el.querySelector('.toast-close').setAttribute('aria-label', t('toast.close_notification'));
                toast.actions.forEach((action, idx) => {
                    const btn = el.querySelector(`.toast-action[data-action-index="${idx}"]`);
                    if (btn) {
                        btn.textContent = action.label;
                        btn.setAttribute('aria-label', action.label);
                    }
                });
            });

            setTimeout(() => {
                visibleToasts.forEach(toast => {
                    const element = document.querySelector(`[data-toast-id="${toast.id}"]`);
                    if (element) element.classList.add('show');
                });
            }, 10);
        },

        createToastHTML(toast) {
            const icons = {
                error: '<span class="i i-x-circle"></span>',
                success: '<span class="i i-check-circle"></span>',
                warning: '<span class="i i-alert-triangle"></span>',
                info: '<span class="i i-info"></span>'
            };

            const iconLabels = {
                error: 'Error',
                success: 'Success',
                warning: 'Warning',
                info: 'Information'
            };

            const actionsHTML = toast.actions.length > 0 ? `
                <div class="toast-actions">
                    ${toast.actions.map((action, idx) => `
                        <button class="toast-action ${action.class || ''}"
                                onclick="ToastManager.handleAction('${toast.id}', '${action.action}')"
                                data-action-index="${idx}">
                        </button>
                    `).join('')}
                </div>
            ` : '';

            return `
                <div class="toast toast-${toast.type}" data-toast-id="${toast.id}" role="alert" aria-live="assertive">
                    <div class="toast-icon" aria-label="${iconLabels[toast.type] || iconLabels.info}" role="img">${icons[toast.type] || icons.info}</div>
                    <div class="toast-content">
                        <div class="toast-title"></div>
                        ${toast.message ? '<div class="toast-message"></div>' : ''}
                        ${actionsHTML}
                    </div>
                    <button class="toast-close" onclick="ToastManager.hide('${toast.id}')">&times;</button>
                </div>
            `;
        },

        handleAction(toastId, action) {
            const toast = this.queue.find(t => t.id === toastId);
            if (!toast) return;

            const actionObj = toast.actions.find(a => a.action === action);
            if (actionObj && actionObj.callback) {
                actionObj.callback();
            }

            this.hide(toastId);
        },

        getDefaultTitle(type) {
            const titles = {
                error: t('toast.default_title.error'),
                success: t('toast.default_title.success'),
                warning: t('toast.default_title.warning'),
                info: t('toast.default_title.info')
            };
            return titles[type] || t('toast.default_title.notification');
        },

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        // Convenience methods
        error(message, options = {}) {
            return this.show({ ...options, type: 'error', message });
        },

        success(message, options = {}) {
            return this.show({ ...options, type: 'success', message });
        },

        warning(message, options = {}) {
            return this.show({ ...options, type: 'warning', message });
        },

        info(message, options = {}) {
            return this.show({ ...options, type: 'info', message });
        }
    };

    // Initialize toast system when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            ToastManager.init();
        });
    } else {
        ToastManager.init();
    }

    // Global error boundary
    window.addEventListener('error', function(event) {
        console.error('Global error caught:', event.error);

        ToastManager.error(
            event.error?.message || t('errors.unknown_error'),
            {
                title: t('toast.app_error'),
                duration: 0,
                actions: [{
                    label: t('toast.reload_page'),
                    class: 'retry',
                    action: 'reload',
                    callback: () => window.location.reload()
                }, {
                    label: t('toast.dismiss'),
                    class: 'dismiss',
                    action: 'dismiss'
                }]
            }
        );
    });

    // Global unhandled promise rejection handler
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);

        ToastManager.error(
            event.reason?.message || t('errors.unknown_error'),
            {
                title: t('toast.app_error'),
                duration: 8000
            }
        );
    });

    // Handle custom HX-Trigger events (showToast)
    document.body.addEventListener('showToast', function(event) {
        const detail = event.detail;
        if (detail) {
            const toast = detail;
            ToastManager.show({
                type: toast.type || 'info',
                title: toast.title,
                message: toast.message,
                duration: toast.duration || 5000
            });
        }
    });

    // Make ToastManager globally accessible
    window.ToastManager = ToastManager;
})();
