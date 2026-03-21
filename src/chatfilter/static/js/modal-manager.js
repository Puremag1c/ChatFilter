/**
 * Modal Dialog System
 * Provides confirmation dialogs with customizable titles, messages, and buttons
 * Different from modal.js (HTMX overlay modals) - this is for programmatic confirmation dialogs
 */
(function() {
    'use strict';

    // i18n helper - fallback to key if i18n not loaded
    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    const ModalManager = {
        currentModal: null,
        overlayElement: null,

        init() {
            // Create modal overlay container if it doesn't exist
            this.overlayElement = document.getElementById('modal-overlay');
            if (!this.overlayElement) {
                this.overlayElement = document.createElement('div');
                this.overlayElement.id = 'modal-overlay';
                this.overlayElement.className = 'modal-overlay';
                this.overlayElement.setAttribute('role', 'dialog');
                this.overlayElement.setAttribute('aria-modal', 'true');
                document.body.appendChild(this.overlayElement);
            }

            // Close modal on overlay click
            this.overlayElement.addEventListener('click', (e) => {
                if (e.target === this.overlayElement) {
                    this.hide();
                }
            });

            // Close modal on Escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.currentModal) {
                    this.hide();
                }
            });
        },

        confirm(options) {
            return new Promise((resolve) => {
                if (!this.overlayElement) this.init();

                const modal = {
                    id: Date.now() + Math.random(),
                    type: options.type || 'warning',
                    icon: options.icon || this.getDefaultIcon(options.type),
                    title: options.title || t('modal.confirm_action'),
                    message: options.message || t('modal.are_you_sure'),
                    confirmText: options.confirmText || t('modal.confirm'),
                    cancelText: options.cancelText || t('modal.cancel'),
                    confirmClass: options.confirmClass || 'danger',
                    onConfirm: () => {
                        resolve(true);
                        this.hide();
                    },
                    onCancel: () => {
                        resolve(false);
                        this.hide();
                    }
                };

                this.currentModal = modal;
                this.render(modal);
            });
        },

        getDefaultIcon(type) {
            const icons = {
                warning: '⚠️',
                danger: '⛔',
                info: 'ℹ️'
            };
            return icons[type] || icons.warning;
        },

        render(modal) {
            const modalHTML = `
                <div class="modal-dialog" role="document">
                    <div class="modal-header">
                        <span class="modal-icon ${modal.type}" aria-hidden="true">${modal.icon}</span>
                        <h2 class="modal-title" id="modal-title-${modal.id}"></h2>
                    </div>
                    <div class="modal-body">
                        <p class="modal-message"></p>
                    </div>
                    <div class="modal-footer">
                        <button class="modal-button secondary"
                                onclick="ModalManager.currentModal.onCancel()">
                        </button>
                        <button class="modal-button ${modal.confirmClass}"
                                onclick="ModalManager.currentModal.onConfirm()"
                                autofocus>
                        </button>
                    </div>
                </div>
            `;

            this.overlayElement.innerHTML = modalHTML;

            // Set translated text via DOM APIs to prevent XSS through translation strings
            this.overlayElement.querySelector('.modal-title').textContent = modal.title;
            this.overlayElement.querySelector('.modal-message').textContent = modal.message;
            const cancelBtn = this.overlayElement.querySelector('.modal-button.secondary');
            cancelBtn.textContent = modal.cancelText;
            cancelBtn.setAttribute('aria-label', modal.cancelText);
            const confirmBtn = this.overlayElement.querySelector(`.modal-button.${modal.confirmClass}`);
            confirmBtn.textContent = modal.confirmText;
            confirmBtn.setAttribute('aria-label', modal.confirmText);

            this.overlayElement.setAttribute('aria-labelledby', `modal-title-${modal.id}`);

            // Show modal with animation
            setTimeout(() => {
                this.overlayElement.classList.add('show');
                // Focus the confirm button for accessibility
                const confirmButton = this.overlayElement.querySelector('.modal-button.' + modal.confirmClass);
                if (confirmButton) {
                    confirmButton.focus();
                }
            }, 10);

            // Trap focus within modal
            this.trapFocus(this.overlayElement);
        },

        hide() {
            if (!this.overlayElement) return;

            this.overlayElement.classList.remove('show');

            setTimeout(() => {
                this.overlayElement.innerHTML = '';
                this.currentModal = null;
            }, 300);
        },

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        trapFocus(element) {
            const focusableElements = element.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );

            if (focusableElements.length === 0) return;

            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            element.addEventListener('keydown', function(e) {
                if (e.key !== 'Tab') return;

                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        lastFocusable.focus();
                        e.preventDefault();
                    }
                } else {
                    if (document.activeElement === lastFocusable) {
                        firstFocusable.focus();
                        e.preventDefault();
                    }
                }
            });
        }
    };

    // Initialize modal system on page load
    document.addEventListener('DOMContentLoaded', function() {
        ModalManager.init();
    });

    // Make ModalManager globally accessible
    window.ModalManager = ModalManager;
})();
