/**
 * ChatFilter Modal System
 * Handles modal dialogs with accessibility, focus management, and mobile keyboard support
 */

class ModalManager {
    constructor() {
        this.activeModal = null;
        this.previousFocus = null;
        this.focusableSelectors = [
            'a[href]',
            'button:not([disabled])',
            'textarea:not([disabled])',
            'input:not([disabled])',
            'select:not([disabled])',
            '[tabindex]:not([tabindex="-1"])'
        ].join(', ');

        this.init();
    }

    init() {
        // Listen for ESC key globally
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeModal) {
                this.close(this.activeModal);
            }
        });

        // Listen for keyboard events on mobile
        if (this.isMobile()) {
            this.setupMobileKeyboardHandling();
        }

        // Handle clicks outside modal
        document.addEventListener('click', (e) => {
            if (this.activeModal && e.target.classList.contains('modal-overlay')) {
                this.close(this.activeModal);
            }
        });
    }

    /**
     * Open a modal by ID
     * @param {string} modalId - The ID of the modal element
     */
    open(modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.error(`Modal with id "${modalId}" not found`);
            return;
        }

        // Store currently focused element
        this.previousFocus = document.activeElement;

        // Show modal
        this.activeModal = modal;
        modal.classList.add('show');
        modal.setAttribute('aria-hidden', 'false');

        // Prevent body scroll
        document.body.classList.add('modal-open');

        // Set focus to first focusable element in modal
        setTimeout(() => {
            this.focusFirstElement(modal);
        }, 100); // Small delay to ensure CSS transition starts

        // Setup focus trap
        this.trapFocus(modal);

        // Announce to screen readers
        this.announceModal(modal);
    }

    /**
     * Close a modal
     * @param {HTMLElement} modal - The modal element to close
     */
    close(modal) {
        if (!modal) return;

        modal.classList.remove('show');
        modal.setAttribute('aria-hidden', 'true');

        // Re-enable body scroll
        document.body.classList.remove('modal-open');

        // Return focus to previously focused element
        if (this.previousFocus && this.previousFocus.focus) {
            this.previousFocus.focus();
        }

        this.activeModal = null;
        this.previousFocus = null;

        // Remove keyboard-visible class if present
        modal.classList.remove('keyboard-visible');
    }

    /**
     * Focus first focusable element in modal
     * @param {HTMLElement} modal
     */
    focusFirstElement(modal) {
        const focusable = modal.querySelectorAll(this.focusableSelectors);
        if (focusable.length > 0) {
            focusable[0].focus();
        }
    }

    /**
     * Trap focus within modal
     * @param {HTMLElement} modal
     */
    trapFocus(modal) {
        const handleTabKey = (e) => {
            if (e.key !== 'Tab') return;

            const focusable = Array.from(modal.querySelectorAll(this.focusableSelectors));
            const firstFocusable = focusable[0];
            const lastFocusable = focusable[focusable.length - 1];

            // If shift+tab on first element, move to last
            if (e.shiftKey && document.activeElement === firstFocusable) {
                e.preventDefault();
                lastFocusable.focus();
            }
            // If tab on last element, move to first
            else if (!e.shiftKey && document.activeElement === lastFocusable) {
                e.preventDefault();
                firstFocusable.focus();
            }
        };

        // Remove existing listener if any
        modal.removeEventListener('keydown', modal._focusTrapHandler);

        // Add new listener
        modal._focusTrapHandler = handleTabKey;
        modal.addEventListener('keydown', handleTabKey);
    }

    /**
     * Announce modal to screen readers
     * @param {HTMLElement} modal
     */
    announceModal(modal) {
        const dialog = modal.querySelector('.modal-dialog');
        const title = modal.querySelector('.modal-title');

        if (dialog) {
            dialog.setAttribute('role', 'dialog');
            dialog.setAttribute('aria-modal', 'true');

            if (title && title.id) {
                dialog.setAttribute('aria-labelledby', title.id);
            }
        }
    }

    /**
     * Check if device is mobile
     * @returns {boolean}
     */
    isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }

    /**
     * Setup mobile keyboard handling
     * Uses visualViewport API to detect keyboard appearance
     */
    setupMobileKeyboardHandling() {
        if (!window.visualViewport) return;

        let initialHeight = window.visualViewport.height;

        window.visualViewport.addEventListener('resize', () => {
            if (!this.activeModal) return;

            const currentHeight = window.visualViewport.height;
            const heightDifference = initialHeight - currentHeight;

            // Keyboard is visible if viewport height decreased significantly
            if (heightDifference > 150) {
                this.activeModal.classList.add('keyboard-visible');
                this.adjustModalForKeyboard();
            } else {
                this.activeModal.classList.remove('keyboard-visible');
            }
        });
    }

    /**
     * Adjust modal position when keyboard is visible
     */
    adjustModalForKeyboard() {
        if (!this.activeModal) return;

        const focusedElement = document.activeElement;
        if (focusedElement && (
            focusedElement.tagName === 'INPUT' ||
            focusedElement.tagName === 'TEXTAREA' ||
            focusedElement.tagName === 'SELECT'
        )) {
            // Scroll focused element into view
            setTimeout(() => {
                focusedElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });
            }, 100);
        }
    }

    /**
     * Create and show a simple modal programmatically
     * @param {Object} options - Modal options
     * @returns {HTMLElement} The created modal element
     */
    createModal(options = {}) {
        const {
            id = `modal-${Date.now()}`,
            title = '',
            body = '',
            icon = null,
            buttons = [],
            closeOnOverlay = true
        } = options;

        // Create modal HTML
        const modal = document.createElement('div');
        modal.id = id;
        modal.className = 'modal-overlay';
        modal.setAttribute('aria-hidden', 'true');

        const iconHtml = icon ? `<span class="modal-icon ${icon.class}">${icon.text}</span>` : '';
        const buttonsHtml = buttons.map(btn => `
            <button type="button"
                    class="modal-button ${btn.class || 'secondary'}"
                    data-action="${btn.action || 'close'}">
                ${btn.text}
            </button>
        `).join('');

        modal.innerHTML = `
            <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="${id}-title">
                <div class="modal-header">
                    ${iconHtml}
                    <h2 class="modal-title" id="${id}-title">${title}</h2>
                </div>
                <div class="modal-body">
                    <div class="modal-message">${body}</div>
                </div>
                <div class="modal-footer">
                    ${buttonsHtml}
                </div>
            </div>
        `;

        // Add to DOM
        document.body.appendChild(modal);

        // Setup button handlers
        modal.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.getAttribute('data-action');
                if (action === 'close') {
                    this.close(modal);
                    // Remove from DOM after animation
                    setTimeout(() => modal.remove(), 300);
                } else if (options.onAction) {
                    options.onAction(action);
                }
            });
        });

        // Handle overlay click
        if (!closeOnOverlay) {
            modal.addEventListener('click', (e) => {
                e.stopPropagation();
            });
        }

        return modal;
    }
}

// Global instance
const modalManager = new ModalManager();

// Expose global functions for easy access
window.openModal = (modalId) => modalManager.open(modalId);
window.closeModal = (modal) => {
    if (typeof modal === 'string') {
        modal = document.getElementById(modal);
    }
    modalManager.close(modal);
};
window.createModal = (options) => modalManager.createModal(options);

// Auto-wire close buttons
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-modal-close]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal-overlay');
            if (modal) {
                modalManager.close(modal);
            }
        });
    });

    // Auto-wire open buttons
    document.querySelectorAll('[data-modal-open]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.getAttribute('data-modal-open');
            if (modalId) {
                modalManager.open(modalId);
            }
        });
    });
});
