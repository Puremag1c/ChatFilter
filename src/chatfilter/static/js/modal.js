/**
 * ChatFilter Modal System
 * Provides accessible modal dialogs with focus trap, keyboard navigation, and ARIA support
 * Version: 1.0.0
 */

(function() {
    'use strict';

    /**
     * Modal manager singleton
     */
    const ModalManager = {
        activeModal: null,
        previousFocus: null,
        focusableSelectors: 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',

        /**
         * Initialize modal functionality
         * Call this on page load
         */
        init() {
            this.attachEventListeners();
            this.setupMutationObserver();
        },

        /**
         * Attach global event listeners
         */
        attachEventListeners() {
            // Global ESC key handler
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.activeModal) {
                    e.preventDefault();
                    this.close(this.activeModal);
                }
            });

            // Close on overlay click
            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('modal-overlay') && this.activeModal) {
                    this.close(this.activeModal);
                }
            });
        },

        /**
         * Setup mutation observer to watch for dynamically added modals
         */
        setupMutationObserver() {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            if (node.classList && node.classList.contains('modal-overlay')) {
                                this.initializeModal(node);
                            } else if (node.querySelector) {
                                const modals = node.querySelectorAll('.modal-overlay');
                                modals.forEach(modal => this.initializeModal(modal));
                            }
                        }
                    });
                });
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        },

        /**
         * Initialize a single modal element
         * @param {HTMLElement} modalOverlay - The modal overlay element
         */
        initializeModal(modalOverlay) {
            const modalDialog = modalOverlay.querySelector('.modal-dialog');
            if (!modalDialog) return;

            // Set ARIA attributes
            modalDialog.setAttribute('role', 'dialog');
            modalDialog.setAttribute('aria-modal', 'true');

            // Set aria-labelledby if modal has a title
            const modalTitle = modalDialog.querySelector('.modal-title');
            if (modalTitle) {
                const titleId = modalTitle.id || `modal-title-${Date.now()}`;
                modalTitle.id = titleId;
                modalDialog.setAttribute('aria-labelledby', titleId);
            }

            // Set aria-describedby if modal has a description
            const modalBody = modalDialog.querySelector('.modal-body');
            if (modalBody) {
                const bodyId = modalBody.id || `modal-body-${Date.now()}`;
                modalBody.id = bodyId;
                modalDialog.setAttribute('aria-describedby', bodyId);
            }

            // Attach close button handlers
            const closeButtons = modalDialog.querySelectorAll('[data-modal-close]');
            closeButtons.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.close(modalOverlay);
                });
            });

            // Handle forms inside modals
            const forms = modalDialog.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', (e) => {
                    // Allow HTMX to handle the submit
                    // Modal will close via HTMX response or explicit close call
                });
            });
        },

        /**
         * Open a modal
         * @param {HTMLElement|string} modalOrSelector - Modal element or selector
         */
        open(modalOrSelector) {
            const modal = typeof modalOrSelector === 'string'
                ? document.querySelector(modalOrSelector)
                : modalOrSelector;

            if (!modal) return;

            // Store currently focused element
            this.previousFocus = document.activeElement;

            // Set as active modal
            this.activeModal = modal;

            // Show modal
            modal.classList.add('show');
            modal.style.display = 'flex';

            // Prevent body scroll
            document.body.style.overflow = 'hidden';

            // Focus first focusable element in modal
            setTimeout(() => {
                this.trapFocus(modal);
                this.focusFirstElement(modal);
            }, 100); // Small delay to allow CSS transitions

            // Announce to screen readers
            this.announceModal(modal, 'opened');
        },

        /**
         * Close a modal
         * @param {HTMLElement|string} modalOrSelector - Modal element or selector
         */
        close(modalOrSelector) {
            const modal = typeof modalOrSelector === 'string'
                ? document.querySelector(modalOrSelector)
                : modalOrSelector;

            if (!modal) return;

            // Hide modal
            modal.classList.remove('show');

            // Wait for CSS transition before hiding
            setTimeout(() => {
                modal.style.display = 'none';

                // Restore body scroll
                document.body.style.overflow = '';

                // Restore focus to previously focused element
                if (this.previousFocus && this.previousFocus.focus) {
                    this.previousFocus.focus();
                }

                // Clear active modal
                if (this.activeModal === modal) {
                    this.activeModal = null;
                }

                // Announce to screen readers
                this.announceModal(modal, 'closed');
            }, 300); // Match CSS transition duration
        },

        /**
         * Set up focus trap within modal
         * @param {HTMLElement} modal - Modal element
         */
        trapFocus(modal) {
            const modalDialog = modal.querySelector('.modal-dialog');
            if (!modalDialog) return;

            const focusableElements = modalDialog.querySelectorAll(this.focusableSelectors);
            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            // Remove existing listener if any
            if (modalDialog._focusTrapHandler) {
                modalDialog.removeEventListener('keydown', modalDialog._focusTrapHandler);
            }

            // Create focus trap handler
            const focusTrapHandler = (e) => {
                if (e.key !== 'Tab') return;

                // Shift + Tab (backwards)
                if (e.shiftKey) {
                    if (document.activeElement === firstFocusable) {
                        e.preventDefault();
                        lastFocusable.focus();
                    }
                }
                // Tab (forwards)
                else {
                    if (document.activeElement === lastFocusable) {
                        e.preventDefault();
                        firstFocusable.focus();
                    }
                }
            };

            // Store handler reference for cleanup
            modalDialog._focusTrapHandler = focusTrapHandler;

            // Attach handler
            modalDialog.addEventListener('keydown', focusTrapHandler);
        },

        /**
         * Focus first focusable element in modal
         * @param {HTMLElement} modal - Modal element
         */
        focusFirstElement(modal) {
            const modalDialog = modal.querySelector('.modal-dialog');
            if (!modalDialog) return;

            const focusableElements = modalDialog.querySelectorAll(this.focusableSelectors);
            if (focusableElements.length > 0) {
                focusableElements[0].focus();
            }
        },

        /**
         * Announce modal state to screen readers
         * @param {HTMLElement} modal - Modal element
         * @param {string} state - 'opened' or 'closed'
         */
        announceModal(modal, state) {
            const modalDialog = modal.querySelector('.modal-dialog');
            if (!modalDialog) return;

            const title = modalDialog.querySelector('.modal-title')?.textContent || 'Dialog';
            const announcement = `${title} ${state}`;

            // Create live region for announcement
            const liveRegion = document.createElement('div');
            liveRegion.setAttribute('role', 'status');
            liveRegion.setAttribute('aria-live', 'polite');
            liveRegion.className = 'sr-only';
            liveRegion.textContent = announcement;

            document.body.appendChild(liveRegion);

            // Remove after announcement
            setTimeout(() => {
                document.body.removeChild(liveRegion);
            }, 1000);
        },

        /**
         * Handle keyboard repositioning on mobile
         * Adjusts modal position when virtual keyboard appears
         */
        handleMobileKeyboard() {
            if (!this.activeModal) return;

            const modalDialog = this.activeModal.querySelector('.modal-dialog');
            if (!modalDialog) return;

            // Check if we're on mobile
            const isMobile = window.innerWidth <= 768;
            if (!isMobile) return;

            // Use visualViewport API if available
            if (window.visualViewport) {
                const updatePosition = () => {
                    const viewportHeight = window.visualViewport.height;
                    const windowHeight = window.innerHeight;
                    const keyboardHeight = windowHeight - viewportHeight;

                    if (keyboardHeight > 100) {
                        // Keyboard is visible
                        modalDialog.style.transform = `translateY(-${keyboardHeight / 2}px)`;
                    } else {
                        // Keyboard is hidden
                        modalDialog.style.transform = '';
                    }
                };

                window.visualViewport.addEventListener('resize', updatePosition);
                window.visualViewport.addEventListener('scroll', updatePosition);
            } else {
                // Fallback: scroll focused input into view
                const inputs = modalDialog.querySelectorAll('input, textarea, select');
                inputs.forEach(input => {
                    input.addEventListener('focus', () => {
                        setTimeout(() => {
                            input.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        }, 300);
                    });
                });
            }
        }
    };

    /**
     * Global API
     */
    window.Modal = {
        open: (selector) => ModalManager.open(selector),
        close: (selector) => ModalManager.close(selector)
    };

    /**
     * Initialize on DOM ready
     */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            ModalManager.init();
        });
    } else {
        ModalManager.init();
    }

    /**
     * HTMX integration
     * Automatically show modals that arrive via HTMX
     */
    document.body.addEventListener('htmx:afterSwap', (event) => {
        const newContent = event.detail.target;
        const modals = newContent.querySelectorAll('.modal-overlay');

        modals.forEach(modal => {
            // Auto-open modals that have data-auto-open attribute
            if (modal.hasAttribute('data-auto-open')) {
                setTimeout(() => ModalManager.open(modal), 50);
            }
        });
    });

    /**
     * Handle mobile keyboard adjustments
     */
    document.addEventListener('focusin', (e) => {
        if (ModalManager.activeModal && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) {
            ModalManager.handleMobileKeyboard();
        }
    });

})();
