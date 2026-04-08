/**
 * Proxy Form Modal
 *
 * Handles proxy CRUD operations via modal form.
 * Provides global ProxyFormModal for add/edit/delete operations.
 *
 * Dependencies: i18n.js, toast-manager.js, modal-manager.js, htmx
 * Exposes: window.ProxyFormModal
 */
(function() {
    'use strict';

    // i18n helper - fallback to key if i18n not loaded
    var t = function(key, params) {
        return window.i18n ? window.i18n.t(key, params) : key;
    };

    const ProxyFormModal = {
        overlay: null,
        form: null,
        titleEl: null,
        submitBtn: null,
        cancelBtn: null,
        isEditing: false,
        editingProxyId: null,
        trapFocusHandler: null,

        init() {
            // Guard: only initialize if proxy form elements exist on this page
            if (!document.getElementById('add-proxy-btn')) {
                return;
            }
            this.overlay = document.getElementById('proxy-form-overlay');
            this.form = document.getElementById('proxy-form');
            this.titleEl = document.getElementById('proxy-modal-title');
            this.submitBtn = document.getElementById('proxy-form-submit');
            this.cancelBtn = document.getElementById('proxy-form-cancel');

            // Open modal for adding
            document.getElementById('add-proxy-btn').addEventListener('click', () => this.openForAdd());

            // Close modal handlers
            this.cancelBtn.addEventListener('click', () => this.close());
            this.overlay.addEventListener('click', (e) => {
                if (e.target === this.overlay) this.close();
            });
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && this.overlay.classList.contains('show')) {
                    this.close();
                }
            });

            // Form submission
            this.form.addEventListener('submit', (e) => this.handleSubmit(e));

            // Real-time validation
            this.form.querySelectorAll('input[required], select[required]').forEach(input => {
                input.addEventListener('blur', () => this.validateField(input));
                input.addEventListener('input', () => this.clearFieldError(input));
            });
        },

        openForAdd() {
            this.isEditing = false;
            this.editingProxyId = null;
            this.titleEl.textContent = t('proxy.form.add_proxy');
            this.submitBtn.querySelector('.btn-text').textContent = t('proxy.form.add_proxy');
            this.form.reset();
            document.getElementById('proxy-id').value = '';
            this.clearAllErrors();
            this.show();
        },

        openForEdit(proxy) {
            this.isEditing = true;
            this.editingProxyId = proxy.id;
            this.titleEl.textContent = t('proxy.form.edit_proxy');
            this.submitBtn.querySelector('.btn-text').textContent = t('proxy.form.save_changes');

            // Fill form with proxy data
            document.getElementById('proxy-id').value = proxy.id;
            document.getElementById('proxy-name').value = proxy.name;
            document.getElementById('proxy-type').value = proxy.type;
            document.getElementById('proxy-host').value = proxy.host;
            document.getElementById('proxy-port').value = proxy.port;
            document.getElementById('proxy-username').value = proxy.username || '';
            document.getElementById('proxy-password').value = ''; // Don't fill password for security

            this.clearAllErrors();
            this.show();
        },

        show() {
            this.overlay.classList.add('show');
            document.getElementById('proxy-name').focus();
            // Trap focus within modal
            this.trapFocus();
        },

        close() {
            this.overlay.classList.remove('show');
            this.form.reset();
            this.clearAllErrors();
            // Remove trap focus handler
            if (this.trapFocusHandler) {
                this.overlay.removeEventListener('keydown', this.trapFocusHandler);
                this.trapFocusHandler = null;
            }
        },

        trapFocus() {
            const focusableElements = this.overlay.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusableElements.length === 0) return;

            const firstFocusable = focusableElements[0];
            const lastFocusable = focusableElements[focusableElements.length - 1];

            // Remove old handler to prevent listener leak
            if (this.trapFocusHandler) {
                this.overlay.removeEventListener('keydown', this.trapFocusHandler);
            }

            // Create new handler
            this.trapFocusHandler = function(e) {
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
            };

            this.overlay.addEventListener('keydown', this.trapFocusHandler);
        },

        validateField(input) {
            const errorEl = document.getElementById(`${input.id}-error`);
            let error = '';

            if (input.validity.valueMissing) {
                error = t('proxy.validation.field_required');
            } else if (input.validity.tooShort) {
                error = `${t('proxy.validation.min_length')} ${input.minLength} ${t('proxy.validation.characters')}`;
            } else if (input.validity.tooLong) {
                error = `${t('proxy.validation.max_length')} ${input.maxLength} ${t('proxy.validation.characters')}`;
            } else if (input.validity.rangeUnderflow) {
                error = `${t('proxy.validation.min_value')} ${input.min}`;
            } else if (input.validity.rangeOverflow) {
                error = `${t('proxy.validation.max_value')} ${input.max}`;
            } else if (input.id === 'proxy-host' && input.value.includes(' ')) {
                error = t('proxy.validation.host_no_spaces');
            }

            if (errorEl) {
                errorEl.textContent = error;
                input.classList.toggle('invalid', !!error);
            }

            return !error;
        },

        clearFieldError(input) {
            const errorEl = document.getElementById(`${input.id}-error`);
            if (errorEl) errorEl.textContent = '';
            input.classList.remove('invalid');
        },

        clearAllErrors() {
            this.form.querySelectorAll('.field-error').forEach(el => el.textContent = '');
            this.form.querySelectorAll('.invalid').forEach(el => el.classList.remove('invalid'));
        },

        validateForm() {
            let isValid = true;
            this.form.querySelectorAll('input[required], select[required]').forEach(input => {
                if (!this.validateField(input)) {
                    isValid = false;
                }
            });

            // Additional custom validation for host
            const hostInput = document.getElementById('proxy-host');
            if (hostInput.value.includes(' ')) {
                const errorEl = document.getElementById('proxy-host-error');
                if (errorEl) errorEl.textContent = t('proxy.validation.host_no_spaces');
                hostInput.classList.add('invalid');
                isValid = false;
            }

            return isValid;
        },

        async handleSubmit(e) {
            e.preventDefault();

            if (!this.validateForm()) {
                window.ToastManager.warning(t('proxy.validation.fix_errors'), {
                    title: t('proxy.validation.error_title'),
                    duration: 3000
                });
                return;
            }

            const formData = {
                name: document.getElementById('proxy-name').value.trim(),
                type: document.getElementById('proxy-type').value,
                host: document.getElementById('proxy-host').value.trim(),
                port: parseInt(document.getElementById('proxy-port').value, 10),
                username: document.getElementById('proxy-username').value.trim(),
                password: document.getElementById('proxy-password').value
            };

            this.submitBtn.disabled = true;
            document.getElementById('proxy-form-spinner').style.display = 'inline-block';

            try {
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                const url = this.isEditing ? `/api/proxies/${this.editingProxyId}` : '/api/proxies';
                const method = this.isEditing ? 'PUT' : 'POST';

                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(formData)
                });

                const data = await response.json();

                if (!response.ok || !data.success) {
                    throw new Error(data.error || t('proxy.messages.operation_failed'));
                }

                this.close();
                htmx.trigger('#proxy-list', 'refresh');

                const successMsg = this.isEditing
                    ? t('proxy.messages.updated_successfully')
                    : t('proxy.messages.added_successfully');
                window.ToastManager.success(successMsg, {
                    title: this.isEditing ? t('proxy.messages.proxy_updated') : t('proxy.messages.proxy_added'),
                    duration: 3000
                });

            } catch (error) {
                console.error('Failed to save proxy:', error);
                window.ToastManager.error(error.message, {
                    title: t('proxy.messages.save_failed'),
                    duration: 8000
                });
            } finally {
                this.submitBtn.disabled = false;
                document.getElementById('proxy-form-spinner').style.display = 'none';
            }
        }
    };

    document.addEventListener('DOMContentLoaded', function() {
        ProxyFormModal.init();

        // Handle proxy edit button
        document.body.addEventListener('click', async function(e) {
            const editBtn = e.target.closest('.proxy-edit-btn');
            if (editBtn) {
                e.preventDefault();
                const proxyData = {
                    id: editBtn.dataset.proxyId,
                    name: editBtn.dataset.proxyName,
                    type: editBtn.dataset.proxyType,
                    host: editBtn.dataset.proxyHost,
                    port: editBtn.dataset.proxyPort,
                    username: editBtn.dataset.proxyUsername || ''
                };
                ProxyFormModal.openForEdit(proxyData);
                return;
            }

            // Handle proxy deletion with conditional confirmation
            const deleteBtn = e.target.closest('.proxy-delete-btn');
            if (!deleteBtn) return;

            e.preventDefault();
            const proxyId = deleteBtn.dataset.proxyId;
            const proxyName = deleteBtn.dataset.proxyName;
            const usageCount = parseInt(deleteBtn.dataset.proxyUsageCount || '0', 10);

            // Show confirmation only if proxy is used by sessions
            if (usageCount > 0) {
                const confirmed = await window.ModalManager.confirm({
                    type: 'danger',
                    icon: '<span class="i i-alert-triangle"></span>',
                    title: t('proxy.delete.title'),
                    message: `${t('proxy.delete.used_by_prefix')} ${usageCount} ${t('proxy.delete.used_by_suffix')}`,
                    confirmText: t('proxy.delete.confirm'),
                    cancelText: t('proxy.delete.cancel'),
                    confirmClass: 'danger'
                });

                if (!confirmed) return;
            }

            deleteBtn.disabled = true;
            try {
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                const response = await fetch(`/api/proxies/${proxyId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRF-Token': csrfToken
                    }
                });

                const data = await response.json();

                if (!response.ok || !data.success) {
                    throw new Error(data.error || 'Delete failed');
                }

                // Refresh the list
                htmx.trigger('#proxy-list', 'refresh');

                window.ToastManager.success(t('proxy.delete.success'), {
                    title: t('proxy.delete.success_title'),
                    duration: 3000
                });

            } catch (error) {
                console.error('Failed to delete proxy:', error);
                window.ToastManager.error(error.message, {
                    title: t('proxy.delete.failed'),
                    duration: 8000
                });
            } finally {
                deleteBtn.disabled = false;
            }
        });
    });

    // Make ProxyFormModal globally accessible
    window.ProxyFormModal = ProxyFormModal;
})();
