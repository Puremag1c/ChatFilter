/**
 * Session configuration form handling
 * Disables form during API credential validation
 */

document.addEventListener('DOMContentLoaded', function() {
    // Listen for HTMX events on session config forms
    document.body.addEventListener('htmx:beforeRequest', function(evt) {
        const form = evt.detail.elt;

        // Check if this is a session config form
        if (form && form.classList.contains('session-config-form')) {
            // Disable all form inputs and buttons
            const inputs = form.querySelectorAll('input, select, button');
            inputs.forEach(input => {
                input.disabled = true;
            });

            // Add visual feedback class
            form.classList.add('form-submitting');
        }
    });

    document.body.addEventListener('htmx:afterRequest', function(evt) {
        const form = evt.detail.elt;

        // Check if this is a session config form
        if (form && form.classList.contains('session-config-form')) {
            // Re-enable all form inputs and buttons
            const inputs = form.querySelectorAll('input, select, button');
            inputs.forEach(input => {
                input.disabled = false;
            });

            // Remove visual feedback class
            form.classList.remove('form-submitting');
        }
    });
});
