// Configure HTMX to include CSRF token in all POST/DELETE requests
document.addEventListener('DOMContentLoaded', function() {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

    if (csrfToken) {
        // Add CSRF token to all HTMX requests
        document.body.addEventListener('htmx:configRequest', function(event) {
            // Only add token to POST/PUT/DELETE requests
            if (event.detail.verb === 'post' || event.detail.verb === 'put' || event.detail.verb === 'delete') {
                event.detail.headers['X-CSRF-Token'] = csrfToken;
            }
        });
    } else {
        console.warn('CSRF token not found in page meta tags');
    }
});
