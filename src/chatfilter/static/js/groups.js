// Global function for handling CSV export download
// Extracted from group_card.html to prevent re-execution on every HTMX swap
window.handleExportDownload = async function(button) {
    const groupId = button.dataset.groupId;
    const groupName = button.dataset.groupName;
    const url = '/api/groups/' + groupId + '/export';

    try {
        const response = await fetch(url);

        if (response.ok) {
            // Success - trigger download
            const blob = await response.blob();
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = groupName.replace(/\s/g, '_') + '.csv';

            // Extract filename from Content-Disposition if present
            if (contentDisposition) {
                const matches = /filename="([^"]+)"/.exec(contentDisposition);
                if (matches && matches[1]) {
                    filename = matches[1];
                }
            }

            // Create download link and trigger
            const downloadUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(downloadUrl);
        } else {
            // Error - show toast
            let errorMessage = 'Failed to export results';

            try {
                const errorData = await response.json();
                errorMessage = errorData.detail || errorMessage;
            } catch (e) {
                // Not JSON, use status text
                errorMessage = response.statusText || errorMessage;
            }

            ToastManager.error(errorMessage, {
                title: 'Export Failed',
                duration: 5000
            });
        }
    } catch (error) {
        console.error('Export error:', error);
        ToastManager.error('Network error while downloading export', {
            title: 'Export Failed',
            duration: 5000
        });
    }
};
