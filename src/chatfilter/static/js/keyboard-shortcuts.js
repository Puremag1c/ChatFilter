/**
 * Keyboard Shortcuts Manager for ChatFilter
 *
 * Provides keyboard shortcuts for common operations throughout the application.
 * Press '?' to see all available shortcuts.
 */

const KeyboardShortcuts = {
    // Track if help modal is open
    helpModalOpen: false,

    // Current page context (detected from URL)
    currentPage: '',

    /**
     * Initialize keyboard shortcuts
     */
    init() {
        this.detectCurrentPage();
        this.attachEventListeners();
        this.createHelpModal();
        console.log('Keyboard shortcuts initialized');
    },

    /**
     * Detect current page from URL
     */
    detectCurrentPage() {
        const path = window.location.pathname;
        if (path === '/' || path === '/upload') {
            this.currentPage = 'sessions';
        } else if (path === '/chats') {
            this.currentPage = 'chats';
        } else if (path === '/chatlist') {
            this.currentPage = 'import';
        } else if (path === '/results') {
            this.currentPage = 'results';
        } else if (path === '/history') {
            this.currentPage = 'history';
        } else if (path === '/proxy') {
            this.currentPage = 'proxy';
        }
    },

    /**
     * Attach global keyboard event listeners
     */
    attachEventListeners() {
        document.addEventListener('keydown', (e) => this.handleKeydown(e));
    },

    /**
     * Main keydown handler
     */
    handleKeydown(e) {
        // Don't intercept if user is typing in an input/textarea (except for specific shortcuts)
        const isInputField = e.target.tagName === 'INPUT' ||
                            e.target.tagName === 'TEXTAREA' ||
                            e.target.tagName === 'SELECT' ||
                            e.target.isContentEditable;

        // Check for help shortcut (? or Shift+/)
        if (e.key === '?' || (e.shiftKey && e.key === '/')) {
            e.preventDefault();
            this.toggleHelpModal();
            return;
        }

        // Handle Escape key
        if (e.key === 'Escape') {
            this.handleEscape(e);
            return;
        }

        // Handle Ctrl/Cmd+Enter for form submission
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            this.handleFormSubmit(e);
            return;
        }

        // Navigation shortcuts (Alt+Number)
        if (e.altKey && !e.ctrlKey && !e.metaKey) {
            const handled = this.handleNavigationShortcut(e);
            if (handled) return;
        }

        // Don't handle other shortcuts if in input field
        if (isInputField) {
            // Exception: Allow Ctrl/Cmd shortcuts even in input fields
            if (!e.ctrlKey && !e.metaKey) {
                return;
            }
        }

        // Handle forward slash for search
        if (e.key === '/' && !isInputField) {
            e.preventDefault();
            this.focusSearch();
            return;
        }

        // Handle Ctrl/Cmd shortcuts
        if (e.ctrlKey || e.metaKey) {
            const handled = this.handleCtrlShortcut(e);
            if (handled) return;
        }
    },

    /**
     * Handle navigation shortcuts (Alt+Number)
     */
    handleNavigationShortcut(e) {
        const keyMap = {
            '1': '/',
            '2': '/chats',
            '3': '/chatlist',
            '4': '/results',
            '5': '/history',
            '6': '/proxy'
        };

        const url = keyMap[e.key];
        if (url) {
            e.preventDefault();
            window.location.href = url;
            return true;
        }
        return false;
    },

    /**
     * Handle Ctrl/Cmd shortcuts
     */
    handleCtrlShortcut(e) {
        // Ctrl/Cmd+F: Focus search
        if (e.key === 'f' || e.key === 'F') {
            e.preventDefault();
            this.focusSearch();
            return true;
        }

        // Ctrl/Cmd+A: Select all
        if (e.key === 'a' || e.key === 'A') {
            if (e.shiftKey) {
                // Ctrl/Cmd+Shift+A: Clear selection
                e.preventDefault();
                this.clearSelection();
            } else {
                // Check if we're in a text context
                const isTextContext = e.target.tagName === 'INPUT' ||
                                     e.target.tagName === 'TEXTAREA' ||
                                     e.target.isContentEditable;

                if (!isTextContext) {
                    e.preventDefault();
                    this.selectAll();
                }
            }
            return true;
        }

        // Ctrl/Cmd+Shift+T: Toggle theme
        if (e.shiftKey && (e.key === 't' || e.key === 'T')) {
            e.preventDefault();
            this.toggleTheme();
            return true;
        }

        // Ctrl/Cmd+Shift+L: Toggle language
        if (e.shiftKey && (e.key === 'l' || e.key === 'L')) {
            e.preventDefault();
            this.toggleLanguage();
            return true;
        }

        // Results page specific shortcuts
        if (this.currentPage === 'results') {
            // Ctrl/Cmd+E: Export CSV
            if (e.key === 'e' || e.key === 'E') {
                e.preventDefault();
                this.exportCSV();
                return true;
            }

            // Ctrl/Cmd+C: Copy selected rows
            if (e.key === 'c' || e.key === 'C') {
                if (e.shiftKey) {
                    // Ctrl/Cmd+Shift+C: Compare selected
                    e.preventDefault();
                    this.compareSelected();
                } else {
                    // Only handle if we have selected rows and not in text context
                    const hasSelectedRows = document.querySelectorAll('.chat-checkbox:checked').length > 0;
                    const isTextContext = e.target.tagName === 'INPUT' ||
                                         e.target.tagName === 'TEXTAREA' ||
                                         e.target.isContentEditable;

                    if (hasSelectedRows && !isTextContext) {
                        e.preventDefault();
                        this.copySelectedRows();
                    }
                }
                return true;
            }
        }

        return false;
    },

    /**
     * Handle Escape key
     */
    handleEscape(e) {
        // Close help modal if open
        if (this.helpModalOpen) {
            this.toggleHelpModal();
            return;
        }

        // Close compare modal if open
        const compareModal = document.getElementById('compare-modal');
        if (compareModal && compareModal.classList.contains('show')) {
            if (typeof closeCompareModal === 'function') {
                closeCompareModal();
            }
            return;
        }

        // Clear search if search field is focused
        const activeElement = document.activeElement;
        if (activeElement && (activeElement.id === 'chat-search' ||
                              activeElement.id === 'search-filter' ||
                              activeElement.type === 'search')) {
            activeElement.value = '';
            activeElement.blur();

            // Trigger input event to update filters
            activeElement.dispatchEvent(new Event('input', { bubbles: true }));
            return;
        }

        // Clear selection
        this.clearSelection();
    },

    /**
     * Focus search field
     */
    focusSearch() {
        // Try different search field IDs based on page
        const searchIds = ['chat-search', 'search-filter', 'search'];

        for (const id of searchIds) {
            const searchField = document.getElementById(id);
            if (searchField) {
                searchField.focus();
                searchField.select();
                return;
            }
        }

        // Try to find any input with type="search"
        const searchInput = document.querySelector('input[type="search"], input[placeholder*="search" i], input[placeholder*="Search"]');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
        }
    },

    /**
     * Select all visible items
     */
    selectAll() {
        const selectAllBtn = document.getElementById('select-all');
        if (selectAllBtn) {
            selectAllBtn.click();
            return;
        }

        // Try select-all checkbox
        const selectAllCheckbox = document.getElementById('select-all-checkbox');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
            return;
        }

        // Fallback: check all visible checkboxes
        const checkboxes = document.querySelectorAll('.chat-checkbox:not([disabled]), .entry-checkbox:not([disabled])');
        checkboxes.forEach(cb => {
            const row = cb.closest('tr, .chat-item, .entry-item');
            if (row && row.style.display !== 'none') {
                cb.checked = true;
            }
        });

        // Trigger change event on first checkbox to update UI
        if (checkboxes.length > 0) {
            checkboxes[0].dispatchEvent(new Event('change', { bubbles: true }));
        }
    },

    /**
     * Clear selection
     */
    clearSelection() {
        const selectNoneBtn = document.getElementById('select-none');
        if (selectNoneBtn) {
            selectNoneBtn.click();
            return;
        }

        // Try select-all checkbox
        const selectAllCheckbox = document.getElementById('select-all-checkbox');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
        }

        // Fallback: uncheck all checkboxes
        const checkboxes = document.querySelectorAll('.chat-checkbox, .entry-checkbox');
        checkboxes.forEach(cb => {
            cb.checked = false;
        });

        // Trigger change event to update UI
        if (checkboxes.length > 0) {
            checkboxes[0].dispatchEvent(new Event('change', { bubbles: true }));
        }
    },

    /**
     * Toggle theme
     */
    toggleTheme() {
        const themeToggleBtn = document.getElementById('theme-toggle');
        if (themeToggleBtn) {
            themeToggleBtn.click();
        }
    },

    /**
     * Toggle language
     */
    toggleLanguage() {
        const languageToggleBtn = document.getElementById('language-toggle');
        if (languageToggleBtn) {
            languageToggleBtn.click();
        }
    },

    /**
     * Submit active form
     */
    handleFormSubmit(e) {
        // Find the active form or form with analysis button
        const analysisBtn = document.querySelector('button[type="submit"][form="analysis-form"], button#start-analysis');
        if (analysisBtn) {
            e.preventDefault();
            analysisBtn.click();
            return;
        }

        // Find any submit button in a visible form
        const submitBtn = document.querySelector('form:not([style*="display: none"]) button[type="submit"]');
        if (submitBtn) {
            e.preventDefault();
            submitBtn.click();
        }
    },

    /**
     * Export CSV (results page)
     */
    exportCSV() {
        const exportBtn = document.getElementById('export-csv-btn');
        if (exportBtn) {
            exportBtn.click();
        }
    },

    /**
     * Copy selected rows (results page)
     */
    copySelectedRows() {
        const copyBtn = document.getElementById('copy-selected-btn');
        if (copyBtn && !copyBtn.disabled) {
            copyBtn.click();
        } else if (typeof copySelectedRows === 'function') {
            copySelectedRows();
        }
    },

    /**
     * Compare selected chats (results page)
     */
    compareSelected() {
        const compareBtn = document.getElementById('compare-selected-btn');
        if (compareBtn && !compareBtn.disabled) {
            compareBtn.click();
        }
    },

    /**
     * Create help modal for keyboard shortcuts
     */
    createHelpModal() {
        const modalHTML = `
            <div id="keyboard-shortcuts-modal" class="modal-overlay" style="display: none;" role="dialog" aria-modal="true" aria-labelledby="shortcuts-modal-title">
                <div class="modal-dialog" role="document" style="max-width: 700px;">
                    <div class="modal-header">
                        <h2 id="shortcuts-modal-title">Keyboard Shortcuts</h2>
                        <button class="modal-close" onclick="KeyboardShortcuts.toggleHelpModal()" aria-label="Close shortcuts help">&times;</button>
                    </div>
                    <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                        <div class="shortcuts-section">
                            <h3>Navigation</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>1</kbd></dt>
                                    <dd>Go to Sessions page</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>2</kbd></dt>
                                    <dd>Go to Chats page</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>3</kbd></dt>
                                    <dd>Go to Import page</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>4</kbd></dt>
                                    <dd>Go to Results page</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>5</kbd></dt>
                                    <dd>Go to History page</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Alt</kbd> + <kbd>6</kbd></dt>
                                    <dd>Go to Proxy page</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="shortcuts-section">
                            <h3>Selection</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>A</kbd></dt>
                                    <dd>Select all visible items</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>Shift</kbd> + <kbd>A</kbd></dt>
                                    <dd>Clear selection</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Esc</kbd></dt>
                                    <dd>Clear selection / Close modals</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="shortcuts-section">
                            <h3>Search & Filters</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>/</kbd></dt>
                                    <dd>Focus search field</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>F</kbd></dt>
                                    <dd>Focus search field</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Esc</kbd> (in search)</dt>
                                    <dd>Clear search and unfocus</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="shortcuts-section">
                            <h3>UI Controls</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>Shift</kbd> + <kbd>T</kbd></dt>
                                    <dd>Toggle dark/light theme</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>Shift</kbd> + <kbd>L</kbd></dt>
                                    <dd>Toggle language (EN/RU)</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>Enter</kbd></dt>
                                    <dd>Submit form / Start analysis</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="shortcuts-section">
                            <h3>Results Page</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>E</kbd></dt>
                                    <dd>Export results to CSV</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>C</kbd></dt>
                                    <dd>Copy selected rows</dd>
                                </div>
                                <div class="shortcut-item">
                                    <dt><kbd>Ctrl/Cmd</kbd> + <kbd>Shift</kbd> + <kbd>C</kbd></dt>
                                    <dd>Compare selected chats</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="shortcuts-section">
                            <h3>Help</h3>
                            <dl class="shortcuts-list">
                                <div class="shortcut-item">
                                    <dt><kbd>?</kbd></dt>
                                    <dd>Show/hide this help dialog</dd>
                                </div>
                            </dl>
                        </div>
                    </div>
                </div>
            </div>

            <style>
                #keyboard-shortcuts-modal .shortcuts-section {
                    margin-bottom: 1.5rem;
                }

                #keyboard-shortcuts-modal .shortcuts-section h3 {
                    margin: 0 0 0.75rem 0;
                    font-size: 1rem;
                    font-weight: 600;
                    color: #333;
                    border-bottom: 2px solid #e9ecef;
                    padding-bottom: 0.5rem;
                }

                #keyboard-shortcuts-modal .shortcuts-list {
                    display: grid;
                    gap: 0.5rem;
                    margin: 0;
                }

                #keyboard-shortcuts-modal .shortcut-item {
                    display: grid;
                    grid-template-columns: minmax(200px, auto) 1fr;
                    gap: 1rem;
                    align-items: center;
                    padding: 0.5rem;
                    border-radius: 4px;
                }

                #keyboard-shortcuts-modal .shortcut-item:hover {
                    background: #f8f9fa;
                }

                #keyboard-shortcuts-modal dt {
                    font-weight: 500;
                    display: flex;
                    gap: 0.25rem;
                    align-items: center;
                    flex-wrap: wrap;
                }

                #keyboard-shortcuts-modal dd {
                    margin: 0;
                    color: #666;
                }

                #keyboard-shortcuts-modal kbd {
                    display: inline-block;
                    padding: 0.25rem 0.5rem;
                    font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
                    font-size: 0.875rem;
                    color: #333;
                    background: #f8f9fa;
                    border: 1px solid #d1d5db;
                    border-radius: 4px;
                    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
                }

                #keyboard-shortcuts-modal .modal-close {
                    background: none;
                    border: none;
                    font-size: 2rem;
                    cursor: pointer;
                    color: #666;
                    padding: 0;
                    width: 32px;
                    height: 32px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    border-radius: 4px;
                }

                #keyboard-shortcuts-modal .modal-close:hover {
                    background: #f8f9fa;
                    color: #333;
                }

                #keyboard-shortcuts-modal .modal-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1.5rem;
                    padding-bottom: 1rem;
                    border-bottom: 2px solid #e9ecef;
                }

                #keyboard-shortcuts-modal .modal-header h2 {
                    margin: 0;
                    color: #333;
                }

                @media (max-width: 768px) {
                    #keyboard-shortcuts-modal .shortcut-item {
                        grid-template-columns: 1fr;
                        gap: 0.25rem;
                    }

                    #keyboard-shortcuts-modal .modal-dialog {
                        max-width: 95% !important;
                    }
                }
            </style>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
    },

    /**
     * Toggle help modal visibility
     */
    toggleHelpModal() {
        const modal = document.getElementById('keyboard-shortcuts-modal');
        if (!modal) return;

        if (this.helpModalOpen) {
            modal.style.display = 'none';
            this.helpModalOpen = false;
        } else {
            modal.style.display = 'flex';
            this.helpModalOpen = true;

            // Focus the close button for accessibility
            const closeBtn = modal.querySelector('.modal-close');
            if (closeBtn) {
                setTimeout(() => closeBtn.focus(), 100);
            }
        }
    }
};

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => KeyboardShortcuts.init());
} else {
    KeyboardShortcuts.init();
}

// Make globally accessible
window.KeyboardShortcuts = KeyboardShortcuts;
