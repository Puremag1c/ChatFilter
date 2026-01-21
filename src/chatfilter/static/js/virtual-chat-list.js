/**
 * Virtual Scrolling for Chat List
 *
 * Implements virtual scrolling using HyperList to efficiently render
 * large chat lists (1000+ items) without performance degradation.
 */

class VirtualChatList {
    constructor() {
        this.chats = [];
        this.filteredChats = [];
        this.selectedIds = new Set();
        this.hyperlist = null;
        this.container = null;
        this.config = null;
        this.searchQuery = '';
        this.typeFilter = '';
    }

    /**
     * Initialize the virtual chat list
     * @param {HTMLElement} container - Container element for the chat list
     * @param {Array} chats - Array of chat objects
     * @param {Object} config - Configuration options
     */
    init(container, chats, config = {}) {
        this.container = container;
        this.chats = chats;
        this.filteredChats = [...chats];
        this.config = {
            itemHeight: config.itemHeight || 70, // Height of each chat item in pixels
            onSelectionChange: config.onSelectionChange || (() => {}),
            ...config
        };

        // Create the virtual scrolling container
        this.setupContainer();

        // Initialize HyperList
        this.initHyperList();

        // Setup event listeners
        this.setupEventListeners();
    }

    /**
     * Setup the container for virtual scrolling
     */
    setupContainer() {
        // Set container height based on visible items (max 10 items visible)
        const visibleItems = Math.min(this.filteredChats.length, 10);
        const containerHeight = visibleItems * this.config.itemHeight;

        this.container.style.height = `${containerHeight}px`;
        this.container.style.overflow = 'auto';
        this.container.style.position = 'relative';
    }

    /**
     * Initialize HyperList for virtual scrolling
     */
    initHyperList() {
        if (typeof HyperList === 'undefined') {
            console.error('HyperList library not loaded');
            return;
        }

        const config = {
            itemHeight: this.config.itemHeight,
            total: this.filteredChats.length,
            generate: (index) => this.generateChatItem(index),
            afterRender: () => {
                // Re-attach event listeners after render
                this.attachCheckboxListeners();
            }
        };

        this.hyperlist = HyperList.create(this.container, config);
    }

    /**
     * Generate a chat item DOM element
     * @param {number} index - Index of the chat in filteredChats array
     * @returns {HTMLElement} The chat item element
     */
    generateChatItem(index) {
        const chat = this.filteredChats[index];
        if (!chat) return document.createElement('div');

        const label = document.createElement('label');
        label.className = 'chat-item';
        label.dataset.title = chat.title || '';
        label.dataset.username = chat.username || '';
        label.dataset.type = chat.chat_type || '';
        label.dataset.chatId = chat.id;

        // Create checkbox
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'chat-checkbox';
        checkbox.name = 'chat_ids';
        checkbox.value = chat.id;
        checkbox.checked = this.selectedIds.has(chat.id);

        // Create chat info container
        const chatInfo = document.createElement('div');
        chatInfo.className = 'chat-info';

        // Chat title
        const chatTitle = document.createElement('div');
        chatTitle.className = 'chat-title';
        chatTitle.textContent = chat.title || 'Unnamed Chat';
        chatTitle.title = chat.title || '';

        // Chat metadata
        const chatMeta = document.createElement('div');
        chatMeta.className = 'chat-meta';

        // Chat type badge
        const chatType = document.createElement('span');
        chatType.className = `chat-type ${chat.chat_type || ''}`;
        chatType.textContent = chat.chat_type || '';
        chatMeta.appendChild(chatType);

        // Username
        if (chat.username) {
            const username = document.createElement('span');
            username.textContent = `@${chat.username}`;
            chatMeta.appendChild(username);
        }

        // Member count
        if (chat.member_count) {
            const memberCount = document.createElement('span');
            memberCount.textContent = `${chat.member_count} members`;
            chatMeta.appendChild(memberCount);
        }

        // Assemble the DOM
        chatInfo.appendChild(chatTitle);
        chatInfo.appendChild(chatMeta);
        label.appendChild(checkbox);
        label.appendChild(chatInfo);

        // Add selected class if checked
        if (this.selectedIds.has(chat.id)) {
            label.classList.add('selected');
        }

        return label;
    }

    /**
     * Attach event listeners to checkboxes
     */
    attachCheckboxListeners() {
        const checkboxes = this.container.querySelectorAll('.chat-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const chatId = e.target.value;
                const label = e.target.closest('.chat-item');

                if (e.target.checked) {
                    this.selectedIds.add(chatId);
                    label?.classList.add('selected');
                } else {
                    this.selectedIds.delete(chatId);
                    label?.classList.remove('selected');
                }

                this.config.onSelectionChange(this.selectedIds);
            });
        });
    }

    /**
     * Setup global event listeners
     */
    setupEventListeners() {
        // Handle checkbox changes via event delegation
        this.container.addEventListener('change', (e) => {
            if (e.target.classList.contains('chat-checkbox')) {
                const chatId = e.target.value;
                const label = e.target.closest('.chat-item');

                if (e.target.checked) {
                    this.selectedIds.add(chatId);
                    label?.classList.add('selected');
                } else {
                    this.selectedIds.delete(chatId);
                    label?.classList.remove('selected');
                }

                this.config.onSelectionChange(this.selectedIds);
            }
        });
    }

    /**
     * Apply search and filter
     * @param {string} searchQuery - Search query string
     * @param {string} typeFilter - Chat type filter
     */
    applyFilters(searchQuery = '', typeFilter = '') {
        this.searchQuery = searchQuery.toLowerCase();
        this.typeFilter = typeFilter;

        this.filteredChats = this.chats.filter(chat => {
            const title = (chat.title || '').toLowerCase();
            const username = (chat.username || '').toLowerCase();
            const chatType = chat.chat_type || '';

            const matchesSearch = !this.searchQuery ||
                                title.includes(this.searchQuery) ||
                                username.includes(this.searchQuery);

            const matchesType = !this.typeFilter || chatType === this.typeFilter;

            return matchesSearch && matchesType;
        });

        this.refresh();
    }

    /**
     * Select all visible (filtered) chats
     */
    selectAll() {
        this.filteredChats.forEach(chat => {
            this.selectedIds.add(chat.id);
        });
        this.refresh();
        this.config.onSelectionChange(this.selectedIds);
    }

    /**
     * Deselect all chats
     */
    selectNone() {
        this.selectedIds.clear();
        this.refresh();
        this.config.onSelectionChange(this.selectedIds);
    }

    /**
     * Add more chats to the list (for pagination)
     * @param {Array} newChats - Array of new chat objects to add
     */
    addChats(newChats) {
        this.chats = [...this.chats, ...newChats];
        this.applyFilters(this.searchQuery, this.typeFilter);
    }

    /**
     * Refresh the virtual list
     */
    refresh() {
        if (!this.hyperlist) return;

        // Update container height
        const visibleItems = Math.min(this.filteredChats.length, 10);
        const containerHeight = visibleItems * this.config.itemHeight;
        this.container.style.height = `${containerHeight}px`;

        // Refresh HyperList with new data
        this.hyperlist.refresh(this.container, {
            itemHeight: this.config.itemHeight,
            total: this.filteredChats.length,
            generate: (index) => this.generateChatItem(index)
        });
    }

    /**
     * Get the count of selected chats
     * @returns {number} Number of selected chats
     */
    getSelectionCount() {
        return this.selectedIds.size;
    }

    /**
     * Get the count of visible (filtered) chats
     * @returns {number} Number of visible chats
     */
    getVisibleCount() {
        return this.filteredChats.length;
    }

    /**
     * Get the total count of all chats
     * @returns {number} Total number of chats
     */
    getTotalCount() {
        return this.chats.length;
    }

    /**
     * Get array of selected chat IDs
     * @returns {Array<string>} Array of selected chat IDs
     */
    getSelectedIds() {
        return Array.from(this.selectedIds);
    }

    /**
     * Destroy the virtual list and cleanup
     */
    destroy() {
        if (this.hyperlist && this.hyperlist.destroy) {
            this.hyperlist.destroy();
        }
        this.hyperlist = null;
        this.chats = [];
        this.filteredChats = [];
        this.selectedIds.clear();
    }
}

// Make VirtualChatList globally accessible
window.VirtualChatList = VirtualChatList;
