/**
 * Tooltip Manager for ChatFilter
 * Provides accessible, keyboard-navigable tooltips with multiple positioning options
 */

const TooltipManager = {
    tooltips: new Map(),
    activeTooltip: null,
    showDelay: 400,
    hideDelay: 100,
    showTimer: null,
    hideTimer: null,

    /**
     * Initialize the tooltip system
     */
    init() {
        console.log('Initializing tooltip system');

        // Find all elements with data-tooltip attribute
        this.refreshTooltips();

        // Set up mutation observer to handle dynamically added tooltips
        this.setupMutationObserver();

        // Global event listeners for hiding tooltips
        document.addEventListener('scroll', () => this.hideAll(), { passive: true });
        window.addEventListener('resize', () => this.hideAll());

        // Escape key to close tooltips
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.activeTooltip) {
                this.hide(this.activeTooltip);
            }
        });
    },

    /**
     * Refresh tooltips - find and bind all tooltip elements
     */
    refreshTooltips() {
        const elements = document.querySelectorAll('[data-tooltip]');
        elements.forEach(element => this.bindTooltip(element));
    },

    /**
     * Set up mutation observer to handle dynamically added content
     */
    setupMutationObserver() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        // Check if the added node itself has a tooltip
                        if (node.hasAttribute && node.hasAttribute('data-tooltip')) {
                            this.bindTooltip(node);
                        }
                        // Check if any children have tooltips
                        if (node.querySelectorAll) {
                            const tooltipElements = node.querySelectorAll('[data-tooltip]');
                            tooltipElements.forEach(el => this.bindTooltip(el));
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
     * Bind tooltip to an element
     */
    bindTooltip(element) {
        // Skip if already bound
        if (this.tooltips.has(element)) {
            return;
        }

        const tooltipText = element.getAttribute('data-tooltip');
        const tooltipTitle = element.getAttribute('data-tooltip-title');
        const position = element.getAttribute('data-tooltip-position') || 'top';
        const variant = element.getAttribute('data-tooltip-variant') || 'default';

        if (!tooltipText) {
            return;
        }

        // Create tooltip element
        const tooltip = document.createElement('div');
        tooltip.className = `tooltip tooltip-${position}`;
        tooltip.setAttribute('role', 'tooltip');
        tooltip.setAttribute('aria-hidden', 'true');

        // Add variant class
        if (variant !== 'default') {
            tooltip.classList.add(`tooltip-${variant}`);
        }

        // Build tooltip content
        if (tooltipTitle) {
            tooltip.classList.add('tooltip-rich');
            tooltip.innerHTML = `
                <div class="tooltip-title">${this.escapeHtml(tooltipTitle)}</div>
                <div class="tooltip-text">${this.escapeHtml(tooltipText)}</div>
            `;
        } else {
            tooltip.textContent = tooltipText;
        }

        // Store tooltip reference
        this.tooltips.set(element, {
            element: tooltip,
            position: position,
            variant: variant
        });

        // Add ARIA attributes to the trigger element
        element.setAttribute('aria-describedby', this.getTooltipId(element));
        tooltip.id = this.getTooltipId(element);

        // Event listeners
        element.addEventListener('mouseenter', () => this.scheduleShow(element));
        element.addEventListener('mouseleave', () => this.scheduleHide(element));
        element.addEventListener('focus', () => this.scheduleShow(element));
        element.addEventListener('blur', () => this.scheduleHide(element));

        // For touch devices
        element.addEventListener('touchstart', (e) => {
            // Prevent default to avoid triggering hover on touch
            e.preventDefault();
            this.toggle(element);
        }, { passive: false });
    },

    /**
     * Generate unique ID for tooltip
     */
    getTooltipId(element) {
        if (!element._tooltipId) {
            element._tooltipId = `tooltip-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        }
        return element._tooltipId;
    },

    /**
     * Schedule showing a tooltip
     */
    scheduleShow(element) {
        // Clear any pending hide
        if (this.hideTimer) {
            clearTimeout(this.hideTimer);
            this.hideTimer = null;
        }

        // If already showing, don't delay
        if (this.activeTooltip === element) {
            return;
        }

        // Schedule show
        this.showTimer = setTimeout(() => {
            this.show(element);
        }, this.showDelay);
    },

    /**
     * Schedule hiding a tooltip
     */
    scheduleHide(element) {
        // Clear any pending show
        if (this.showTimer) {
            clearTimeout(this.showTimer);
            this.showTimer = null;
        }

        // Schedule hide
        this.hideTimer = setTimeout(() => {
            this.hide(element);
        }, this.hideDelay);
    },

    /**
     * Show tooltip
     */
    show(element) {
        // Hide any active tooltip
        if (this.activeTooltip && this.activeTooltip !== element) {
            this.hide(this.activeTooltip);
        }

        const tooltipData = this.tooltips.get(element);
        if (!tooltipData) {
            return;
        }

        const tooltip = tooltipData.element;

        // Append to body if not already
        if (!tooltip.parentElement) {
            document.body.appendChild(tooltip);
        }

        // Position the tooltip
        this.position(element, tooltip, tooltipData.position);

        // Show tooltip
        requestAnimationFrame(() => {
            tooltip.classList.add('show');
            tooltip.setAttribute('aria-hidden', 'false');
        });

        this.activeTooltip = element;
    },

    /**
     * Hide tooltip
     */
    hide(element) {
        const tooltipData = this.tooltips.get(element);
        if (!tooltipData) {
            return;
        }

        const tooltip = tooltipData.element;
        tooltip.classList.remove('show');
        tooltip.setAttribute('aria-hidden', 'true');

        if (this.activeTooltip === element) {
            this.activeTooltip = null;
        }
    },

    /**
     * Toggle tooltip visibility
     */
    toggle(element) {
        if (this.activeTooltip === element) {
            this.hide(element);
        } else {
            this.show(element);
        }
    },

    /**
     * Hide all tooltips
     */
    hideAll() {
        this.tooltips.forEach((tooltipData, element) => {
            this.hide(element);
        });
    },

    /**
     * Position tooltip relative to element
     */
    position(element, tooltip, preferredPosition) {
        const rect = element.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();
        const scrollX = window.pageXOffset || document.documentElement.scrollLeft;
        const scrollY = window.pageYOffset || document.documentElement.scrollTop;

        let position = preferredPosition;
        let top = 0;
        let left = 0;

        // Calculate positions for each direction
        const positions = {
            top: {
                top: rect.top + scrollY - tooltipRect.height - 8,
                left: rect.left + scrollX + (rect.width / 2) - (tooltipRect.width / 2)
            },
            bottom: {
                top: rect.bottom + scrollY + 8,
                left: rect.left + scrollX + (rect.width / 2) - (tooltipRect.width / 2)
            },
            left: {
                top: rect.top + scrollY + (rect.height / 2) - (tooltipRect.height / 2),
                left: rect.left + scrollX - tooltipRect.width - 8
            },
            right: {
                top: rect.top + scrollY + (rect.height / 2) - (tooltipRect.height / 2),
                left: rect.right + scrollX + 8
            }
        };

        // Check if preferred position fits in viewport
        const pos = positions[position];
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        // Auto-adjust position if it goes off-screen
        if (pos.top < scrollY) {
            position = 'bottom';
        } else if (pos.top + tooltipRect.height > scrollY + viewportHeight) {
            position = 'top';
        }

        if (pos.left < scrollX) {
            position = 'right';
        } else if (pos.left + tooltipRect.width > scrollX + viewportWidth) {
            position = 'left';
        }

        // Apply final position
        const finalPos = positions[position];
        tooltip.style.top = `${finalPos.top}px`;
        tooltip.style.left = `${finalPos.left}px`;

        // Update tooltip class to match position
        tooltip.className = `tooltip tooltip-${position}`;
        const variant = element.getAttribute('data-tooltip-variant');
        if (variant && variant !== 'default') {
            tooltip.classList.add(`tooltip-${variant}`);
        }
        if (element.hasAttribute('data-tooltip-title')) {
            tooltip.classList.add('tooltip-rich');
        }
        if (tooltip.classList.contains('show')) {
            tooltip.classList.add('show');
        }
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Update tooltip text dynamically
     */
    updateTooltip(element, newText, newTitle = null) {
        const tooltipData = this.tooltips.get(element);
        if (!tooltipData) {
            return;
        }

        element.setAttribute('data-tooltip', newText);
        if (newTitle) {
            element.setAttribute('data-tooltip-title', newTitle);
        }

        const tooltip = tooltipData.element;
        if (newTitle) {
            tooltip.classList.add('tooltip-rich');
            tooltip.innerHTML = `
                <div class="tooltip-title">${this.escapeHtml(newTitle)}</div>
                <div class="tooltip-text">${this.escapeHtml(newText)}</div>
            `;
        } else {
            tooltip.classList.remove('tooltip-rich');
            tooltip.textContent = newText;
        }
    },

    /**
     * Remove tooltip from element
     */
    removeTooltip(element) {
        const tooltipData = this.tooltips.get(element);
        if (!tooltipData) {
            return;
        }

        const tooltip = tooltipData.element;
        if (tooltip.parentElement) {
            tooltip.parentElement.removeChild(tooltip);
        }

        element.removeAttribute('aria-describedby');
        this.tooltips.delete(element);
    }
};

// Initialize tooltips when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => TooltipManager.init());
} else {
    TooltipManager.init();
}

// Make TooltipManager globally accessible
window.TooltipManager = TooltipManager;
