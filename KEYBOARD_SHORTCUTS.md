# Keyboard Shortcuts

ChatFilter now includes comprehensive keyboard shortcuts for improved productivity.

## Quick Access

Press **?** (question mark) or click the ⌨️ icon in the header to view all available shortcuts.

## Available Shortcuts

### Navigation (Alt + Number)
- **Alt+1**: Go to Sessions page
- **Alt+2**: Go to Chats page
- **Alt+3**: Go to Import page
- **Alt+4**: Go to Results page
- **Alt+5**: Go to History page
- **Alt+6**: Go to Proxy page

### Selection Operations
- **Ctrl/Cmd+A**: Select all visible items (chats, entries)
- **Ctrl/Cmd+Shift+A**: Clear selection
- **Escape**: Clear selection / Close modals

### Search & Filters
- **/**: Focus search field
- **Ctrl/Cmd+F**: Focus search field (alternative)
- **Escape** (in search): Clear search and unfocus

### UI Controls
- **Ctrl/Cmd+Shift+T**: Toggle dark/light theme
- **Ctrl/Cmd+Shift+L**: Toggle language (EN/RU)
- **Ctrl/Cmd+Enter**: Submit form / Start analysis

### Results Page Specific
- **Ctrl/Cmd+E**: Export results to CSV
- **Ctrl/Cmd+C**: Copy selected rows (when rows are selected)
- **Ctrl/Cmd+Shift+C**: Compare selected chats

### Help
- **?** or **Shift+/**: Show/hide keyboard shortcuts help dialog

## Implementation Details

### Files Modified/Created
1. **`src/chatfilter/static/js/keyboard-shortcuts.js`** (new)
   - Main keyboard shortcuts handler
   - Context-aware shortcut management
   - Built-in help modal

2. **`src/chatfilter/templates/base.html`**
   - Added keyboard shortcuts script include
   - Added keyboard shortcuts button (⌨️) in header

3. **`src/chatfilter/static/css/style.css`**
   - Styling for keyboard shortcuts button
   - Modal styling for help dialog

### Features
- **Context-Aware**: Shortcuts adapt based on current page
- **Non-Intrusive**: Doesn't interfere with native browser shortcuts
- **Input-Safe**: Shortcuts don't trigger when typing in input fields (except Ctrl/Cmd shortcuts)
- **Accessible**: ARIA labels and keyboard navigation support
- **Visual Feedback**: Help modal with comprehensive shortcut list
- **Cross-Platform**: Works on Windows (Ctrl), Mac (Cmd), and Linux

### Smart Behavior
- **Search Focus**: Automatically finds and focuses the appropriate search field based on page context
- **Selection**: Works with different types of selectable items (chats, entries, results)
- **Modal Handling**: Escape key intelligently closes modals before clearing selection
- **Form Submission**: Finds and triggers the appropriate submit button based on context

## Browser Compatibility
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Keyboard shortcuts follow platform conventions (Cmd on Mac, Ctrl on Windows/Linux)

## Testing Checklist
- [x] JavaScript syntax validation
- [ ] Navigation shortcuts (Alt+1-6)
- [ ] Selection shortcuts (Ctrl/Cmd+A, Ctrl/Cmd+Shift+A, Escape)
- [ ] Search shortcuts (/, Ctrl/Cmd+F)
- [ ] UI toggle shortcuts (Ctrl/Cmd+Shift+T, Ctrl/Cmd+Shift+L)
- [ ] Form submission (Ctrl/Cmd+Enter)
- [ ] Results page shortcuts (Ctrl/Cmd+E, Ctrl/Cmd+C, Ctrl/Cmd+Shift+C)
- [ ] Help modal (?)
- [ ] Mobile responsiveness
- [ ] Dark mode compatibility

## Future Enhancements
- Customizable shortcuts (user preferences)
- Visual keyboard shortcut hints on hover
- Additional page-specific shortcuts
- Shortcut recording/learning mode
