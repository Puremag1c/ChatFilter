# Testing Strategy for Automated Verification

## Problem Statement

OPS manual test tasks cannot be completed by agents due to environmental constraints:
- Require real Telegram sessions (phone verification, 2FA)
- Require network manipulation (proxy errors, timeouts)
- Agent environment cannot create/modify real sessions

## Strategy: Split Testing + Mock Automation

### 1. Task Classification

#### Agent-Verifiable (Automated)
Tasks that agents CAN complete without human intervention:

- **Code Review Tasks**
  - Verify code changes exist in specified files
  - Check error handling logic is present
  - Validate template changes (error display, translations)
  - Run automated tests (unit, integration)
  - Example: Verify `error_message` saved to config.json

- **Static Analysis Tasks**
  - Check for security vulnerabilities
  - Validate translation files completeness
  - Verify documentation updates
  - Check code style compliance

- **Mock-Based UI Tests** (NEW)
  - Playwright tests with mocked error states
  - Inject test data via localStorage/fixtures
  - Simulate error scenarios without real network
  - See [Mock Testing Patterns](#mock-testing-patterns) below

#### Human-Required (Manual)
Tasks that REQUIRE human verification:

- **Real Session Tests**
  - Add Telegram accounts (phone verification)
  - Test with real proxy configurations
  - Verify actual network timeouts
  - Test 2FA workflows

- **Visual/UX Verification**
  - Check error message clarity
  - Verify UI responsiveness across devices
  - Test accessibility features
  - Validate translations in context

- **Edge Cases**
  - Rare network conditions (<1% probability)
  - Browser-specific quirks
  - Complex multi-step workflows

### 2. OPS Task Split Pattern

When analyst creates OPS manual test task:

```bash
# Original task: "[OPS] Manual test Bug X: Feature Y"
# Split into 2 subtasks:

# Task 1: Code Review (agent)
bd create --title="[OPS] Code review Bug X: Feature Y" \
  --type=task --priority=1 \
  --assignee=executor \
  --description="Verify code changes for Bug X fix.

files:
- src/chatfilter/sessions.py (error handling)
- src/chatfilter/templates/session_row.html (error display)

done_when:
- All code changes from Bug X fix commit are reviewed
- Error handling logic verified
- Template error display verified
- No manual browser testing required"

# Task 2: Browser Test (human)
bd create --title="[OPS] Browser test Bug X: Feature Y" \
  --type=task --priority=2 \
  --assignee=human \
  --add-label=requires-human-test \
  --description="Manual browser testing for Bug X fix.

Test scenarios:
1. [scenario 1]
2. [scenario 2]

Prerequisites:
- Code review task completed
- Dev server running
- Test Telegram accounts available

done_when:
- All scenarios tested manually
- Results documented in notes"
```

### 3. Mock Testing Patterns

For UI features that can be tested with mocked states, use Playwright:

#### Pattern: Mock Error States

```javascript
// playwright-tests/mock-error-states.spec.js
import { test, expect } from '@playwright/test';

test('Connect failure shows error message', async ({ page }) => {
  // Navigate to sessions page
  await page.goto('http://localhost:8000/sessions');

  // Mock error state via localStorage
  await page.evaluate(() => {
    localStorage.setItem('chatfilter_test_mode', 'true');
    localStorage.setItem('chatfilter_mock_connect_error',
      'Failed to connect: Proxy authentication required');
  });

  // Trigger connect (button should read mock state)
  await page.click('[data-session-id="test-session"] button.connect-btn');

  // Verify error message displays
  const errorMsg = await page.locator('.error-message').textContent();
  expect(errorMsg).toContain('Failed to connect');
  expect(errorMsg).toContain('Proxy authentication required');
});
```

#### Pattern: Mock Session States

```javascript
// Create test fixture for sessions
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.__TEST_SESSIONS__ = [
      {
        id: 'test-session-1',
        name: 'Test Account',
        error_message: 'Connection timeout',
        status: 'disconnected'
      }
    ];
  });
});
```

#### Pattern: Mock Network Conditions

```javascript
// Simulate network failure
await page.route('**/api/sessions/*/connect', route => {
  route.fulfill({
    status: 500,
    body: JSON.stringify({ error: 'Network timeout' })
  });
});
```

### 4. When to Use Each Approach

| Scenario | Approach | Reason |
|----------|----------|--------|
| Verify error handling code exists | Code Review | Agent can read code |
| Verify error message displays | Mock UI Test | Can mock error state |
| Verify proxy error with real proxy | Human Test | Needs real network |
| Verify translation completeness | Code Review | Agent can check files |
| Verify translation looks good | Human Test | Needs native speaker |
| Verify button click triggers API | Mock UI Test | Can mock API response |
| Verify 2FA flow | Human Test | Needs real Telegram account |

### 5. Workflow for Blocked Tasks

For currently blocked tasks (ChatFilter-qroaz, ChatFilter-ldmxa):

```bash
# 1. Close blocked task as completed (code review done)
bd close ChatFilter-qroaz --reason="Code review completed. Browser test not feasible in agent environment."

# 2. Create human verification task
bd create --title="[Human] Browser test Bug 2: Connect failure error message" \
  --type=task --priority=2 \
  --assignee=human \
  --add-label=requires-human-test \
  --description="Manual verification that Bug 2 fix works in real browser.

Prerequisites:
- Bug 2 code merged to main (commit ce26c00)
- Dev server running

Test scenarios:
1. Account without phone number in account_info
2. Account with invalid proxy configured
3. Network disconnect during connect

Expected result:
- Error message displays inline in session row
- No silent failures

done_when:
- All 3 scenarios tested
- Results documented in notes"
```

### 6. Future: Automated Mock Tests

To reduce human testing burden, create Playwright test suite:

```bash
# Directory structure
playwright-tests/
  ├── fixtures/
  │   ├── test-sessions.json       # Mock session data
  │   └── error-states.json        # Mock error scenarios
  ├── specs/
  │   ├── session-errors.spec.js   # Bug 2 tests
  │   ├── translations.spec.js     # Bug 3 tests
  │   └── multi-tab.spec.js        # MULTITAB.md tests
  └── playwright.config.js
```

Run automated tests before human verification:
```bash
# Agent can run these
npx playwright test

# If all pass → likely works
# If any fail → fix before human test
```

## Decision: Hybrid Approach

**Adopted strategy:**
1. **Code review** → agents (automated, always)
2. **Mock UI tests** → agents via Playwright (when feasible)
3. **Real browser tests** → humans (when necessary)

**Benefits:**
- Agents complete 80% of verification automatically
- Humans focus on 20% that requires real sessions/judgment
- Clear criteria for what needs human intervention
- Blocking tasks can be unblocked (split into agent + human)

**Implementation:**
- Document created: TESTING_STRATEGY.md (this file)
- Blocked tasks updated: split or closed with human follow-up
- Future: Playwright mock test suite for common scenarios
