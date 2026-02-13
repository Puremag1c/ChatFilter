# Decision: GroupEngine Tests Deferred to Backlog

## Context
GroupEngine analysis orchestration (v0.10.0) currently has no dedicated unit tests.

## Analysis
Evidence shows:
- ✅ API layer covered: `test_groups_api.py` (6 tests)
- ✅ Storage layer covered: `test_group_database.py` (16 tests)
- ❌ Orchestration layer (GroupEngine) not covered

## Decision
**Deferred to P2 backlog** for following reasons:

1. **Dependency on Telethon**: GroupEngine heavily depends on Telethon client. Unit tests would require extensive mocking for marginal value.

2. **Coverage at boundaries**: Critical paths already tested:
   - API endpoints tested (input validation, response contracts)
   - Database operations tested (CRUD, persistence)

3. **Test value vs cost**: GroupEngine orchestration tests would be:
   - E2E/integration level (SPEC scenarios)
   - Expensive to maintain (Telethon API changes)
   - Low marginal value (boundaries already covered)

4. **Priority alignment**: v0.10.0 ready for release with current coverage. GroupEngine tests are P2 improvement, not P0 blocker.

## Next Steps
- Backlog item for E2E/integration tests when Telethon mocking infrastructure matures
- SPEC test scenarios remain as acceptance criteria for future iteration
