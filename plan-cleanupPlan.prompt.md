## Plan: Safe Repo Cleanup
I need start.sh, so keep it.
Conservative cleanup plan for the Sentinel Core repo. The goal is to remove dead files and redundant code without breaking the documented or current runtime path. The main rule is: delete only after the last caller or reference is migrated, and keep runtime entry points intact until the new path is the only supported one.

**Steps**
1. Build a final keep/remove/migrate inventory for the suspicious files and code paths. Confirm direct references for the startup scripts, scratch utilities, frontend dependency/CSS, and legacy tests before deleting anything. This includes checking docs, preflight checks, shell scripts, and test imports so the cleanup target list is evidence-based.
2. Remove the low-risk artifacts first, because they have no runtime role. Delete the timestamped backup logs under `data/logs/`, and remove the `scratch/` utilities only after confirming they are not part of any maintained workflow. If `tests/test_stabilization.py` is still only covering legacy behavior, move any useful assertions into the current consumer/tri-layer tests first, then delete the old file.
3. Clean the frontend in a narrowly scoped way. Remove the unused `@tanstack/react-virtual` dependency from `ui/package.json` and `ui/package-lock.json`, and delete the unused `.reputation-tag` rule from `ui/src/App.css`. Keep the other class names that `ui/src/App.jsx` uses, even if they are only styled implicitly today, because deleting them would change layout or behavior. Finish with a build and lint pass.
4. Keep the legacy startup script, but clean the redundant code inside it. Update all references in the README, startup guides, troubleshooting docs, preflight script, and improved scripts so the supported commands clearly point to the kept launcher flow. Remove duplicated setup steps inside `start.sh` only where the behavior stays identical, and keep the script as a compatibility entry point if that remains the safer rollback path.
5. Decide separately whether the training/export tooling should be archived rather than deleted. `models/train.py` and `scripts/export_onnx.py` are not runtime dependencies, but they still matter if model regeneration stays in scope. Remove them only if the team has a documented external model build process or is intentionally dropping in-repo retraining support.
6. Treat documentation cleanup as a follow-up phase, not part of the first delete pass. `STARTUP_OPTIMIZATION_PLAN.md` and similar historical docs can be archived or removed only after the migrated commands and supported workflow are reflected everywhere else.

**Relevant files**
- `/home/preet/FYP/setup.sh` and `/home/preet/FYP/start.sh` — current runtime entry points; keep `start.sh` and clean redundant code inside it rather than deleting it.
- `/home/preet/FYP/setup.sh` and `/home/preet/FYP/start.sh` — replacement flow that must become the only supported path before removing the originals.
- `/home/preet/FYP/preflight.sh` — still checks for the legacy scripts, so it must be updated before any deletion.
- `/home/preet/FYP/README.md`, `/home/preet/FYP/STARTUP_GUIDE.md`, `/home/preet/FYP/QUICK_START_SUMMARY.md`, `/home/preet/FYP/DELIVERY_SUMMARY.md`, `/home/preet/FYP/TROUBLESHOOTING_INDEX.md`, `/home/preet/FYP/GETTING_STARTED_CHECKLIST.md` — docs that still point at the old startup flow.
- `/home/preet/FYP/data/logs/consumer.log.20260428_171642.bak` and `/home/preet/FYP/data/logs/errors.log.20260428_171642.bak` — safe cleanup candidates.
- `/home/preet/FYP/scratch/test_models.py` and `/home/preet/FYP/scratch/test_nmap_perf.py` — ad hoc local utilities, likely removable after reference checks.
- `/home/preet/FYP/tests/test_stabilization.py` — legacy behavior test to fold into the maintained suite or remove if coverage exists elsewhere.
- `/home/preet/FYP/ui/package.json`, `/home/preet/FYP/ui/package-lock.json`, `/home/preet/FYP/ui/src/App.css`, `/home/preet/FYP/ui/src/App.jsx` — frontend dependency and CSS cleanup surface.
- `/home/preet/FYP/models/train.py` and `/home/preet/FYP/scripts/export_onnx.py` — tooling files to archive only if retraining/export is no longer needed.

**Verification**
1. Run repository-wide reference checks for every planned deletion candidate and confirm there are no remaining callers before removing the file.
2. Run `./preflight.sh` after startup-script migration to confirm the documented setup/start path still passes validation.
3. Run `pytest tests/` after any test-file cleanup to confirm the maintained suite still passes.
4. Run `cd ui && npm run lint && npm run build` after frontend cleanup to confirm the UI still compiles cleanly.
5. Smoke test the real startup flow with the improved scripts and confirm the dashboard, ingestion, and relay start as expected.

**Decisions**
- Do not delete `setup.sh`; keep `start.sh` and only remove redundant internal code that does not change its behavior.
- Do not remove CSS classes that `App.jsx` currently uses, even if they are not fully styled in the current CSS files.
- Treat model training/export files and historical docs as optional archive candidates, not immediate deletions.
- Prefer deletion of low-risk artifacts first, then caller migration where needed, and keep `start.sh` as a maintained compatibility launcher.