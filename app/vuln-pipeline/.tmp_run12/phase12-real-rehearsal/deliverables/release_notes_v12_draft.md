# Release Notes v12 Draft

- Real-input onboarding path is fixed on `data\inputs\real\*` with legacy fallback kept only for selection fallback.
- Intake provenance and SHA-256 recording are available through `input_intake_manifest.json` and `input_hashes.json`.
- Customer package privacy audit now covers ZIP entries, file/path patterns, and Markdown/JSON/TXT keyword scanning.
- PowerShell wrappers cover preflight, real rehearsal, customer final, archive-only, and PPTX capability checks.
- Actual real rehearsal was not executed because `data\inputs\real\*` currently contains no eligible inputs.

## Operational Scope
- Preflight, submission gate, readiness, privacy audit, archive-only, PPTX capability, and onboarding checklist remain active.
- Commit prep summary and git change manifest were generated for release preparation.

## Known Limitations
- `python-pptx` is not installed in the current environment.
- The current blocked rehearsal result is due to missing real inputs, not parser failure.
- PowerShell may display Korean incorrectly unless UTF-8 console settings are applied.

## Next Candidate Steps
- Place actual Burp, nuclei, and httpx files under `data\inputs\real\*`.
- Rerun the real rehearsal with `--stage-real-inputs`.
- Review commit grouping and create the release commit set.
