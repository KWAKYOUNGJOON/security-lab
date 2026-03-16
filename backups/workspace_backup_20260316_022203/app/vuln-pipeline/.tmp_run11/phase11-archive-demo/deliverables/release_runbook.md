# Release Runbook

- run_root: `.tmp_run11\phase11-archive-demo`
- compare_to_run: `phase11-final-stage-demo`
- readiness_policy: `D:\취약점 진단\app\vuln-pipeline\configs\readiness\customer_release.yaml`

## Release Candidate
1. Run with `--release-candidate` to generate the candidate manifest.
2. Check `report_data\release_candidate_manifest.json` for blocking reasons.

## Finalize Delivery
1. Run with `--finalize-delivery` after review closure and readiness checks.
2. Verify `delivery\final_delivery_manifest.json` was updated.

## Submission Gate
- current status: `not_generated`
1. Confirm readiness, unresolved review count, privacy audit, and PPTX requirement checks.
2. Do not send the customer ZIP when submission gate is `fail`.

## Customer Submission Handoff
- customer_submission_zip: ``
1. Send only the customer submission ZIP after gate and privacy audit pass.
2. Keep final delivery manifest with the delivery record.

## Internal Archive Retention
- internal_archive_zip: `.tmp_run11\phase11-archive-demo\delivery\internal_archive_v1.0.zip`
1. Retain the internal archive ZIP with report data and comparison outputs.
2. Use archive-only reruns for internal retention updates without rebuilding customer output.
3. Record that customer submission artifacts were not regenerated during archive-only runs.
