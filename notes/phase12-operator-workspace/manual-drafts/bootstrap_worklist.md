# Bootstrap Worklist

- suggested_action_bucket is a triage hint only. It does not move any row into live manual inputs.
- Review the working draft named in `suggested_working_file` first, then decide whether anything should move from `draft_candidates` into the actionable list.
- Promotion helper reads only the top-level actionable list: `overrides`, `suppressions`, or `review_resolutions`.
- `draft_candidates` stays informational until a human copies selected rows into the matching actionable list.
- Recommended next step after editing: `python -m vuln_pipeline.cli.manual_promotion --working-dir <draft-dir> --output-dir <plan-dir> --plan-only`

- No unresolved review_queue rows were available.
