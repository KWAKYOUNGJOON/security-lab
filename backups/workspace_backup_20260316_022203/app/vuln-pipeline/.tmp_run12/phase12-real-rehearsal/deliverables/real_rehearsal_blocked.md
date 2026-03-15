# Real Rehearsal Blocked

- run_id: `phase12-real-rehearsal`
- reason: `no eligible real input files were found in data\inputs\real\*`
- preflight_status: `blocked`
- selection_status: `incomplete`

## Tool Summary
- burp: selected_path=`None` reason=`no_eligible_candidates` source=`legacy_fallback`
- nuclei: selected_path=`None` reason=`no_eligible_candidates` source=`legacy_fallback`
- httpx: selected_path=`None` reason=`no_eligible_candidates` source=`legacy_fallback`

## Blockers
- real scan inputs are not ready

## Next Action
- Place actual Burp, nuclei, and httpx files in `data\inputs\real\*` and rerun the rehearsal.
