# Deployment and release controls

Maritime OT Watch uses GitHub Actions deployment rather than a `gh-pages` branch.

## Current launch-candidate state

The intelligence acquisition and normalization gate is closed. CISA OT CSAF, CISA KEV, FIRST EPSS, curated provenance, source-health semantics, and corpus integrity have passed controlled live validation.

Both workflows remain intentionally `workflow_dispatch`-only. The custom domain and HTTPS are active; the site remains an unannounced launch candidate until the final live-origin QA/repair gate passes.

## Identity and conversion gate

1. Operate a real Tidecairn-domain commercial inbox (`contact@tidecairn.com`).
2. Verify `tidecairn.com` under the Tidecairn GitHub organization's **Settings → Pages** domain-verification control and retain the TXT challenge record.
3. Enable the Watch conversion surface only after the inbox and domain are operational.

## First Pages validation

Completed: GitHub Actions is the Pages source, `watch.tidecairn.com` is the verified custom domain, the `watch` CNAME points to `tidecairn.github.io`, the first Pages deployment succeeded, and GitHub-managed HTTPS is active.

Remaining before announcement:

1. Apply any fixes produced by the live-origin red-team gate.
2. Manually refresh intelligence and redeploy Pages.
3. Re-run desktop/mobile/accessibility/security/live-data QA against `https://watch.tidecairn.com`.
4. Only after acceptance, enable post-launch automation.

## Post-acceptance automation

Only after live-origin acceptance:

- add the six-hour intelligence refresh schedule;
- allow successful refresh commits to trigger Pages publication;
- update repository/public status from launch candidate to public;
- create the first public release/tag.

`dist/` is generated in CI and is intentionally not committed.
