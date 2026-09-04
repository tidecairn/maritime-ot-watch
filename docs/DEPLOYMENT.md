# Deployment and release controls

Maritime OT Watch uses GitHub Actions deployment rather than a `gh-pages` branch.

## Current launch-candidate state

The intelligence acquisition and normalization gate is closed. CISA OT CSAF, CISA KEV, FIRST EPSS, curated provenance, source-health semantics, and corpus integrity have passed controlled live validation.

Both workflows remain intentionally `workflow_dispatch`-only until the custom-domain deployment has passed live-origin QA.

## Identity and conversion gate

1. Operate a real Tidecairn-domain commercial inbox (`contact@tidecairn.com`).
2. Verify `tidecairn.com` under the Tidecairn GitHub organization's **Settings → Pages** domain-verification control and retain the TXT challenge record.
3. Enable the Watch conversion surface only after the inbox and domain are operational.

## First Pages validation

1. In repository **Settings → Pages**, choose **GitHub Actions** as the build/deployment source.
2. Configure the custom domain as `watch.tidecairn.com`.
3. At the authoritative DNS provider, create only the required `watch` CNAME pointing to `tidecairn.github.io`; do not use wildcard DNS.
4. Wait for GitHub's DNS check to pass.
5. Manually run **Publish GitHub Pages**.
6. Wait for the GitHub-managed TLS certificate and enable **Enforce HTTPS** when available.
7. Perform desktop/mobile/accessibility/security/live-data QA against `https://watch.tidecairn.com` before announcement.

## Post-acceptance automation

Only after live-origin acceptance:

- add the six-hour intelligence refresh schedule;
- allow successful refresh commits to trigger Pages publication;
- update repository/public status from launch candidate to public;
- create the first public release/tag.

`dist/` is generated in CI and is intentionally not committed.
