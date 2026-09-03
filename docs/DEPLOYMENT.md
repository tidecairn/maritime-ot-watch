# Deployment and release controls

Maritime OT Watch uses GitHub Actions deployment rather than a `gh-pages` branch.

## Pre-publication state

Both workflows are intentionally `workflow_dispatch`-only. Nothing is scheduled and a source push cannot publish the site accidentally.

## First live-source validation

1. Manually run **Refresh Watch intelligence**.
2. Confirm CISA ICS, CISA KEV, and FIRST EPSS source states are not `pending`.
3. Review every automatically selected signal for false-positive relevance and malformed metadata.
4. Verify `data/watch.sha256` against `data/watch.json`.
5. Repeat local/CI tests.

Do not add the six-hour schedule until this corpus review passes.

## First Pages validation

1. Configure a real Tidecairn commercial inbox and rebuild the public conversion surface.
2. Verify the `tidecairn.com` domain in the GitHub organization.
3. Configure `watch.tidecairn.com` DNS and the Pages custom domain.
4. In repository Settings → Pages, choose **GitHub Actions** as the source.
5. Manually run **Publish GitHub Pages**.
6. Perform full desktop/mobile live-origin browser QA before announcement.
7. Only after acceptance, enable push-triggered deployment if desired.

`dist/` is generated in CI and is intentionally not committed.
