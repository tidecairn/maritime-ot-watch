# Deployment and release controls

Maritime OT Watch is the public intelligence surface of Tidecairn Systems and is served at:

`https://watch.tidecairn.com`

GitHub Actions is the publishing source. `dist/` is generated in CI and is intentionally not committed.

## Production state

The following gates are closed:

- Tidecairn-domain email operational;
- organization Pages domain verified;
- `watch.tidecairn.com` DNS validated;
- GitHub-managed HTTPS active and enforced;
- intelligence acquisition/normalization gate passed;
- live-origin repair gate passed;
- public commercial contact configured at `contact@tidecairn.com`;
- production presentation marker `watch-ui/v1.1` active.

## Production refresh path

`Refresh Watch intelligence` runs at an offset six-hour cadence:

- 01:17 UTC
- 07:17 UTC
- 13:17 UTC
- 19:17 UTC

Manual dispatch remains available.

Each run performs:

1. pre-refresh regression tests;
2. public-source acquisition and normalization;
3. post-refresh regression tests;
4. JavaScript syntax validation;
5. exact static build;
6. verified `watch.json` / `watch.sha256` commit when bytes changed;
7. direct deployment of the exact refreshed `dist/` artifact to GitHub Pages.

The refresh workflow deploys directly because pushes made with the workflow's standard `GITHUB_TOKEN` do not reliably trigger a second workflow. No PAT or recursive workflow trigger is required.

## Code-change publication path

`Publish GitHub Pages` runs on:

- push to `main`;
- manual dispatch.

It independently executes regression tests, JavaScript syntax validation, the static build, and GitHub Pages deployment.

Both production workflows share one repository-level concurrency group so code deployments and intelligence refresh deployments cannot race each other.

## Failure behavior

A failed source acquisition cannot advance that source's `lastSuccess`. Suspicious empty/collapsed source responses fail plausibility checks and preserve prior known-good records. Failed QA prevents publication.

If a scheduled refresh fails:

1. inspect the failed job;
2. do not manually edit `data/watch.json`;
3. correct the acquisition or test defect;
4. re-run the workflow;
5. confirm the public integrity indicator returns `VERIFIED`.

## Release freeze

The first production tag is `v1.0.0`.

Post-1.0 changes to selector, acquisition, provenance, ordering, or integrity semantics require regression coverage and a deliberate version-marker change where materially appropriate.
