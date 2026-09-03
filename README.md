# TIDECAIRN Maritime OT Watch

Source-backed maritime OT vulnerability, exploitation, product-change, and U.S. regulatory intelligence from **Tidecairn Systems**.

**Status:** pre-publication release candidate. GitHub Pages and scheduled source refresh are intentionally manual-only until the first live CISA/KEV/EPSS corpus has been reviewed.

Maritime OT Watch is a discovery and prioritization surface. It does **not** make facility applicability or compliance determinations. Exact identity, version applicability, operational context, evidence sufficiency, and human designation remain separate questions handled by the private TIDECAIRN Watchtower workflow.

## Public identity

- Organization: `tidecairn`
- Company: **Tidecairn Systems**
- Canonical company domain: `tidecairn.com`
- Planned Watch origin: `watch.tidecairn.com`

The custom Watch origin is not activated until DNS and live-origin QA are complete.

## Data sources

- U.S. Coast Guard maritime cybersecurity guidance (curated)
- CISA ICS Advisories RSS
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS context
- Curated vendor PSIRT / CSAF records

## Trust behavior

Source acquisition health is tracked independently. A failed source refresh preserves the prior records for that source and does not advance its `lastSuccess` timestamp. The generated JSON has a SHA-256 sidecar checked by the browser to detect partial/static-file mismatches.

Automated inclusion means a source record is plausibly relevant to industrial-control environments. It does **not** assert that the affected product is deployed at a particular maritime facility.

## Local QA

```bash
python -m unittest discover -s tests -v
node --check assets/watch.js
python scripts/build.py
```

## Controlled publishing

The repository is intentionally configured in prelaunch mode:

1. `Refresh Watch intelligence` is manual-only.
2. `Publish GitHub Pages` is manual-only.
3. The first live source refresh must be inspected before scheduling is enabled.
4. A Tidecairn-domain commercial inbox must be configured before the public conversion surface is enabled.
5. `watch.tidecairn.com` is added only after domain verification and DNS setup.

See `methodology.html`, `privacy.html`, `docs/SOURCE-POLICY.md`, and `docs/DEPLOYMENT.md` for the public operating model.

Copyright © 2026 Tidecairn Systems. Publication of this repository does not by itself grant an open-source license.
