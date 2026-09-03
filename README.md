# TIDECAIRN Maritime OT Watch

Source-backed maritime OT vulnerability, exploitation, product-change, and U.S. regulatory intelligence from **Tidecairn Systems**.

**Status:** pre-publication RC2.3 normalization candidate. GitHub Pages and scheduled source refresh are intentionally manual-only until the normalized live CISA CSAF/KEV/EPSS corpus has passed review.

Maritime OT Watch is a discovery and prioritization surface. It does **not** make facility applicability or compliance determinations. Exact identity, version applicability, operational context, evidence sufficiency, and human designation remain separate questions handled by the private TIDECAIRN Watchtower workflow.

## Public identity

- Organization: `tidecairn`
- Company: **Tidecairn Systems**
- Canonical company domain: `tidecairn.com`
- Planned Watch origin: `watch.tidecairn.com`

The custom Watch origin is not activated until DNS and live-origin QA are complete.

## Data sources

- U.S. Coast Guard maritime cybersecurity guidance (curated)
- CISA ICS Advisories via CISA's official TLP:WHITE OT CSAF ROLIE feed (`cisagov/CSAF`), with direct CISA RSS/listing fallbacks
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS context
- Curated vendor PSIRT / CSAF records

## Trust behavior

Source acquisition health is tracked independently. A failed source refresh preserves the prior records for that source and does not advance its `lastSuccess` timestamp. The generated JSON has a SHA-256 sidecar checked by the browser to detect partial/static-file mismatches.

Automated CISA ICS inclusion follows CISA's official ICS Advisory classification. The primary acquisition path is CISA's machine-readable OT CSAF feed; the updater records the feed timestamp and SHA-256 snapshot used for each successful refresh. CSAF normalization prefers explicit advisory/vulnerability summaries over deployment metadata and adds advisory-family context when an upstream product label is only a generic series/model name. Automated KEV inclusion uses token-aware OT product rules or a CVE already present in selected CISA ICS intelligence; CVE-only linkage is labeled explicitly with the related ICSA identifiers. It does **not** assert that the affected product is deployed at a particular maritime facility.

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
3. The RC2.3 normalized live CSAF source refresh must be inspected before scheduling is enabled.
4. A Tidecairn-domain commercial inbox must be configured before the public conversion surface is enabled.
5. `watch.tidecairn.com` is added only after domain verification and DNS setup.

See `methodology.html`, `privacy.html`, `docs/SOURCE-POLICY.md`, and `docs/DEPLOYMENT.md` for the public operating model.

Copyright © 2026 Tidecairn Systems. Publication of this repository does not by itself grant an open-source license.
