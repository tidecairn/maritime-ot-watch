# TIDECAIRN Maritime OT Watch

Source-backed maritime OT vulnerability, exploitation, product-change, and U.S. regulatory intelligence from **Tidecairn Systems**.

**Status:** public production service at **https://watch.tidecairn.com**.

Maritime OT Watch is a discovery and prioritization surface. It does **not** make facility applicability or compliance determinations. Exact identity, version applicability, operational context, evidence sufficiency, and human designation remain separate questions handled by the private **TIDECAIRN Watchtower** workflow.

## Public identity

- Organization: `tidecairn`
- Company: **Tidecairn Systems**
- Canonical company domain: `tidecairn.com`
- Watch origin: **https://watch.tidecairn.com**
- Commercial contact: **contact@tidecairn.com**

## Data sources

- U.S. Coast Guard maritime cybersecurity guidance (curated)
- CISA ICS Advisories via CISA's official TLP:WHITE OT CSAF ROLIE feed (`cisagov/CSAF`), with direct CISA RSS/listing fallbacks
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS context
- Curated vendor PSIRT / CSAF records

## Trust behavior

Source acquisition health is tracked independently. A failed source refresh preserves the prior records for that source and does not advance its `lastSuccess` timestamp. The generated JSON has a SHA-256 sidecar checked by the browser to detect partial/static-file mismatches.

Automated CISA ICS inclusion follows CISA's official ICS Advisory classification. The primary acquisition path is CISA's machine-readable OT CSAF feed; the updater records the feed timestamp and SHA-256 snapshot used for each successful refresh. CSAF normalization prefers explicit advisory/vulnerability summaries over deployment metadata and adds advisory-family context when an upstream product label is only a generic series/model name.

Automated KEV inclusion uses token-aware OT product rules or a CVE already present in selected CISA ICS intelligence; CVE-only linkage is labeled explicitly with the related ICSA identifiers. Public inclusion does **not** assert that the affected product is deployed at a particular maritime facility.

The Watch orders signals by latest known advisory activity. Where a source publishes a later revision, the revision date drives ordering while the original publication date remains visible.

## Production operation

The Watch operates on GitHub Actions:

- intelligence refresh: four times per day at an offset six-hour cadence, plus manual dispatch;
- each refresh executes pre/post regression tests, JavaScript syntax validation, static build, verified data commit, and direct deployment of the exact refreshed artifact;
- ordinary pushes to `main` also run the full Pages build/deploy gate;
- all third-party GitHub Actions are pinned to immutable commit SHAs.

## Local QA

```bash
python -m unittest discover -s tests -v
node --check assets/watch.js
python scripts/build.py
```

See `methodology.html`, `privacy.html`, `docs/SOURCE-POLICY.md`, and `docs/DEPLOYMENT.md` for the public operating model.

## Commercial platform

**TIDECAIRN Watchtower** performs the private, facility-specific decision step: exact product identity, version applicability, evidence debt, Critical IT/OT designation, KEV traceability, assessment workflow, and reviewer-ready proof.

Assessment firms and maritime operators interested in a controlled technical validation can contact **contact@tidecairn.com**.

Copyright © 2026 Tidecairn Systems. Publication of this repository does not by itself grant an open-source license.
