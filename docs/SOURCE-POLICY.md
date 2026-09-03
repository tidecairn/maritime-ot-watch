# Source policy

Maritime OT Watch prefers primary sources: U.S. Coast Guard, CISA ICS Advisories, CISA Known Exploited Vulnerabilities, vendor PSIRTs/CSAF, and FIRST EPSS for probability context.

## Epistemic boundary
A public signal can establish that a product, vendor, vulnerability, or regulatory change deserves review. It cannot establish that an unnamed facility asset is affected. Exact identity, version, configuration, evidence freshness, operational context, and human designation remain separate questions.

## Failure policy
Every automated source has `checkedAt` and `lastSuccess`. Failed acquisition preserves the previous records for that source, leaves `lastSuccess` unchanged, and surfaces degraded health. Missing upstream data never becomes a negative finding.

## Relevance policy
Automated CISA ICS records are filtered using an explicit OT vendor/product vocabulary. “Selected” means plausible industrial-control relevance in maritime environments. It does not assert maritime deployment. CISA KEV records are included only where the product passes the same OT criteria or the CVE appears in a selected CISA ICS record.
