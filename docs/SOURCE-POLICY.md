# Source policy

Maritime OT Watch prefers primary sources: U.S. Coast Guard, CISA ICS Advisories, CISA Known Exploited Vulnerabilities, vendor PSIRTs/CSAF, and FIRST EPSS for probability context.

## Epistemic boundary
A public signal can establish that a product, vendor, vulnerability, or regulatory change deserves review. It cannot establish that an unnamed facility asset is affected. Exact identity, version, configuration, evidence freshness, operational context, and human designation remain separate questions.

## Failure policy
Every live source has `checkedAt` and `lastSuccess`. Failed acquisition preserves the previous records for that source, leaves `lastSuccess` unchanged, and surfaces degraded health. The curated registry is separately labeled `local-registry`; its successful load is not represented as a fresh online re-verification of each underlying source.

Successful transport alone is not sufficient. CISA ICS acquisition is subject to a minimum-record plausibility check and, after a known-good live corpus exists, a collapse guard. An empty or implausibly collapsed response is quarantined rather than replacing known-good records.

## CISA ICS policy
Records classified by CISA as **ICS Advisory** are eligible for the public Watch without a second generic keyword filter. The primary acquisition path is CISA's official **TLP:WHITE Operational Technology CSAF ROLIE feed** published from the `cisagov/CSAF` repository. CISA's repository identifies itself as the machine-readable CSAF source for CISA IT and OT advisories; signal-level source links remain the corresponding `cisa.gov` advisory pages.

The updater accepts only final, TLP:WHITE `ICSA-*` documents from the OT/white feed, excludes ICS Medical advisories, requires the document's CISA web self-reference, and records both the ROLIE feed update timestamp and SHA-256 of the exact feed snapshot used. Direct CISA RSS and the CISA ICS Advisory listing remain fail-closed fallback paths. If all paths fail, prior CISA ICS records are preserved and `lastSuccess` does not advance.

The GitHub-hosted CSAF feed is not treated as a secondary editorial source: it is CISA's own machine-readable publication channel. Secondary reporting remains excluded as authority.

## KEV relevance policy
KEV inclusion is intentionally precision-biased. A KEV record enters only when:

1. its CVE is already present in the selected CISA ICS corpus; or
2. the product contains a strong industrial-control identifier such as PLC, SCADA, HMI, SIMATIC, Modicon, ControlLogix, RTU, OPC UA, or process-control terminology; or
3. a recognized OT vendor is paired with a vendor-gated industrial term such as DCS, PAC, controller, drive, industrial, or automation; or
4. the vendor/product pair is an explicit bounded industrial exception.

Matching is token-aware where ambiguity matters. Ordinary IT strings such as `driver`, `Virtual`, `Apache`, `Compact`, and generic application-delivery `controller` products must not qualify merely because they contain the letter sequences `drive`, `RTU`, `PAC`, or `controller`.

“Selected” means review-worthy industrial-control relevance. It does not assert maritime deployment.
