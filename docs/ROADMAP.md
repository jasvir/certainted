# Roadmap

## Phase 1 — local observation (this repository)

- Two destination collectors: authorized JSON Lines metadata from a file or standard input, and a loopback HTTP CONNECT adapter whose listener starts by default for `serve` and is disabled with `-noproxy`. Applications must opt in to using the proxy.
- Shared normalization, destination/port scope, bounded scheduling, rate limiting, caching, and periodic refresh.
- Independent TLS probes with separately stored presented certificates and verified candidate paths using a named system or custom PEM trust store.
- Dashboard or CLI import of operator-supplied, signature-verified CRLs from local files, plus operator-initiated dashboard URL import with public-network scope and size/time limits. Exact issuer/serial matching produces post-revocation findings for historical and future probes. Directly presented and candidate-path evidence remain distinct, as do cryptographically verified and key-identifier candidate issuer matches.
- SQLite destination events, probe history, CA inventory, watch rules, and historical findings. Direct, candidate-path, and name-only evidence are distinct. Watch changes reevaluate historical probes. Local inventories seed source-attributed exact-key watches for the eight affected eMudhra intermediates reported in October 2026; these incident watches remain distinct from verified CRL findings.
- Local dashboard, time-window exposure search, JSON/CSV exports, retention and pruning controls, tests using generated local certificates, and macOS/Linux CI.
- Optional Manual or explicitly enabled Auto sharing of minimal public reports, plus a separate unauthenticated public report receiver and dashboard. Community reports remain unverified claims and do not expose the local inventory API.

Phase 1 focuses on finding contacted destinations whose independent probes present certificates listed as revoked. It has no enforcement, no inspection of application payloads, and no guaranteed knowledge of the application's actual TLS chain. CRL retrieval is operator initiated and refresh is manual; an unlisted certificate is not declared good. The UI and API are loopback-only and do not include remote authentication. Destination, probe, finding, and grouped-alert API lists are capped at 10,000 records per query. Exports for destinations, probes, and findings are bounded to the most recent 100,000 records per resource, and probe exports also have a 32 MiB evidence budget. These caps avoid unbounded local responses and are not a substitute for pagination or an archival workflow.

## Phase 2 — enterprise collection and deployment

Implement one practical metadata adapter for an existing egress source, preferably a structured gateway or proxy access log configured to emit only timestamp, destination host/IP, port, collector, and vantage. Avoid importing request paths, headers, bodies, or credentials. If a Linux flow source is used instead, preserve IP-only events and do not invent DNS or workload attribution. Document source-specific parsing, permission requirements, rotation, and failure behavior.

Add deployment guidance for running observers at each relevant customer network vantage, especially for private endpoints. Aggregate multiple observers while retaining each original vantage and timestamp. Provide authenticated and encrypted remote dashboard/API access when deployment needs it. Define authorization for metadata sources, private-network scope, database backups, and retention. Add pagination and scalable historical queries before increasing limits.

If community reporting is used at scale, add abuse mitigation, moderation and dispute workflows, provenance checks where feasible, and pagination or archival access to public reports. Reporter authentication would change the trust and privacy model and needs separate review; anonymous submissions remain claims even if many submitters repeat them.

Evaluate opt-in scheduled CRL refresh from authorized sources with explicit provenance, issuer-chain policy, and coverage reporting. Define a separate OCSP adapter if needed. OS revocation caches are not a complete inventory of issuers or revoked certificates and must not silently become a global watchlist.

## Phase 3 — opt-in enrichment and visualization

- Optional Certificate Transparency enrichment with explicit third-party metadata disclosure, query bounds, and source/time provenance. Public issuance records do not prove an application encountered or trusted a certificate; absence of public CT is not proof of compromise, especially for private PKI.
- AIA issuer fetching only after a security review, with explicit opt-in, scope checks, size/time limits, and provenance. It must never silently become part of core path evidence.
- Experimental local-versus-remote independent probe comparison. Route, CDN, rotation, load-balancer, client-capability, and selective-attack differences must be represented as alternative explanations. It is not guaranteed interception detection.
- A dependency graph distinguishing observed destination-to-presented-certificate relationships from inferred candidate issuers and trust roots.
- Optional application instrumentation as a new evidence type for chains actually seen by an application. It must remain separate from independent probe observations and respect application consent and privacy boundaries.
