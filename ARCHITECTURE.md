# Architecture

Certainted keeps destination collection separate from certificate inspection. `serve` enables the loopback CONNECT adapter by default; `serve -noproxy` disables it. The observation engine runs either way, so an enterprise metadata collector can be added without replacing the probe, analysis, storage, or dashboard modules.

```text
JSONL collector       CONNECT listener (default-on)       future gateway/flow collectors
       \                        |                                  /
        +---- destination events +---------------------------------+
                              |
                   normalization and scope policy
                              |
                  bounded queue, cache, scheduler
                              |
                    independent TLS probe
                              |
                presented list + candidate paths
                              |
                SQLite history, signed CRLs, watch rules
                              |
                  local API, dashboard, exports

Application <-- encrypted TCP bytes --> CONNECT adapter <-- encrypted TCP bytes --> Destination
                                         |
                                         +--> destination event (only)
```

The CONNECT forwarding path contains no certificate inspection and does not feed application bytes to the observation engine. A conventional HTTP CONNECT proxy conveys encrypted bytes to keep application connections working. Its local endpoint can therefore see byte counts and timing in memory, but Certainted does not parse payloads, decrypt application TLS, or persist tunneled bytes. The independent probe terminates only its own TLS connection and sends no HTTP request.

## Module boundaries

| Module | Responsibility | Boundary |
| --- | --- | --- |
| `internal/model` | Event, probe, certificate, candidate-path, watch, and finding records | Shared data contracts with provenance and timestamps |
| `internal/collector` | JSONL event parsing and a destination-sink interface | File/stdin collection independent of CONNECT |
| `internal/observe` | Normalize collector events; enforce destination policy; queue, deduplicate, rate-limit, and refresh probes | Accepts destination metadata, never application streams |
| `internal/probe` | Make a fresh TLS connection, collect presented certificates, and separately validate candidate paths | Uses its own connection and configured trust store |
| `internal/proxy` | Default-on HTTP CONNECT adapter, disabled by `serve -noproxy`; relay opaque TCP streams; emit destination metadata | Forwarding remains independent of inspection outcomes |
| `internal/revocation` | Parse and verify operator-supplied CRLs | Rejects unsupported CRL scope; URL acquisition is a separate, user-initiated step |
| `internal/store` | SQLite event, probe, revocation, watchlist, finding, and historical inventory | Persists bounded evidence, never tunnel payloads |
| `internal/enrichment` | Disabled-by-default CT enrichment interface | No third-party lookup in Phase 1 |
| Local HTTP API and Preact/TypeScript `ui` | Read inventory and findings, add watch rules, export JSON/CSV | Embedded assets; loopback only in Phase 1 |

The collector-to-observer contract is a `DestinationEvent`. A collector supplies the destination it actually knows, a timestamp, its identity, and a network vantage. The observer can receive events through JSONL ingestion or the CONNECT adapter. Future enterprise adapters should emit the same event shape and should not invent hostname, workload, or application identity.

## JSON Lines destination events

Each line is an independent JSON object. An example with reliable workload attribution:

```json
{"time":"2026-10-25T12:00:00Z","collector":"gateway-egress","vantage":"corp-west-egress","hostname":"service.example","ip":"203.0.113.10","port":443,"workload":"payments-api","attribution_reliable":true}
```

This documentation address is illustrative and is outside the default probe policy. In actual use, omit `ip` when the collector does not know it; omit `hostname` when it saw only an IP. `time` uses RFC 3339 and defaults to ingestion time if missing. `port` defaults to 443. `collector` and `vantage` default to `jsonl` and `local` if omitted. `workload` is discarded unless `attribution_reliable` is true. Collector time and probe time remain separate.

There are three distinct persisted record types:

1. **Destination observations** preserve collector-provided metadata. Two events for the same destination are still two source observations.
2. **Probe observations** preserve a separate TLS handshake, target IP, port, SNI, timestamp, vantage, TLS version and cipher, presented certificates, candidate paths, trust-store label, and failures. A probe may be skipped by the short-term cache while the destination event is retained.
3. **Analysis results** link revocation or watch evidence to a destination event and probe. A revocation finding is `direct` when the matching certificate was presented to the probe, or `candidate` when it appeared only in a reconstructed path. Watch findings may also be `name_only`. Recurring findings can be grouped as alerts while the underlying observations remain available.

The event count is not an HTTPS request count. A CONNECT tunnel can carry multiple requests, and Certainted cannot see them.

## Scope, scheduling, and probes

Input normalization validates hostname syntax, IP addresses, ports, and metadata lengths. Scope policy is applied to both CONNECT forwarding and probing. Defaults allow public IPs on ports 443 and 8443; private and sensitive ranges require explicit CIDR authorization. DNS answers are checked against policy, and the chosen IP is pinned for the outgoing connection so a second resolution cannot silently redirect it. The queue and worker count are bounded. The observer uses a global minimum probe interval, a recent-result cache keyed by destination, vantage, and trust-store configuration, and optional scheduled refreshes.

Each probe starts a fresh TCP/TLS connection. A known DNS hostname is used for SNI; an IP-only event has no invented SNI. The probe records what the endpoint presented even if subsequent path validation fails. It places limits on handshake time, certificate count, and total certificate bytes. It extracts subject, issuer, serial, SANs, validity, CA constraint, self-signed status, public-key algorithm/size, certificate SHA-256, and Subject Public Key Info SHA-256. No application cookies, bearer tokens, client certificates, session secrets, or proxy credentials are copied into the probe.

The server-presented certificate list and reconstructed paths are stored separately. Go's X.509 verification builds all available verified paths using presented intermediates and the configured trust roots. Each certificate in a candidate path is marked as `presented` or `trust_store`. A custom PEM trust store replaces the system roots for that probe configuration. Validation errors, unresolved issuers, incomplete chains, and failures remain explicit. A self-signed certificate is not automatically a trusted root. Cross-signs and multiple candidate paths are kept when verification returns them. Phase 1 performs no automatic AIA fetching.

An independent probe's candidate path is a potential exposure relationship at its own vantage. It cannot establish the original application's presented chain, trust store, or connection result. Probes with different TLS capabilities, network routes, or times may legitimately see different certificates.

## Revocation analysis

An operator imports a CRL and its issuer certificate from a known source. The dashboard accepts a local CRL file or a user-entered HTTP(S) URL; both require a local issuer certificate file. The URL fetch is a distinct, operator-initiated acquisition step performed by the local server, never a side effect of probing or parsing. It is limited to public IPs on ports 80/443, pins validated DNS answers for the connection, rejects redirects, and bounds response size and time. It does not inherit application proxy credentials or settings. There is no automatic refresh, issuer-certificate fetching, or OCSP lookup. Certainted verifies the CRL's signature, issuer name, update interval, and supported scope before storing it; the supplied issuer certificate is **not** automatically trusted as a root. Expired, future, delta, indirect, and partitioned CRLs are rejected because interpreting them as a complete issuer list would be misleading. Imports retain source, CRL and issuer fingerprints, update times, and individual revocation times and reasons.

The local CLI separately seeds a static, source-attributed incident watchlist for eight eMudhra intermediate CA public keys reported compromised and revoked in October 2026. Each key covers two known revoked certificate variants; the full identities and sources are in [the incident record](docs/EMUDHRA_2026.md). These are exact SPKI matches, not name searches or signature-verified CRL entries. This preserves a distinct evidence label and covers cross-signs without duplicating findings. A migration ledger adds each identity once to an existing inventory, reevaluates history, and respects later user edits or deletions. No incident data is fetched at runtime. The two code-signing keys are recorded for completeness but are outside normal TLS-chain observation.

A revocation finding requires an exact raw issuer-name hash and serial match. The cert-to-issuer key relationship is separately labeled as either cryptographically verified or a weaker key-identifier candidate. It never relies on a display-name substring. Independently, `direct` means the probe was presented that certificate; `candidate` means it appeared only in a reconstructed path. The dashboard and exports show both dimensions. Only a direct, cryptographically verified match should trigger a browser notification by default.

Findings are generated for probe observations at or after the CRL entry's revocation time, including historical probes reevaluated on import and future probes. An imported CRL's current listing does not establish that a pre-revocation probe saw a revoked certificate. Missing an entry is not proof of good standing: CRLs may be incomplete for the question at hand, expire, omit old entries, or cover only a particular issuer. A stale imported list must be labeled at use time. Older probes lacking exact issuer identity fields need a fresh probe rather than a name-only retroactive match.

Collection of a destination shows that an application or metadata source reported contact with that destination. A separate probe presenting a revoked certificate does not prove the original application received, requested, accepted, or trusted that certificate. Certainted does not block the connection.

## Watch and exposure analysis

Watch rules support exact certificate fingerprint, exact public-key fingerprint, and weaker name-only matches. They carry a human name and group, source-attributed or manually assigned status, severity, reason, source/reference, and effective dates. Names aid search and display, but are not a reliable CA identity. A key fingerprint groups certificate variants that reuse that key; it does not represent all keys belonging to a CA organization.

Effective dates are evaluated against probe time as `[effective_from, effective_to)`: start inclusive, end exclusive.

Evaluation labels a match to a directly presented chain as `direct`, a match only in a verified candidate path as `candidate`, and a subject/issuer name search hit as `name_only`. A watched root supplied solely by the trust store is therefore an inferred candidate exposure, never presented evidence. Adding or changing a rule reevaluates historical probes. Findings link back to their destination event and probe rather than claiming that the source application used the probed chain.

The dashboard's exposure view filters findings by watch rule and observation time. Destination and CA views show certificate history and first/last observations. JSON and CSV exports use the same local API evidence labels.

## Optional public community reports

The local `serve` process starts in Manual sharing mode. Its sharing component reads eligible revocation and watchlist findings from SQLite, builds a small allowlisted report, and previews that **exact outbound JSON** in the local dashboard. Manual sharing requires selecting reports. An explicit Auto share choice records an activation time and sends eligible observations made after that time; switching back to Manual stops new automatic sends. Report hashes are recorded locally to avoid resubmitting the same claim. An outbound client uses a dedicated connection without the application's proxy settings, HTTPS to the fixed production endpoint, bounded timeouts, and no redirects. Neither forwarding nor probing depends on publication succeeding.

The publishable fields are a public DNS hostname and port, UTC observation day, certificate fingerprint, direct or candidate label, and either CRL or exact CA watch evidence. The selection excludes IP-only and private destinations, name-only matches, and monitored-only watches. CRL reports require a directly presented certificate and a verified issuer-key path. Watch status and severity are operator-assigned; the public report does not make them authoritative. Destination IP, collector, network vantage, workload, source URL, exact probe time, raw certificates, and local database IDs are not included. Public hostnames remain potentially sensitive.

`public-serve` is a **separate executable mode**, handler, and SQLite database. It exposes only a read-only public dashboard, `GET /api/v1/reports`, `GET /api/v1/stats`, and bounded `POST /api/v1/reports`. It never opens the local inventory database, resolves a submitted hostname, probes a submitted destination, or fetches submitted certificate/CRL material. Reports are format-checked, deduplicated, capped by count and retention, and always labeled unverified. There is no reporter authentication or proof that a historical probe took place. A reverse proxy can expose this loopback service over HTTPS; the local dashboard and CONNECT adapter must stay private. See [community deployment](docs/COMMUNITY.md).

## Trust and privacy boundaries

- The collector is trusted only for its own reported destination metadata, not for application TLS evidence unless a future collector explicitly supports a distinct direct-session evidence type.
- The probe is authoritative only for its handshake from its recorded vantage and time.
- Configured trust roots can support candidate-path validation but do not reveal an application's trust decision.
- The local SQLite database and exports contain sensitive hostnames, certificate contents, and metadata. They should be protected as operational inventory.
- The loopback API is not an authenticated remote management interface. Remote access requires authentication and transport protection in a later phase.

## Extension points

Phase 2 can map existing gateway access logs, proxy destination records, or Linux network-flow events into `DestinationEvent`. It should ingest destination fields only and preserve unknown hostname or attribution. A gateway may know a hostname from CONNECT authority; an IP flow alone generally does not. A single event may identify an egress vantage but not a workload unless the source provides reliable mapping. Multiple-observer aggregation should retain each vantage rather than merging observations into one purported network truth.

The `internal/enrichment` package defines a `CTProvider` interface but ships no network implementation; CT lookups are disabled. A future opt-in implementation must record source, query time, and disclosure notice, remain bounded, and never change direct probe evidence. A public CT record is issuance evidence, not proof that an application encountered or trusted a certificate; private PKI may have no public CT record. AIA fetching and remote-probe comparison need similarly explicit authorization, limits, and provenance. Future instrumentation of an application's actual TLS session must use a new evidence type separate from independent probes.
