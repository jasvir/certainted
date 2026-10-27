# Threat model

Certainted processes sensitive destination metadata and actively connects to destinations. It must be deployed only for networks and services the operator is authorized to observe. Its main safety boundary is that application TLS remains end to end between the application and destination; only a separate Certainted probe terminates TLS.

## Assets and trust boundaries

| Asset | Why it matters | Boundary |
| --- | --- | --- |
| Application tunnel | May carry credentials and confidential content inside TLS | CONNECT adapter relays opaque bytes; it must not terminate TLS or persist payloads |
| Destination events | Hostnames, IPs, timestamps, vantage, and optional workload identity can reveal internal activity | Collector input is untrusted for network authorization and only as reliable as its source |
| Probe evidence | Certificates, paths, failures, and routing detail reveal service infrastructure | Independent connection, recorded vantage/time, bounded storage |
| Watchlist labels | A status such as `compromised` can affect human decisions | Manual provenance, except eight source-attributed eMudhra intermediate-key entries from the October 2026 incident; these are distinct from verified CRL evidence |
| Imported CRLs | A forged, stale, or scoped list could create false findings or false reassurance | Operator supplies source and issuer certificate; signature, freshness, and supported scope are checked after bounded acquisition |
| SQLite inventory and exports | Historical operational map of destinations and CAs | Local file access must be restricted; removal/retention is an operator responsibility |
| Dashboard/API | Makes sensitive metadata searchable and allows watchlist changes | Loopback-only Phase 1 service; no unauthenticated remote exposure |
| Public reports | Voluntarily disclosed hostnames and certificate findings can reveal browsing or service use; anonymous claims can be false | Explicit local opt-in, minimal outbound schema, separate public database, unverified labels and bounded ingestion |

An attacker may control a JSONL input line, a CONNECT target, DNS answers, server certificate fields, or a web page open in the same browser as the dashboard. A compromised local account with access to the database can read the inventory; Phase 1 does not claim to protect against that host-level compromise.

## Forwarding and privacy

The CONNECT adapter starts on loopback by default and can be disabled with `serve -noproxy`. It is a real TCP proxy: it cannot deliver a working tunnel without conveying the application's encrypted bytes. It accepts CONNECT and rejects ordinary plaintext HTTP forwarding. It uses bounded concurrent tunnels, connection/idle timeouts, and stream shutdown behavior. It emits the destination host or IP and port; it does not persist request paths, headers, bodies, tunneled bytes, packet captures, TLS keys, or proxy credentials. A separate probe is scheduled asynchronously. A probe failure or watchlist match cannot rewrite the application's TLS result or intentionally block a valid tunnel.

Even without decryption, the proxy endpoint and surrounding infrastructure can observe connection destinations, timing, and volume. Application-level privacy still depends on the application's TLS configuration and the destination. Do not point an application at this local adapter if its traffic is not authorized for observation.

## Active probing and network scope

JSONL and CONNECT targets are untrusted input for the network dialer. A careless probe service could be used for server-side request forgery or to touch cloud metadata, loopback administration, or private infrastructure. Phase 1 scope defaults to public IP addresses on ports 443 and 8443. Sensitive, private, loopback, and reserved ranges require explicit `-allow-cidr` policy; unspecified and multicast addresses are always rejected. Custom ports require `-ports`. DNS answers are checked before dialing, and the selected IP is pinned across that dial. Rejecting an entire mixed authorized/unauthorized DNS answer set reduces DNS rebinding and split-horizon surprises. The same scope policy applies to proxy forwarding and independent probes.

Operators should still review any private CIDR they authorize. A broad CIDR can expose internal services to both forwarding and active probes. Scope enforcement is a policy control, not proof of destination ownership. Rate limits, bounded queues/workers, timeouts, certificate-size limits, deduplication, caching, and refresh intervals reduce accidental load. Probes make separate handshakes and are visible to destination servers. They send no HTTP requests or application authentication material.

An endpoint may require a client certificate or present different chains according to SNI, TLS features, network route, CDN edge, load balancer, or time. A failed or different probe cannot by itself establish interception or compromise. For a private endpoint, run the observer in the relevant customer network; a remote vantage is a distinct observation.

## Certificate and trust analysis

The server-presented list is direct probe evidence. A candidate path is derived using a named trust-store configuration and cryptographic verification; a root supplied by that store is labeled inferred if it was not presented. Verification errors and unresolved issuers remain visible rather than being silently turned into a trusted path. A self-signed certificate is not necessarily a trust anchor. Exact certificate and public-key fingerprints support identity matching; subject and issuer text cannot establish CA identity. Public-key matching covers a key, not all keys of a CA organization.

Certificate retrieval intentionally permits an invalid chain on **Certainted's own probe connection** so the presented evidence is available. Validation is then performed separately. This has no effect on the original application's TLS validation. Certainted does not reuse its cookies, client certificates, credentials, or secrets. A future optional AIA or CT lookup would disclose queried certificate or hostname metadata to third parties and must be opt-in with recorded provenance; Phase 1 makes no such requests.

## Revocation evidence

The built-in eMudhra incident entries are offline copies of exact public-key identities from published incident records. Their compromise and revocation labels cite those records; Certainted has not independently fetched or verified the issuer CRLs for them. They belong to the watchlist evidence path, not the signed-CRL path. A matching probe is evidence that the endpoint presented a certificate with an affected key at that probe time and vantage, not that the user's application saw or accepted it. The affected root is not seeded as a compromised key. The two code-signing keys are outside ordinary TLS observation. Updates to the bundled list require a reviewed software release; no remote source can silently change it.

CRL import verifies a signed list against an operator-supplied issuer certificate, including update times and supported full-list scope. It does not validate that issuer certificate against an application trust store or establish the operator's source as authoritative. The imported CRL, issuer certificate, and URL may be sensitive. A local file import has no third-party lookup; entering a URL deliberately makes a request from the Certainted host. The CRL host sees the full request; network observers can see the destination and, over HTTP, the URL path and query. Neither path runs automatically, and there is no scheduled refresh. Unsupported delta, indirect, or partitioned lists are rejected rather than silently treated as complete coverage. Revocation is a certificate status; its presence does not by itself mean a CA was compromised.

The URL fetch is a separate SSRF boundary from destination probing. It accepts HTTP(S) only, limits destinations to public IPs on ports 80/443, rejects a DNS answer set containing private or sensitive addresses, pins the approved IP across the connection, and rejects redirects. It uses no application credentials or proxy settings and has bounded response size and connection/total time. A signed CRL still needs an issuer certificate selected by the operator: transport TLS, an HTTP server, or a CRL URL alone does not establish that issuer's trust or authority. Operators should review the source and refresh an imported list when needed.

An exact raw issuer-name and serial match is a possible identity match. Where a presented issuer or verified candidate path confirms the certificate signature with the CRL issuer's public key, the finding can be labeled cryptographically verified. Matching based only on issuer name and key identifiers is explicitly labeled a candidate. A positive entry applies only from its revocation time onward. A missing entry or expired CRL never proves a certificate was unrevoked. Stale CRLs must be visible to operators; continued use requires an updated import.

The application contact event and the probe's certificate observation are different evidence. Certainted cannot conclude that the application saw or accepted a revoked certificate. A direct finding says the independent probe was presented the certificate; a candidate-path finding is inferred. Neither interrupts traffic.

## Local dashboard and API

The dashboard displays untrusted certificate and hostname strings using text nodes rather than HTML interpolation. Its scripts and styles are local, with no analytics or external assets. The local HTTP service should reject non-loopback binds in Phase 1, unexpected Host values, cross-origin state-changing requests, and permissive CORS. Restrictive Content Security Policy, frame protection, and `nosniff` headers reduce browser-origin and local-service attacks. These protections matter even for a loopback app because an arbitrary web page may try to contact local services or exploit DNS rebinding.

The `stop` command uses a loopback-only control request to trigger the existing graceful shutdown path. The control route requires the same local Host, origin checks, and explicit intent header as other state changes, plus a random per-run token stored in a private directory under the user's cache directory. The command must run as the same local user and know the dashboard listener address. A program with access to that user's token can request shutdown; protecting the local account and its cache files remains necessary. On Windows, control-file privacy relies on the user profile's filesystem ACLs.

Phase 1 has no user authentication or HTTPS termination for the dashboard/API or CONNECT proxy. Do not publish these listeners on a public interface, put them behind an unauthenticated tunnel, or expose the SQLite file or exports to other users. Remote access belongs in Phase 2 with authentication, transport protection, and deployment-specific policy.

## Optional community sharing and public receiver

Sharing is off by default. Manual mode displays the exact public JSON and requires selecting a report; Auto share requires a separate explicit choice and only considers observations after activation. A public hostname or fingerprint can still identify services a person uses. Previously published reports remain public when Auto share is disabled. The local bridge must send an allowlisted report rather than serializing an inventory/export record. It omits IP addresses, workloads, collector and network-vantage identities, exact probe times, source URLs, and raw certificate/CRL data. The client does not inherit `HTTPS_PROXY`, send application credentials, or follow redirects. Failed publication does not affect application traffic or probing.

The Internet-facing `public-serve` mode is isolated from the private observer API and database. Its receiver checks report shape and size, caps total storage and request rate, and treats all submitted content as untrusted. It does **not** authenticate reporters, verify that a probe occurred, confirm historic certificate presentation, establish an application's trust decision, or verify a reported watchlist status. A malicious sender can fabricate plausible reports or repeat a true report; deduplication is not an anti-abuse identity system. The public service never probes a submitted hostname or fetches a submitted URL, avoiding an attacker-directed network dialer. Its UI renders submitted strings as text and shows an unverified label. The public reverse proxy should provide HTTPS, host-level request controls and a deliberate access-log policy; it may still observe sender IPs even though the application does not store them intentionally.

## Storage, retention, and incident use

Inventory data includes hostnames, IP addresses, certificate contents, timestamps, collector identity, vantage, and optional workload identity. Protect database backups and CSV/JSON exports as sensitive operational data. Automatic retention is configurable through `-retention-days`; `prune -before` removes older records explicitly. An old destination event remains while a newer refresh probe still references it, so provenance is not broken. Full deletion requires stopping the service and removing the database and copies/exports. SQLite deletion does not by itself erase historical filesystem snapshots or backups.

Watchlist findings are potential exposure evidence. A direct match means a watched certificate/key was seen in an independent probe's presented chain. A candidate match means a trust-store path included it. A name-only match is a search lead. None of these proves the application saw or trusted that chain. Human status labels need a recorded reason and source when used for incident response. Changes to watch rules reevaluate historical observations, so an analyst can investigate a time window without implying all applications in that window made identical trust decisions.

## Residual limitations

- Direct UDP/QUIC and applications bypassing the proxy are invisible to CONNECT collection.
- IP-only flow metadata can have ambiguous hostname identity, especially with shared IPs and ECH. TLS 1.3 and encrypted traffic limit what metadata collectors can infer.
- Certificates are sampled at probe time. Short-lived or selective certificate presentation may be missed, and caching means a destination event need not create a new probe.
- A selectively targeted attacker may evade independent probes; discrepancies can also be benign. Certainted is not guaranteed MITM detection or an enforcement point.
- Phase 1 is local and single-observer. Cross-vantage correlation, authenticated remote access, application-session instrumentation, CT enrichment, and AIA fetching are deferred.
