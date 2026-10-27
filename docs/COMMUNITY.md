# Public community reports

`certainted public-serve` runs a **separate** public dashboard for `certainted.com`. It accepts small, unauthenticated reports and stores them in its own SQLite database. Do not expose the local `certainted serve` dashboard, API, proxy, or inventory database to the Internet.

The local dashboard offers Manual and Auto share near **Potential CA exposure**. Manual share previews each complete public report before sending it; if its contents change before the send, Certainted asks for a fresh review. The preview scans up to 1,000 recent local candidates and shows up to 100 eligible reports. Auto share is off by default; enabling it explicitly sends eligible **future** findings without another review. Both modes use HTTPS to `https://certainted.com/api/v1/reports`. Disabling Auto share stops future sends; reports already published remain public. A failed send leaves the finding local for retry. `-share-url` can point at an HTTP loopback receiver for local testing; production HTTPS sharing is restricted to `certainted.com`.

## What is published

A report names a **public destination hostname and port**, a UTC observation day, a certificate SHA-256 fingerprint, an evidence label, and one of two finding types:

| Type | Additional fields | Interpretation |
| --- | --- | --- |
| CRL match | Certificate serial; CRL, issuer-certificate, and issuer-key SHA-256 fingerprints; revocation and CRL update times | The reporter says a certificate directly presented to its independent probe was listed in a locally imported, signature-verified CRL, with a verified issuer-key path. |
| CA watchlist match | Exact certificate or key fingerprint; operator-assigned status and severity | The reporter says a watched CA certificate/key was directly presented to its probe or appeared in a candidate path. Status is the reporter's own label. |

The sharing code excludes IP-only and nonpublic destinations, name-only watch matches, and monitored-only watch entries. It does not send workload identity, collector identity, network vantage, device/user identity, destination IP, exact probe time, source URLs, application content, raw certificates, or raw CRLs. It never sends a raw local export. Hostnames and certificate fingerprints can still reveal sites a person or organization uses, so review reports carefully and enable Auto share only if that disclosure is acceptable.

The public service does not authenticate reporters, probe submitted hosts, fetch submitted CRL URLs, or verify that a claimed probe took place. It deduplicates identical reports and bounds request sizes and stored records; those limits do not make the content trustworthy. The dashboard labels every item **unverified community report**. A recipient can probe the listed hostname independently and compare fingerprints, but a later or different-vantage probe cannot prove what the reporter saw earlier. A CRL claim needs the matching CRL and issuer certificate from a trusted source for independent signature and revocation checks. A watchlist status needs an authoritative source before being treated as a CA verdict.

The receiver does not intentionally persist sender IP addresses or user-agent strings. Its host, reverse proxy, DNS provider, and network path can still see connection metadata. Keep access logs disabled or set a deliberate retention policy if you enable them.

## Run on a Linux VPS

Build the same executable on the VPS, then run the public service with a database **separate** from local observer databases:

```sh
go build -o certainted .
./certainted public-serve -db /var/lib/certainted/community.db -http 127.0.0.1:8790
```

Keep the public service bound to loopback and put an HTTPS reverse proxy in front of it. For example, a Caddyfile can contain:

```caddyfile
certainted.com {
	reverse_proxy 127.0.0.1:8790
}

www.certainted.com {
	redir https://certainted.com{uri} permanent
}
```

The repository includes [deploy/certainted-public.service](../deploy/certainted-public.service) and [deploy/Caddyfile](../deploy/Caddyfile) as deployment examples. Install the executable at `/opt/certainted/certainted`, copy the service to `/etc/systemd/system/`, and place the Caddyfile at `/etc/caddy/Caddyfile`; then enable both services. The service uses systemd's `DynamicUser` and `StateDirectory` so its public SQLite file remains private and persistent.

Point the apex domain's A/AAAA records at the VPS and point `www` at the same VPS (for example, with a `www` CNAME to `certainted.com`) so Caddy can serve HTTPS and redirect it to the apex. Remove or update conflicting web-hosting A, CNAME, and HTTPS/SVCB address-hint records from the previous host; preserve unrelated email and domain-connection records. Allow inbound ports 80 and 443, and keep 8790 private. Caddy's [automatic HTTPS](https://caddyserver.com/docs/automatic-https) can obtain and renew certificates for both names when DNS and network reachability are set up; [`reverse_proxy`](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) forwards the apex site to the loopback service. Back up the SQLite file. Restrict the host firewall. The sample systemd unit caps the public service at 384 MiB and 128 tasks for a 1 GiB VPS; adjust these limits based on measured usage.

The receiver retains reports for up to 365 days and 25,000 records, returns at most 200 recent reports per listing, and uses a **global** in-memory limit of five submissions per second with a 60-request burst. These are capacity bounds, not abuse prevention: one anonymous sender can exhaust the submission allowance, fill the feed with fabricated claims, and evict older reports. The public dashboard labels every report unverified. Before relying on this feed as a public source, add moderation, incident response, and host-level abuse controls appropriate to traffic levels.

`GET /api/v1/reports` and `GET /api/v1/stats` serve the public dashboard. `POST /api/v1/reports` accepts the bounded report format. No public endpoint exposes a local observer's full inventory or offers a remote probe operation.
