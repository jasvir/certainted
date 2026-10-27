# Certainted

Certainted is a local certificate-observation agent. It learns destinations from metadata events or applications configured to use its HTTP CONNECT proxy, makes **separate TLS connections** to those destinations, and records the certificates presented to its probes. The proxy listener starts by default and can be disabled with `serve -noproxy`; applications must opt in to using it. Its main task is to find destinations that are still contacted when Certainted's probe presents a certificate listed in an imported certificate revocation list (CRL) or matches a known affected CA key. It also supports a CA watchlist for broader investigations.

> **Certainted observes and alerts; it does not block connections or prevent an application from using a revoked certificate.** A revocation finding means a contacted destination's independent probe presented a certificate listed as revoked by an imported CRL, or a reconstructed candidate path contained it. It does not prove which certificate chain the application received or trusted.

The optional CONNECT proxy sees destination metadata and relays encrypted application bytes, but it does not decrypt, inspect, or store application contents or terminate the application's TLS session. Certainted opens its own separate TLS connection to retrieve the certificate chain presented to its probe. That chain may differ from the one the application receives. Certainted does not install a root CA or change application certificate validation.

## Download a prebuilt executable

Choose a build for your computer from [GitHub Releases](https://github.com/jasvir/certainted/releases/latest). Each archive contains a single `certainted` executable (`certainted.exe` on Windows); extract it into a folder you control, then follow [Start the dashboard and proxy](#start-the-dashboard-and-proxy). You do not need Go or Node.js to run a prebuilt executable.

| System | Download |
| --- | --- |
| macOS, Apple Silicon | [ARM64 archive](https://github.com/jasvir/certainted/releases/latest/download/certainted_darwin_arm64.tar.gz) |
| macOS, Intel | [x64 archive](https://github.com/jasvir/certainted/releases/latest/download/certainted_darwin_amd64.tar.gz) |
| Windows, x64 | [x64 ZIP](https://github.com/jasvir/certainted/releases/latest/download/certainted_windows_amd64.zip) |
| Windows, ARM64 | [ARM64 ZIP](https://github.com/jasvir/certainted/releases/latest/download/certainted_windows_arm64.zip) |
| Linux, x64 | [x64 archive](https://github.com/jasvir/certainted/releases/latest/download/certainted_linux_amd64.tar.gz) |
| Linux, ARM64 | [ARM64 archive](https://github.com/jasvir/certainted/releases/latest/download/certainted_linux_arm64.tar.gz) |

The release also includes [SHA-256 checksums](https://github.com/jasvir/certainted/releases/latest/download/checksums.txt). These builds are not code signed or notarized, so your operating system may warn before running them. Review the source and verify the checksum before making a local exception. While the repository is private, GitHub access is required for both downloads and source.

## Install from source

Install [Go 1.23 or newer](https://go.dev/doc/install) and Git, then clone the [Certainted repository](https://github.com/jasvir/certainted). The dashboard is embedded in the Go executable; Node.js is needed only if you change its TypeScript source.

**macOS or Linux (Terminal):**

```bash
git clone https://github.com/jasvir/certainted.git
cd certainted
go build -o certainted .
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/jasvir/certainted.git
cd certainted
go build -o certainted.exe .
```

Windows builds successfully, but automated runtime tests currently run only on macOS and Linux. To run the local test suite on your machine, use `go test ./...` from the repository directory. The core tests use local services and generated certificates, without requiring public Internet access.

## Start the dashboard and proxy

Start Certainted in one terminal. By default, the dashboard listens on `127.0.0.1:8787` and the CONNECT proxy listens on `127.0.0.1:8080`.

| Action | macOS / Linux | Windows PowerShell |
| --- | --- | --- |
| Start | `./certainted serve` | `.\certainted.exe serve` |
| Stop (from another terminal) | `./certainted stop` | `.\certainted.exe stop` |

Without `-db`, Certainted uses `certainted.db` for a new installation. If `certained.db` already exists and `certainted.db` does not, it uses the existing file so your history remains available. It does not move or rename database files. You can always choose a file explicitly with `-db`; for example, `./certainted serve -db certained.db`.

Open [the local dashboard](http://127.0.0.1:8787/) while Certainted is running. Both listeners are loopback-only; `127.0.0.1` in the instructions below assumes Certainted and the application run on the **same computer**.

Use `-proxy 127.0.0.1:PORT` to choose another loopback proxy address. Use `-noproxy` when you want only the dashboard and metadata ingestion, with no CONNECT listener. Keep proxy settings in applications aligned with the chosen port; applications configured to use a stopped or disabled proxy may be unable to connect.

Run the stop command under the **same user account** as the running instance. It targets the default dashboard address, `127.0.0.1:8787`. If you started Certainted with a different dashboard listener, use the same address with `./certainted stop -http 127.0.0.1:PORT` (or the Windows executable). The command waits for the dashboard listener to close; active CONNECT tunnels are closed during shutdown. To stop a version that predates this command, press Ctrl+C in its terminal once, then restart with the updated executable. Stopping Certainted does not turn off an `HTTPS_PROXY` environment variable or an operating-system proxy setting.

## Option 1: Set `HTTPS_PROXY` for selected applications

Set the variable in the terminal from which you start a compatible application:

**macOS or Linux:**

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://example.com/
```

**Windows PowerShell:**

```powershell
$env:HTTPS_PROXY = 'http://127.0.0.1:8080'
curl.exe https://example.com/
```

For a direct test without environment variables, run `curl --proxy http://127.0.0.1:8080 https://example.com/` (use `curl.exe` on Windows). The destination should appear in the dashboard after its independent probe completes. Some applications ignore `HTTPS_PROXY` or require their own proxy setting; see [client examples for curl, Python, Java, Go, and Node.js](docs/CLIENTS.md). An existing `NO_PROXY` setting can also bypass the proxy.

## Option 2: Use your operating system's HTTPS proxy setting

These settings affect applications that honor the operating system's web-proxy configuration. Configure **HTTPS only**: Certainted accepts CONNECT tunnels and rejects ordinary plaintext HTTP requests.

| System | HTTPS-only setup |
| --- | --- |
| **macOS** | System Settings → Network → active Wi-Fi or Ethernet service → Details → Proxies → **Secure Web Proxy (HTTPS)**. Set server `127.0.0.1`, port `8080`. Leave **Web Proxy (HTTP)** off. [Apple instructions](https://support.apple.com/en-gb/guide/mac-help/mchlp2591/mac) |
| **Windows** | Press Win+R, run `inetcpl.cpl`, then **Connections → LAN settings**. Select **Use a proxy server for your LAN**, open **Advanced**, and clear **Use the same proxy server for all protocols**. Set only **Secure** to `127.0.0.1`, port `8080`; leave HTTP, FTP, and SOCKS blank. This applies to apps using Windows' user proxy settings; some services and apps have separate settings. [Microsoft proxy guidance](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge-proxy-support) |
| **Linux (GNOME)** | Settings → Network → Network Proxy → Manual. Set only the **HTTPS** proxy to `127.0.0.1`, port `8080`. Other Linux desktops have different menus. [GNOME instructions](https://help.gnome.org/gnome-help/net-proxy.html) |

Avoid Windows' basic **Settings → Network & internet → Proxy → Manual proxy setup** with Certainted: that single proxy can also receive plaintext HTTP, which Certainted rejects. [Microsoft protocol scope](https://learn.microsoft.com/en-us/windows/client-management/mdm/networkproxy-csp)

No OS proxy setting guarantees coverage of every application. Direct connections, VPN-specific routes, and UDP/QUIC traffic may bypass the CONNECT proxy. A tunnel may contain multiple HTTPS requests, which Certainted neither reads nor counts.

Turn off the OS proxy setting when you stop Certainted, or applications using that setting may be unable to connect.

## Option 3: Ingest destination metadata without the proxy

Save a file named `events.jsonl` containing a destination you are authorized to probe:

```json
{"collector":"manual-jsonl","vantage":"my-computer","hostname":"example.com","port":443}
```

Then ingest it and run the dashboard with `-noproxy`:

| macOS / Linux | Windows PowerShell |
| --- | --- |
| `./certainted ingest -file events.jsonl` | `.\certainted.exe ingest -file events.jsonl` |
| `./certainted serve -noproxy` | `.\certainted.exe serve -noproxy` |

Use `-file -` to read JSON Lines from standard input. Events can also include `time` (RFC 3339), `ip`, and `workload` with `attribution_reliable: true` when the source can support that attribution; see [the collector format](ARCHITECTURE.md). This path does not forward application traffic.

## Check for revoked certificates

Certainted ships an offline, incident-specific watch for the eight eMudhra intermediate CA keys reported compromised and revoked in October 2026. Those keys cover 16 reported revoked certificate variants: eight issued by eMudhra and eight cross-signed by Sectigo. Six keys belong to TLS intermediates; two belong to code-signing intermediates that ordinary TLS probes will not encounter. The watches match exact **public-key SHA-256 fingerprints**, so a cross-sign or another certificate using the same affected key is covered without relying on CA names. They are labeled as incident-based CA exposure findings, **not** as findings from a locally verified CRL. Historical key matches can predate the certificates' revocation dates; compare probe and revocation times before describing a past observation as post-revocation. The related emSign ECC root was distrusted as a precaution; its key was not reported compromised and is not seeded as a revoked intermediate. See [eMudhra incident identifiers and sources](docs/EMUDHRA_2026.md).

Certainted does not fetch CRLs automatically or ship a general revocation list. For signed CRL evidence, supply a CRL and the certificate of its issuer from a source you trust. In the dashboard's **CA watchlist & CRLs** section, select **CRL file** or **CRL URL**, provide the issuer certificate file, and select **Import**. The **Revoked certificates** section shows only imported-CRL findings and history; built-in eMudhra matches appear under **CA exposure**. A URL is fetched by the local Certainted server only when you submit the form. The CRL host sees the request; network observers can see the destination and, with HTTP, the URL path and query. A local file is sent only to the loopback API for import. Certainted verifies the CRL signature and validity period against the supplied issuer certificate; this does **not** establish that the issuer certificate is a trusted root or that the source is authoritative.

URL imports allow public IP destinations on ports 80 and 443. Redirects and private or local destinations are rejected; the fetch has a 10-second timeout and an 8 MiB response limit. URL fetching does not use application credentials or proxy settings. The default stored source records only the URL scheme and host, omitting path and query; add a source note if you need a more specific reference. Imported lists are not refreshed automatically; import a new CRL when it changes.

**macOS or Linux:**

```bash
./certainted crl import -file issuer.crl -issuer issuer.pem -source 'operator-supplied CRL'
```

**Windows PowerShell:**

```powershell
.\certainted.exe crl import -file issuer.crl -issuer issuer.pem -source 'operator-supplied CRL'
```

Run `./certainted crl list` (or `.\certainted.exe` on Windows) to see imported lists. The dashboard shows post-revocation findings and their CRL provenance. Importing a CRL reevaluates stored probes; future probes are checked too. Matching requires the certificate's raw issuer name and serial number, not a substring of its display name. The dashboard labels whether the issuer key relationship was cryptographically verified or is only a key-identifier candidate. A CRL entry is not itself evidence that the CA was compromised: revocation can have many reasons.

The CRL must be a current, supported full list. Expired, future, delta, indirect, or partitioned CRLs are rejected instead of being treated as proof that an unlisted certificate is good. Certainted makes no third-party request for a local file import and makes no scheduled CRL requests. Check the source and refresh your imported CRLs yourself. Older probe records created before issuer identity was stored need a fresh probe for exact matching.

To export revocation findings, run `./certainted export -resource revocations -format csv` (or choose `json`). The dashboard also offers local JSON/CSV exports. Protect CRLs, database files, and exports as operational evidence.

## Watchlists, notifications, and limits

The CA watchlist starts with the eight incident-based eMudhra key watches described above. On first use of an existing database, Certainted adds missing built-in identities and reevaluates historical probes. It does not replace a matching rule you already configured, and deleting or editing a seeded rule is respected on later starts. In **CA watchlist & CRLs**, add other rules using an exact certificate or public-key SHA-256 fingerprint from the inventory, or load a watchlist with **JSON file** or **CSV file**. The **Export JSON** and **Export CSV** controls download watch entries; they do not import them. File imports accept up to 2 MiB and 256 entries at a time. Larger exports must be split before reimporting. Imported record IDs are replaced with local IDs, exact duplicates are skipped, and stored observations are reevaluated. If an entry lacks `source`, Certainted records that it came from a JSON or CSV watchlist. JSON is the lossless interchange format for watchlist text: CSV export adds spreadsheet-formula guards that can make literal leading apostrophes ambiguous on reimport. Other CA status labels are assigned by their source or by you and need supporting evidence. Findings distinguish certificates **presented to a probe** from roots found only in a **candidate trust path**.

The dashboard shows findings even if notifications are off. To receive optional browser notifications, click **Enable alerts** and grant permission. Certainted checks while the dashboard is open and notifies about eligible stored or newly found destination matches, summarizing matches found in the same check. A later independent probe of a previously alerted match can notify again after a 30-minute cooldown. Notification receipts are kept in the browser's site storage so reloading the dashboard does not repeat the same alert. **Send test notification** reports whether the browser showed the notification, reported an error, or gave no confirmation; the operating system still controls whether a banner appears. Click the **×** to collapse the alert controls without pausing alerts; **Show options** expands them again. Notifications report potential exposure, not confirmed application use. Neither findings nor failed probes interrupt CONNECT traffic.

## Optional community sharing

The local dashboard can publish selected findings to the separate public receiver at [certainted.com](https://certainted.com). Sharing is **off by default**. In Manual mode, review the exact report before sending it. Auto share requires an explicit opt-in and sends eligible future reports without another review. Reports include a public destination hostname, port, certificate fingerprint, observation day, and CRL or CA watchlist evidence; they omit workload, device identity, destination IP, and application content. A hostname or certificate fingerprint may still reveal a site you use. The public feed is unauthenticated, and reports are labeled unverified rather than proof of an application's TLS result or a CA's status. See [Public community reports](docs/COMMUNITY.md) for the report format, privacy limits, and VPS setup.

By default, Certainted probes and tunnels only to public IP addresses on ports 443 and 8443. To include private destinations, configure a narrow `-allow-cidr` (or `-allow-private` for private global-unicast IPs); use `-ports` for other ports. Keep the dashboard, proxy, SQLite database, and exports local and access-controlled; Phase 1 has no remote authentication. Use `-retention-days` or `prune -before` to remove old evidence.

For the evidence model, destination scope, privacy limits, and future work, see [Architecture](ARCHITECTURE.md), [Threat model](THREAT_MODEL.md), and [Roadmap](docs/ROADMAP.md).

## License

Certainted is available under the [MIT License](LICENSE).
