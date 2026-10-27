import { h, render, type ComponentChildren } from "preact";
import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { compactNoticeState, dueNoticeCandidates, markNotified, mergeNoticeStates, parseNoticeState, type NoticeCandidate, type NoticeState } from "./notification_tracker";

type Evidence = "direct" | "candidate" | "name_only" | string;
interface Certificate {
  fingerprint_sha256: string; spki_sha256: string; subject: string; issuer: string; serial: string;
  not_before: string; not_after: string; dns_names?: string[]; ip_addresses?: string[];
  email_addresses?: string[]; uris?: string[]; is_ca: boolean; basic_constraints_valid: boolean;
  max_path_len: number; max_path_len_zero: boolean; key_usage: number;
  self_signed: boolean; public_key_algorithm: string; key_bits?: number; source: string;
}
interface CandidatePath { certificates: Certificate[]; validation: string }
interface DestinationEvent {
  id: number; time: string; collector: string; vantage: string; hostname?: string; ip?: string;
  port: number; workload?: string; attribution_reliable?: boolean;
}
interface Probe {
  id: number; destination_id: number; time: string; vantage: string; hostname?: string; target_ip?: string;
  port: number; sni?: string; tls_version?: string; cipher_suite?: string; presented?: Certificate[];
  candidate_paths?: CandidatePath[]; trust_store?: string; validation_error?: string; failure?: string;
  incomplete_chain?: boolean;
}
interface Watch {
  id: number; name: string; group?: string; match_type: string; value: string; status: string;
  severity: string; reason?: string; source?: string; effective_from?: string; effective_to?: string;
}
interface IncidentManifest {
  id: string; as_of: string; description: string; sources: string[];
  intermediates: {
    name: string; usage: string; spki_sha256: string;
    certificates: { issued_by: string; sha256: string; serial_hex: string }[];
  }[];
}
interface Finding {
  id: number; watch_id: number; probe_id: number; destination_id: number; evidence: Evidence;
  certificate_fingerprint: string; time: string;
}
interface RevocationFinding {
  id: number; crl_id: number; destination_id: number; destination_key?: string; probe_id: number; certificate_fingerprint: string;
  certificate_serial: string; evidence: Evidence; issuer_match: "verified_path" | "key_identifier_candidate" | string;
  revoked_at: string; reason: string; reason_code: number;
  time: string; issuer: string; source: string; crl_fingerprint_sha256: string;
  crl_this_update: string; crl_next_update: string; crl_this_update_after_probe: boolean; crl_stale_at_probe: boolean;
}
interface CRLRecord {
  id: number; source: string; issuer: string; fingerprint_sha256: string;
  issuer_fingerprint_sha256: string; this_update: string; next_update: string;
  imported_at: string; entry_count: number;
}
interface CRLImportResult { id: number; entry_count: number; source: string }
interface WatchImportResult { imported: number; skipped?: number; ids?: number[] }

function syncCRLFieldValidity(event: Event): void {
  const input = event.currentTarget as HTMLInputElement;
  if (input.matches(":user-invalid")) input.setAttribute("aria-invalid", "true");
  else input.removeAttribute("aria-invalid");
}
function markCRLFieldInvalid(event: Event): void {
  (event.currentTarget as HTMLInputElement).setAttribute("aria-invalid", "true");
}
interface Alert {
  watch_id: number; destination_id: number; destination_key: string; evidence: Evidence; first_seen: string;
  last_seen: string; observation_count: number; latest_probe_id: number;
}
interface CAMatch { watch_id: number; name: string; status: string; evidence: Evidence }
interface CARecord {
  certificate: Certificate; first_seen: string; last_seen: string; presented_observations: number;
  candidate_observations: number; destination_count: number; watch_matches?: CAMatch[];
}
interface Stats {
  destination_events?: number; unique_destinations?: number; probed_destinations?: number;
  probes?: number; last_24h_probes?: number; successful_probes?: number; failed_probes?: number;
  observed_ca_certificates?: number; watchlist_matches?: number; affected_destinations?: number;
  verified_direct_revocations?: number;
  latest_probe?: string;
}
type CommunityMode = "manual" | "auto";
interface CommunityPreviewItem { id: string; report_id: string; report: unknown; shared: boolean }
interface CommunityPreview { mode: CommunityMode; reports: CommunityPreviewItem[] }
type Row = { key: string; cells: ComponentChildren[] };
type TimeFilter = { watchID: string; from: string; to: string };
type RevocationFilter = { from: string; to: string; evidence: string };

function dateText(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function timestamp(value?: string): number {
  const time = value ? Date.parse(value) : NaN;
  return Number.isFinite(time) ? time : 0;
}
function shortHash(value?: string): string {
  return value ? (value.length > 20 ? `${value.slice(0, 16)}…` : value) : "—";
}
function destinationKey(destination: DestinationEvent): string {
  return [destination.hostname || "", destination.ip || "", destination.port, destination.vantage].join("|");
}
function destinationText(destination?: DestinationEvent): string {
  if (!destination) return "Unknown destination";
  const host = destination.hostname || destination.ip || "Unknown host";
  return `${host}${destination.hostname && destination.ip ? ` (${destination.ip})` : ""}:${destination.port}`;
}
function destinationTextOrID(destination: DestinationEvent | undefined, id: number): string {
  return destination ? destinationText(destination) : `Destination event #${id} (outside recent list)`;
}
function evidenceText(value: Evidence): string {
  return value === "direct" ? "Directly presented" : value === "candidate" ? "Candidate path" : value === "name_only" ? "Name only" : value || "Unknown";
}
function keyUsageText(mask: number): string {
  const names: [number, string][] = [[1, "digital signature"], [2, "content commitment"], [4, "key encipherment"], [8, "data encipherment"], [16, "key agreement"], [32, "certificate signing"], [64, "CRL signing"], [128, "encipher only"], [256, "decipher only"]];
  const active = names.filter(([bit]) => (mask & bit) !== 0).map(([, name]) => name);
  return active.length ? active.join(", ") : "not specified";
}
function timeQuery(filter: TimeFilter, limit = 10000): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) });
  if (filter.watchID) query.set("watch_id", filter.watchID);
  if (filter.from) query.set("from", new Date(filter.from).toISOString());
  // The API uses an exclusive upper bound. A datetime-local choice includes its selected minute.
  if (filter.to) query.set("to", new Date(new Date(filter.to).getTime() + 60_000).toISOString());
  return query;
}
function revocationQuery(filter: RevocationFilter, limit = 10000): URLSearchParams {
  const query = new URLSearchParams({ limit: String(limit) });
  if (filter.from) query.set("from", new Date(filter.from).toISOString());
  if (filter.to) query.set("to", new Date(new Date(filter.to).getTime() + 60_000).toISOString());
  if (filter.evidence) query.set("evidence", filter.evidence);
  return query;
}
async function getJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json() as Promise<T>;
}
function asList<T>(value: T[] | { items?: T[] } | null): T[] {
  return Array.isArray(value) ? value : value?.items || [];
}

function Badge({ evidence, children }: { evidence?: string; children: ComponentChildren }) {
  return <span class={`badge ${evidence || ""}`.trim()}>{children}</span>;
}
function Stacked({ primary, secondary }: { primary: ComponentChildren; secondary?: ComponentChildren }) {
  return <div><div class="primary">{primary}</div>{secondary && <div class="secondary">{secondary}</div>}</div>;
}
function DataTable({ caption, headers, rows, empty }: { caption: string; headers: string[]; rows: Row[]; empty: string }) {
  if (!rows.length) return <p class="empty">{empty}</p>;
  return <table>
    <caption>{caption}</caption>
    <thead><tr>{headers.map((header) => <th scope="col" key={header}>{header}</th>)}</tr></thead>
    <tbody>{rows.map((row) => <tr key={row.key}>{row.cells.map((content, index) => <td key={index}>{content}</td>)}</tr>)}</tbody>
  </table>;
}
function ExportLinks({ resource, filter, query }: { resource: string; filter?: TimeFilter; query?: URLSearchParams }) {
  return <div class="export-links">{(["json", "csv"] as const).map((format) => {
    const params = query ? new URLSearchParams(query) : filter ? timeQuery(filter, 100000) : new URLSearchParams();
    params.delete("limit");
    params.set("format", format);
    return <a key={format} href={`/api/export/${encodeURIComponent(resource)}?${params.toString()}`} download={`certainted-${resource}.${format}`}>Export {format.toUpperCase()}</a>;
  })}</div>;
}
function SectionHeader({ number, eyebrow, title, titleID, exportResource, filter, exportQuery }: { number: string; eyebrow: string; title: string; titleID: string; exportResource?: string; filter?: TimeFilter; exportQuery?: URLSearchParams }) {
  return <div class="section-heading"><div><p class="eyebrow">{number} / {eyebrow}</p><h2 id={titleID}>{title}</h2></div>{exportResource && <ExportLinks resource={exportResource} filter={filter} query={exportQuery} />}</div>;
}
function CertificateList({ certificates, context }: { certificates: Certificate[]; context: string }) {
  if (!certificates.length) return <p>No certificates recorded.</p>;
  return <ol>{certificates.map((certificate, index) => <li key={`${certificate.fingerprint_sha256}-${index}`}>
    <div class="primary">{certificate.subject || "Unknown subject"} · {certificate.is_ca ? "CA" : "leaf"} · <Badge evidence={certificate.source === "trust_store" ? "candidate" : certificate.source === "presented" ? "direct" : ""}>{certificate.source === "trust_store" ? "Trust-store candidate (inferred)" : certificate.source === "presented" ? "Presented by endpoint" : context}</Badge></div>
    <div class="secondary">Issuer: {certificate.issuer || "unknown"}; serial: {certificate.serial || "unknown"}</div>
    <div class="mono">Certificate SHA-256: {certificate.fingerprint_sha256 || "unknown"}</div>
    <div class="mono">Public-key SHA-256: {certificate.spki_sha256 || "unknown"}</div>
    <div class="secondary">{dateText(certificate.not_before)} to {dateText(certificate.not_after)} · {certificate.public_key_algorithm || "key algorithm unknown"}{certificate.key_bits ? ` · ${certificate.key_bits} bits` : ""}{certificate.self_signed ? " · self-signed (not automatically trusted)" : ""}</div>
    <div class="secondary">Basic constraints: {certificate.basic_constraints_valid ? (certificate.is_ca ? "CA" : "not CA") : "not marked valid"}{certificate.max_path_len_zero ? "; max path length 0" : certificate.max_path_len > 0 ? `; max path length ${certificate.max_path_len}` : ""}; key usage: {keyUsageText(certificate.key_usage || 0)}</div>
    {Boolean(certificate.dns_names?.length || certificate.ip_addresses?.length || certificate.email_addresses?.length || certificate.uris?.length) && <div class="secondary">SANs: {[...(certificate.dns_names || []), ...(certificate.ip_addresses || []), ...(certificate.email_addresses || []), ...(certificate.uris || [])].join(", ")}</div>}
  </li>)}</ol>;
}
function ProbeDetails({ probe }: { probe: Probe }) {
  return <details><summary>View probe evidence</summary><div class="detail-content">
    <p>Target: {probe.target_ip || probe.hostname || "unknown"}:{probe.port}; SNI: {probe.sni || "none"}; vantage: {probe.vantage || "unknown"}</p>
    <p>TLS: {probe.tls_version || "unknown"}; cipher: {probe.cipher_suite || "unknown"}</p>
    <p>Trust store: {probe.trust_store || "not configured"}; validation: {probe.validation_error || "no validation error recorded"}</p>
    {probe.failure && <p>Probe failure: {probe.failure}</p>}
    {probe.incomplete_chain && <p>The presented chain was incomplete.</p>}
    <h4>Presented by endpoint</h4><CertificateList certificates={probe.presented || []} context="presented" />
    <h4>Candidate paths ({probe.candidate_paths?.length || 0})</h4>
    {!probe.candidate_paths?.length && <p>No validated candidate path recorded.</p>}
    {(probe.candidate_paths || []).map((path, index) => <div key={index}>
      <p>Path {index + 1}: {path.validation || "validation unavailable"}</p>
      <CertificateList certificates={path.certificates || []} context="candidate path" />
    </div>)}
  </div></details>;
}

function WatchForm({ onSaved }: { onSaved: () => Promise<void> }) {
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    if (!form.reportValidity()) return;
    const values = new FormData(form);
    const matchType = String(values.get("match_type") || "");
    let value = String(values.get("value") || "").trim();
    if (matchType !== "name") {
      value = value.replace(/[:\s]/g, "").toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(value)) {
        setMessage("Certificate and public-key fingerprints must be 64 hexadecimal characters.");
        return;
      }
    }
    const from = String(values.get("effective_from") || "");
    const to = String(values.get("effective_to") || "");
    if (from && to && timestamp(from) >= timestamp(to)) {
      setMessage("The effective-until date must follow the effective-from date.");
      return;
    }
    const payload = {
      name: String(values.get("name") || "").trim(),
      group: String(values.get("group") || "").trim(),
      match_type: matchType,
      value,
      status: String(values.get("status") || "monitored"),
      severity: String(values.get("severity") || "info"),
      reason: String(values.get("reason") || "").trim(),
      source: String(values.get("source") || "").trim() || "Manual dashboard entry",
      ...(from ? { effective_from: new Date(from).toISOString() } : {}),
      ...(to ? { effective_to: new Date(to).toISOString() } : {}),
    };
    setSaving(true);
    setMessage("Saving entry and reevaluating stored observations…");
    try {
      const response = await fetch("/api/watches", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-Certainted-Intent": "1" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error((await response.text()).slice(0, 300) || `HTTP ${response.status}`);
      form.reset();
      await onSaved();
      setMessage("Watchlist entry saved. Historical probe observations were reevaluated.");
    } catch (error) {
      setMessage(`Could not save watchlist entry: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setSaving(false);
    }
  }
  return <details class="watch-form-wrap"><summary>Add a watchlist entry</summary>
    <form id="watch-form" action="/api/watches" method="post" onSubmit={(event) => void submit(event)}>
      <div class="form-grid">
        <div><label htmlFor="watch-name">Name</label><input id="watch-name" name="name" required maxLength={200} /></div>
        <div><label htmlFor="watch-group">Organization / group</label><input id="watch-group" name="group" maxLength={200} /></div>
        <div><label htmlFor="watch-match-type">Match by</label><select id="watch-match-type" name="match_type"><option value="cert_sha256">Certificate SHA-256</option><option value="spki_sha256">Public key SHA-256</option><option value="name">Name only</option></select></div>
        <div><label htmlFor="watch-value">Match value</label><input id="watch-value" name="value" required maxLength={500} aria-describedby="watch-value-help" autoCorrect="off" autoCapitalize="off" spellcheck={false} /><small id="watch-value-help">Use a hex SHA-256 fingerprint for exact certificate or public-key matches.</small></div>
        <div><label htmlFor="watch-status">Status</label><select id="watch-status" name="status"><option value="monitored">Monitored</option><option value="under investigation">Under investigation</option><option value="distrusted">Distrusted</option><option value="compromised">Compromised</option></select></div>
        <div><label htmlFor="watch-severity">Severity</label><select id="watch-severity" name="severity"><option value="info">Info</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
        <div><label htmlFor="watch-effective-from">Effective from</label><input id="watch-effective-from" name="effective_from" type="datetime-local" /></div>
        <div><label htmlFor="watch-effective-to">Effective until (exclusive)</label><input id="watch-effective-to" name="effective_to" type="datetime-local" /></div>
        <div class="wide"><label htmlFor="watch-reason">Reason</label><textarea id="watch-reason" name="reason" rows={2} maxLength={2000} /></div>
        <div class="wide"><label htmlFor="watch-source">Source / reference</label><input id="watch-source" name="source" maxLength={500} /></div>
      </div>
      <button type="submit" disabled={saving}>Save and reevaluate history</button>
      <p id="watch-result" role="status" aria-live="polite">{message}</p>
    </form>
  </details>;
}

type ImportKind = "json" | "csv" | "crl-file" | "crl-url";

function MonitoringImports({ onImported }: { onImported: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [kind, setKind] = useState<ImportKind | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  useEffect(() => {
    if (kind && !dialog.current?.open) dialog.current?.showModal();
  }, [kind]);

  function open(kindToOpen: ImportKind): void {
    if (saving) return;
    setMessage("");
    setError(false);
    setKind(kindToOpen);
  }

  const isCRL = kind === "crl-file" || kind === "crl-url";
  const title = kind === "json" ? "Import JSON watchlist" : kind === "csv" ? "Import CSV watchlist" : kind === "crl-file" ? "Import CRL file" : "Import CRL URL";

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    if (!kind) return;
    const form = event.currentTarget as HTMLFormElement;
    if (!form.reportValidity()) return;
    const payload = new FormData(form);
    if (kind === "crl-url") {
      const value = String(payload.get("crl_url") || "").trim();
      let url: URL;
      try { url = new URL(value); } catch {
        setError(true);
        setMessage("Enter a complete HTTP or HTTPS CRL URL.");
        return;
      }
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        setError(true);
        setMessage("The CRL URL must start with https:// or http://.");
        return;
      }
      payload.set("crl_url", url.href);
    }
    if (isCRL) payload.set("method", kind === "crl-url" ? "url" : "file");
    else payload.set("format", kind);
    setSaving(true);
    setError(false);
    setMessage(isCRL ? (kind === "crl-url" ? "Fetching and verifying this CRL…" : "Verifying and importing this CRL…") : "Importing watches and reevaluating stored probes…");
    try {
      const response = await fetch(isCRL ? "/api/revocations/import" : "/api/watches/import", {
        method: "POST", credentials: "same-origin",
        headers: { Accept: "application/json", "X-Certainted-Intent": "1" },
        body: payload,
      });
      const raw = await response.text();
      let result: (CRLImportResult & WatchImportResult) & { error?: string };
      try { result = JSON.parse(raw) as (CRLImportResult & WatchImportResult) & { error?: string }; }
      catch { throw new Error(response.ok ? "The server returned an invalid response." : `HTTP ${response.status}: ${raw.slice(0, 200)}`); }
      if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
      form.reset();
      onImported();
      dialog.current?.close();
      setMessage(isCRL
        ? `CRL #${result.id} imported with ${result.entry_count} revoked serial${result.entry_count === 1 ? "" : "s"}. Stored probes were reevaluated.`
        : result.imported
          ? `${result.imported} watchlist entr${result.imported === 1 ? "y" : "ies"} imported${result.skipped ? `; ${result.skipped} duplicate${result.skipped === 1 ? "" : "s"} skipped` : ""}. Stored probes were reevaluated.`
          : `No new watches imported; ${result.skipped || 0} duplicate${result.skipped === 1 ? "" : "s"} skipped.`);
    } catch (cause) {
      setError(true);
      setMessage(`Could not import ${isCRL ? "CRL" : "watchlist"}: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      setSaving(false);
    }
  }

  return <div class="monitoring-imports" aria-label="Import monitoring sources">
    <div class="import-actions">
      <span class="import-actions-label">Load from</span>
      <button type="button" onClick={() => open("json")} disabled={saving}>JSON file</button>
      <button type="button" onClick={() => open("csv")} disabled={saving}>CSV file</button>
      <button type="button" onClick={() => open("crl-file")} disabled={saving}>CRL file</button>
      <button type="button" onClick={() => open("crl-url")} disabled={saving}>CRL URL</button>
    </div>
    {!kind && message && <p class={error ? "import-result error" : "import-result"} role="status" aria-live="polite">{message}</p>}
    <dialog ref={dialog} class="import-dialog" aria-labelledby="import-dialog-title" onCancel={(event) => { if (saving) event.preventDefault(); }} onClose={() => setKind(null)}>
      {kind && <>
        <div class="import-dialog-heading"><h3 id="import-dialog-title">{title}</h3><button type="button" class="dialog-close" onClick={() => dialog.current?.close()} aria-label="Close import dialog" disabled={saving}>×</button></div>
        <p class="import-dialog-description">{isCRL
          ? "Choose a certificate revocation list and its issuer certificate. Certainted verifies the CRL signature and checks stored and future independent probes. The issuer certificate does not become a trusted root."
          : "Load up to 256 CA watch entries from a file up to 2 MiB. Certificate, public-key, and name matching rules are supported. Imported entries are checked against stored probe history."}</p>
        {kind === "crl-url" && <p class="import-dialog-note">Certainted fetches this URL once when you import it. The request reveals your network address and request metadata to that host. Lists are not refreshed automatically.</p>}
        <form method="post" encType="multipart/form-data" onSubmit={(event) => void submit(event)}>
          <div class="import-fields">
            {(kind === "json" || kind === "csv") && <div><label htmlFor="watch-import-file">{kind.toUpperCase()} watchlist file</label><input id="watch-import-file" name="file" type="file" accept={kind === "json" ? ".json,application/json" : ".csv,text/csv"} required /></div>}
            {kind === "crl-file" && <div><label htmlFor="crl-import-file">CRL file (PEM or DER)</label><input id="crl-import-file" name="crl_file" type="file" accept=".crl,.pem,.der,application/pkix-crl" required onBlur={syncCRLFieldValidity} onChange={syncCRLFieldValidity} onInvalid={markCRLFieldInvalid} /></div>}
            {kind === "crl-url" && <div><label htmlFor="crl-import-url">CRL URL (HTTP or HTTPS)</label><input id="crl-import-url" name="crl_url" type="url" placeholder="https://ca.example/revocations.crl" autoCorrect="off" autoCapitalize="off" spellcheck={false} required aria-describedby="crl-url-help" onBlur={syncCRLFieldValidity} onInput={syncCRLFieldValidity} onInvalid={markCRLFieldInvalid} /><small id="crl-url-help">Public addresses on standard HTTP or HTTPS ports only; redirects are not followed.</small></div>}
            {isCRL && <><div><label htmlFor="crl-import-issuer">Issuer certificate (PEM or DER)</label><input id="crl-import-issuer" name="issuer_file" type="file" accept=".crt,.cer,.pem,.der,application/pkix-cert" required onBlur={syncCRLFieldValidity} onChange={syncCRLFieldValidity} onInvalid={markCRLFieldInvalid} /></div><div><label htmlFor="crl-import-source">Source note (optional)</label><input id="crl-import-source" name="source" type="text" maxLength={500} placeholder="CA bulletin or internal reference" /></div></>}
          </div>
          <div class="dialog-actions"><button type="button" class="secondary-button" onClick={() => dialog.current?.close()} disabled={saving}>Cancel</button><button type="submit" disabled={saving}>{saving ? "Importing…" : "Import"}</button></div>
          <p class={error ? "import-result error" : "import-result"} role="status" aria-live="polite">{message}</p>
        </form>
      </>}
    </dialog>
  </div>;
}

const alertPreferenceKey = "certainted.desktop-alerts.enabled";
const alertCollapsedKey = "certainted.desktop-alerts.collapsed.v2";
const alertReceiptKey = "certainted.desktop-alerts.receipts.v1";
const legacyAlertPreferenceKey = "certained.desktop-alerts.enabled";
const maxAlertReceipts = 12000;

function alertPermission(): NotificationPermission | "unsupported" {
  if (!window.isSecureContext || typeof Notification === "undefined") return "unsupported";
  return Notification.permission;
}

function savedAlertFlag(key: string, legacyKey: string): boolean {
  try {
    const current = window.localStorage.getItem(key);
    if (current !== null) return current === "1";
    const legacy = window.localStorage.getItem(legacyKey);
    if (legacy !== null) {
      window.localStorage.setItem(key, legacy);
      window.localStorage.removeItem(legacyKey);
    }
    return legacy === "1";
  } catch { return false; }
}

function savedAlertPreference(): boolean {
  return savedAlertFlag(alertPreferenceKey, legacyAlertPreferenceKey);
}

function saveAlertPreference(enabled: boolean): void {
  try {
    if (enabled) window.localStorage.setItem(alertPreferenceKey, "1");
    else window.localStorage.removeItem(alertPreferenceKey);
  } catch { /* Alerts still work for this open page when storage is unavailable. */ }
}

function savedAlertCollapse(): boolean {
  // Earlier versions removed the prompt entirely when dismissed. Start those
  // users with the full prompt again; only a new collapse is persisted.
  try { return window.localStorage.getItem(alertCollapsedKey) === "1"; } catch { return false; }
}

function alertIdentity(alert: Alert): string {
  return JSON.stringify([alert.watch_id, alert.evidence, alert.destination_key]);
}

function revocationIdentity(finding: RevocationFinding): string {
  return JSON.stringify([finding.destination_key || finding.destination_id, finding.certificate_fingerprint, finding.evidence, finding.issuer_match]);
}

function loadAlertReceipts(): NoticeState {
  try { return parseNoticeState(window.localStorage.getItem(alertReceiptKey)); } catch { return {}; }
}

function saveAlertReceipts(receipts: NoticeState): NoticeState {
  try {
    const merged = compactNoticeState(mergeNoticeStates(loadAlertReceipts(), receipts), maxAlertReceipts);
    window.localStorage.setItem(alertReceiptKey, JSON.stringify(merged));
    return merged;
  } catch { return receipts; /* Alerts still work for this open page. */ }
}

function showDesktopNotification(title: string, body: string, onOpen?: () => void): Notification | null {
  try {
    const notification = new Notification(title, { body });
    if (onOpen) notification.onclick = () => { window.focus(); onOpen(); notification.close(); };
    return notification;
  } catch { return null; }
}

function DesktopAlerts({ onNewAlert, onOpenAlert, onOpenRevocation }: { onNewAlert: () => void; onOpenAlert: () => void; onOpenRevocation: () => void }) {
  const [permission, setPermission] = useState(alertPermission);
  const [enabled, setEnabled] = useState(savedAlertPreference);
  const [collapsed, setCollapsed] = useState(savedAlertCollapse);
  const [message, setMessage] = useState("");
  const [showPermissionHelp, setShowPermissionHelp] = useState(false);
  const active = enabled && permission === "granted";

  async function enable(): Promise<void> {
    if (permission === "unsupported") return;
    try {
      // A permission prompt must follow this explicit button click.
      const result = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
      setPermission(result);
      if (result === "granted") {
        saveAlertPreference(true);
        setEnabled(true);
        setShowPermissionHelp(false);
        setMessage("Alerts enabled. Certainted will check stored and new findings while this page is open.");
      } else {
        setShowPermissionHelp(true);
        setMessage(result === "denied"
          ? "Notifications are blocked for this address in your browser settings."
          : "The browser did not grant permission. It may have dismissed or suppressed the prompt.");
      }
    } catch {
      setShowPermissionHelp(true);
      setMessage("The browser could not request notification permission.");
    }
  }

  function pause(): void {
    saveAlertPreference(false);
    setEnabled(false);
    setMessage("Desktop alerts paused for Certainted.");
  }

  function sendTest(): void {
    if (Notification.permission !== "granted") {
      setPermission(Notification.permission);
      setMessage("Browser notification permission is no longer granted. Check this site's notification setting.");
      return;
    }
    const notification = showDesktopNotification(
      "Certainted test notification",
      "Your local dashboard requested this test notification.",
    );
    if (!notification) {
      setMessage("This browser could not create a test notification. Check its notification settings.");
      return;
    }
    let completed = false;
    const timer = window.setTimeout(() => {
      if (!completed) setMessage("The browser gave no display confirmation. Check system notification settings and Focus mode.");
    }, 5000);
    notification.addEventListener("show", () => {
      completed = true;
      window.clearTimeout(timer);
      setMessage("The browser reported showing the test notification. Your operating system can still hide its banner.");
    }, { once: true });
    notification.addEventListener("error", () => {
      completed = true;
      window.clearTimeout(timer);
      setMessage("The browser reported a notification delivery error. Check browser and system notification settings.");
    }, { once: true });
    setMessage("Waiting for the browser to report whether it showed the test notification…");
  }

  function toggleCollapsed(): void {
    const next = !collapsed;
    setCollapsed(next);
    if (!next) setPermission(alertPermission());
    try {
      if (next) window.localStorage.setItem(alertCollapsedKey, "1");
      else window.localStorage.removeItem(alertCollapsedKey);
    } catch { /* The control still works for this open page. */ }
  }

  useEffect(() => {
    if (!active) return;
    let current = true;
    let checking = false;
    let receipts = loadAlertReceipts();
    let previousAlertVersion: string | null = null;
    let previousRevocationVersion: string | null = null;
    async function check(): Promise<void> {
      if (!current || checking) return;
      checking = true;
      try {
        if (Notification.permission !== "granted") {
          setPermission(Notification.permission);
          setEnabled(false);
          saveAlertPreference(false);
          return;
        }
        const [alertResult, revocationResult] = await Promise.allSettled([
          getJSON<Alert[]>("/api/alerts?limit=10000"),
          getJSON<RevocationFinding[]>("/api/revocations/findings?limit=1000"),
        ]);
        if (!current) return;
        receipts = mergeNoticeStates(receipts, loadAlertReceipts());
        let inventoryChanged = false;
        let notificationFailed = false;
        let notificationRequested = false;
        const failedChecks: string[] = [];
        const now = Date.now();

        if (alertResult.status === "fulfilled") {
          const alerts = asList(alertResult.value);
          const version = JSON.stringify(alerts.map((alert) => [alertIdentity(alert), alert.latest_probe_id]));
          if (previousAlertVersion !== null && version !== previousAlertVersion) inventoryChanged = true;
          previousAlertVersion = version;
          const candidates = alerts.filter((alert) => alert.evidence === "direct" || alert.evidence === "candidate")
            .map((alert): NoticeCandidate => ({ key: `ca:${alertIdentity(alert)}`, probeId: alert.latest_probe_id }));
          const due = dueNoticeCandidates(candidates, receipts, now);
          if (due.length) {
            const requested = showDesktopNotification(
              "Certainted: potential CA exposure",
              `${due.length} destination match${due.length === 1 ? "" : "es"} in independent probes. Review the CA watch and probe evidence.`,
              onOpenAlert,
            );
            if (requested) {
              receipts = saveAlertReceipts(markNotified(receipts, due, now));
              notificationRequested = true;
            } else notificationFailed = true;
          }
        } else failedChecks.push("CA watches");

        if (revocationResult.status === "fulfilled") {
          const revocations = asList(revocationResult.value);
          const version = JSON.stringify(revocations.map((finding) => [finding.id, finding.probe_id]));
          if (previousRevocationVersion !== null && version !== previousRevocationVersion) inventoryChanged = true;
          previousRevocationVersion = version;
          const candidatesByKey = new Map<string, NoticeCandidate>();
          for (const finding of revocations) {
            if (finding.evidence !== "direct" || finding.issuer_match !== "verified_path" || finding.crl_stale_at_probe) continue;
            const key = `crl:${revocationIdentity(finding)}`;
            const prior = candidatesByKey.get(key);
            if (!prior || finding.probe_id > prior.probeId) candidatesByKey.set(key, { key, probeId: finding.probe_id });
          }
          const due = dueNoticeCandidates([...candidatesByKey.values()], receipts, now);
          if (due.length) {
            const requested = showDesktopNotification(
              "Certainted: revoked certificate in probe",
              `${due.length} destination match${due.length === 1 ? "" : "es"} with direct independent-probe evidence. Review the CRL and probe details.`,
              onOpenRevocation,
            );
            if (requested) {
              receipts = saveAlertReceipts(markNotified(receipts, due, now));
              notificationRequested = true;
            } else notificationFailed = true;
          }
        } else failedChecks.push("revocation findings");

        if (inventoryChanged) onNewAlert();
        if (notificationFailed) {
          saveAlertPreference(false);
          setEnabled(false);
          setMessage("This browser could not create a desktop notification. Findings remain available in the dashboard.");
        } else if (failedChecks.length) {
          setMessage(`Could not check ${failedChecks.join(" and ")}; Certainted will retry while this page is open.`);
        } else if (notificationRequested) {
          setMessage("Browser notification requested. If no banner appears, use Send test notification and check browser and system settings.");
        }
      } catch {
        if (current) setMessage("Could not check for new alerts; Certainted will retry while this page is open.");
      } finally {
        checking = false;
      }
    }
    void check();
    const timer = window.setInterval(() => void check(), 30_000);
    return () => { current = false; window.clearInterval(timer); };
  }, [active, onNewAlert, onOpenAlert, onOpenRevocation]);

  const description = permission === "unsupported"
    ? "This browser cannot show desktop notifications here. Findings remain available in Revoked certificates and CA exposure."
    : permission === "denied"
      ? "Notifications are blocked for this local address. Change the browser site setting to enable them."
      : active
        ? "On while this dashboard is open. Certainted checks for direct revocation findings and CA watch matches."
        : "Get a local browser alert for direct revocation findings and CA watch matches while this dashboard is open.";
  const compactStatus = active ? "On" : permission === "denied" ? "Blocked" : permission === "unsupported" ? "Unavailable" : "Off";
  const permissionHelp = permission !== "granted" && (permission === "unsupported" || permission === "denied" || showPermissionHelp);
  return <aside class={`desktop-alerts${collapsed ? " is-collapsed" : ""}`} aria-label="Desktop alerts">
    {collapsed && <div class="desktop-alerts-compact-label"><strong>Desktop alerts</strong><span>{compactStatus}</span></div>}
    <div id="desktop-alerts-details" hidden={collapsed}>
      <h3>Desktop alerts</h3>
      <p>{description}</p>
      <p class="alert-message" role="status">{message}</p>
      {permissionHelp && <p class="alert-permission-help">Open this local dashboard at <code>{window.location.origin}</code> directly in Chrome. In Chrome's site settings for this address, set Notifications to Allow, then reload. If you dismissed the prompt, you can also click Enable alerts again.</p>}
    </div>
    <div class="desktop-alerts-actions">
      {!collapsed && active && <button type="button" class="test-alerts" onClick={sendTest}>Send test notification</button>}
      {!collapsed && (active ? <button type="button" onClick={pause}>Pause alerts</button>
        : permission !== "unsupported" && permission !== "denied" ? <button type="button" onClick={() => void enable()}>Enable alerts</button> : null)}
      <button type="button" class={collapsed ? "expand-alerts" : "dismiss-alerts"} onClick={toggleCollapsed} aria-controls="desktop-alerts-details" aria-expanded={!collapsed} aria-label={collapsed ? "Show desktop alert options" : "Collapse desktop alert options"} title={collapsed ? "Show desktop alert options" : "Collapse desktop alert options"}>{collapsed ? "Show options" : "×"}</button>
    </div>
  </aside>;
}

function Overview({ stats, destinations, probes, findings, revocationFindings, crlCount, watchCount, onNewAlert, onOpenAlert, onOpenRevocation, onProbeFilter }: { stats: Stats; destinations: DestinationEvent[]; probes: Probe[]; findings: Finding[]; revocationFindings: RevocationFinding[]; crlCount: number; watchCount: number; onNewAlert: () => void; onOpenAlert: () => void; onOpenRevocation: () => void; onProbeFilter: (filter: "all" | "failed") => void }) {
  const unique = stats.unique_destinations ?? new Set(destinations.map(destinationKey)).size;
  const probed = stats.probed_destinations ?? new Set(probes.map((probe) => probe.destination_id)).size;
  const failed = stats.failed_probes ?? probes.filter((probe) => Boolean(probe.failure)).length;
  const affected = stats.affected_destinations ?? new Set(findings.map((finding) => finding.destination_id)).size;
  const matches = stats.watchlist_matches ?? findings.length;
  const events = stats.destination_events ?? destinations.length;
  const directRevocations = revocationFindings.filter((finding) => finding.evidence === "direct" && finding.issuer_match === "verified_path");
  const candidateRevocations = revocationFindings.filter((finding) => finding.evidence !== "direct" || finding.issuer_match !== "verified_path");
  const verifiedDestinations = new Set(directRevocations.map((finding) => finding.destination_key || finding.destination_id)).size;
  const cards = [
    { label: "Verified direct probe matches", value: crlCount ? (stats.verified_direct_revocations ?? directRevocations.length) : "—", detail: crlCount ? `${verifiedDestinations} destination${verifiedDestinations === 1 ? "" : "s"} in loaded history; ${candidateRevocations.length} other potential match${candidateRevocations.length === 1 ? "" : "es"}` : "Import a CRL to check stored probes", href: crlCount ? "#revocations" : "#watchlist", action: crlCount ? "Review revocation evidence" : "Load a CRL", attention: (stats.verified_direct_revocations ?? directRevocations.length) > 0 },
    { label: "Potential exposure", value: watchCount ? affected : "—", detail: watchCount ? `${matches} watchlist finding${matches === 1 ? "" : "s"} in stored history` : "Add a CA watch to start matching", href: watchCount ? "#exposure" : "#watchlist", action: watchCount ? "Investigate exposure" : "Set up watchlist", attention: affected > 0 },
    { label: "Destinations observed", value: unique, detail: `${events} collector event${events === 1 ? "" : "s"} received`, href: "#destinations", action: "Browse destinations" },
    { label: "Probe failures", value: failed, detail: `${probed} of ${unique} destinations ever probed`, href: "#probes", action: "Inspect failed probes", onClick: () => onProbeFilter("failed") },
  ];
  const latest = stats.latest_probe || probes.reduce((max, probe) => timestamp(probe.time) > timestamp(max) ? probe.time : max, "");
  return <section id="overview" aria-labelledby="overview-title">
    <SectionHeader number="01" eyebrow="Summary" title="Overview" titleID="overview-title" />
    <div class="stat-grid">{cards.map((card) => <a class={`stat${card.attention ? " attention" : ""}`} href={card.href} key={card.label} onClick={card.onClick}>
      <span class="stat-label">{card.label}</span><strong class="stat-value">{typeof card.value === "number" ? new Intl.NumberFormat().format(card.value) : card.value}</strong>
      <span class="stat-detail">{card.detail}</span><span class="stat-action">{card.action} <span aria-hidden="true">↗</span></span>
    </a>)}</div>
    <DesktopAlerts onNewAlert={onNewAlert} onOpenAlert={onOpenAlert} onOpenRevocation={onOpenRevocation} />
    <div class="note-row"><p>Collector events and independent probes are separate; neither counts application requests. Revocation matches are from Certainted probes.</p><p><a href="#probes">Latest probe: {dateText(latest)}</a></p></div>
  </section>;
}

function RevocationsView({ crls, findings, destinations, filter, setFilter, search, setSearch }: {
  crls: CRLRecord[]; findings: RevocationFinding[]; destinations: DestinationEvent[];
  filter: RevocationFilter; setFilter: (filter: RevocationFilter) => void; search: string; setSearch: (value: string) => void;
}) {
  const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
  const needle = search.trim().toLowerCase();
  const rows: Row[] = findings.filter((finding) => {
    const destination = destinationsByID.get(finding.destination_id);
    const haystack = `${destinationTextOrID(destination, finding.destination_id)} ${finding.certificate_fingerprint} ${finding.certificate_serial} ${finding.issuer} ${finding.reason} ${finding.source}`.toLowerCase();
    return !needle || haystack.includes(needle);
  }).sort((a, b) => timestamp(b.time) - timestamp(a.time)).map((finding) => {
    const destination = destinationsByID.get(finding.destination_id);
    const source = finding.source || `Imported CRL #${finding.crl_id}`;
    return { key: `${finding.crl_id}-${finding.probe_id}-${finding.certificate_fingerprint}`, cells: [
      <Stacked primary={destinationTextOrID(destination, finding.destination_id)} secondary={destination?.vantage ? `Vantage: ${destination.vantage}` : undefined} />,
      <div><div class="mono">SHA-256: {finding.certificate_fingerprint || "—"}</div><div class="mono">Serial: {finding.certificate_serial || "—"}</div></div>,
      <div><Badge evidence={finding.evidence}>{finding.evidence === "direct" ? "Presented to probe" : "Candidate path (inferred)"}</Badge><div class="issuer-match"><Badge evidence={finding.issuer_match === "verified_path" ? "success" : "candidate"}>{finding.issuer_match === "verified_path" ? "Issuer path verified" : "Issuer link requires review"}</Badge></div></div>,
      <Stacked primary={dateText(finding.revoked_at)} secondary={finding.reason || `Reason code ${finding.reason_code}`} />,
      <Stacked primary={dateText(finding.time)} secondary={`Probe #${finding.probe_id}`} />,
      <div><div class="primary">{finding.issuer || "Unknown issuer"}</div><div class="secondary">Source: {source}</div><div class="secondary">Valid {dateText(finding.crl_this_update)} to {dateText(finding.crl_next_update)}</div>{finding.crl_this_update_after_probe && <Badge evidence="candidate">CRL update dated after probe</Badge>}{finding.crl_stale_at_probe && <Badge evidence="failed">Stale at probe time</Badge>}</div>,
    ] };
  });
  const now = Date.now();
  const crlRows: Row[] = [...crls].sort((a, b) => timestamp(b.imported_at) - timestamp(a.imported_at)).map((crl) => {
    const expired = timestamp(crl.next_update) <= now;
    return { key: String(crl.id), cells: [
      <Stacked primary={crl.issuer || "Unknown issuer"} secondary={<code class="mono">{crl.issuer_fingerprint_sha256 || "Issuer certificate unknown"}</code>} />,
      <span class="mono">{crl.source || "Local import"}</span>,
      <Stacked primary={<Badge evidence={expired ? "failed" : "success"}>{expired ? "Expired" : "Current"}</Badge>} secondary={`${dateText(crl.this_update)} to ${dateText(crl.next_update)}`} />,
      crl.entry_count ?? "—",
      dateText(crl.imported_at),
    ] };
  });
  return <section id="revocations" aria-labelledby="revocations-title">
    <SectionHeader number="03" eyebrow="Revocation" title="Revoked certificates" titleID="revocations-title" exportResource="revocations" exportQuery={revocationQuery(filter, 100000)} />
    <p class="section-description">This section uses imported, signature-verified CRLs. The built-in eMudhra incident keys are separate <a href="#watchlist">CA watchlist</a> entries; their matches appear under <a href="#exposure">CA exposure</a>. For CRL findings, “presented” is direct probe evidence and “candidate path” is inferred. Neither establishes which certificate the original application received or trusted.</p>
    <div class="filters">
      <div><label htmlFor="revocation-from">Probed from</label><input id="revocation-from" type="datetime-local" value={filter.from} onChange={(event) => setFilter({ ...filter, from: event.currentTarget.value })} /></div>
      <div><label htmlFor="revocation-to">Probed through</label><input id="revocation-to" type="datetime-local" value={filter.to} onChange={(event) => setFilter({ ...filter, to: event.currentTarget.value })} /></div>
      <div><label htmlFor="revocation-evidence">Evidence</label><select id="revocation-evidence" value={filter.evidence} onChange={(event) => setFilter({ ...filter, evidence: event.currentTarget.value })}><option value="">All matches</option><option value="direct">Presented to probe</option><option value="candidate">Candidate path (inferred)</option></select></div>
      <div><label htmlFor="revocation-search">Search findings</label><input id="revocation-search" type="search" placeholder="Destination, serial, issuer, or reason" value={search} onInput={(event) => setSearch(event.currentTarget.value)} /></div>
    </div>
    <div class="table-wrap"><DataTable caption={`${rows.length} post-revocation finding record${rows.length === 1 ? "" : "s"}${findings.length >= 10000 ? " (API limit reached; use export for more)" : ""}`} headers={["Destination", "Certificate", "Evidence", "Revoked / reason", "Probe observed", "CRL provenance"]} rows={rows} empty={crls.length ? "No post-revocation findings for these filters." : "No CRLs imported yet. Load a signed CRL in CA watchlist & CRLs to compare it with stored probes."} /></div>
    <div class="section-heading subsection-heading"><h3 id="imported-crls">Imported CRLs</h3><ExportLinks resource="crls" /></div>
    <p class="section-description">Certainted uses locally imported, signature-verified CRLs. Expired lists remain historical evidence; import a newer CRL for current status.</p>
    <div class="table-wrap"><DataTable caption={`${crlRows.length} imported CRL${crlRows.length === 1 ? "" : "s"}`} headers={["Issuer", "Source", "Freshness", "Revoked serials", "Imported"]} rows={crlRows} empty="No CRLs imported yet." /></div>
  </section>;
}

function CommunityShare() {
  const dialog = useRef<HTMLDialogElement>(null);
  const [mode, setMode] = useState<CommunityMode | null>(null);
  const [preview, setPreview] = useState<CommunityPreviewItem[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [pendingAuto, setPendingAuto] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [dialogMessage, setDialogMessage] = useState("");

  async function loadPreview(): Promise<CommunityPreview> {
    const result = await getJSON<CommunityPreview>("/api/community/preview");
    if (result.mode !== "manual" && result.mode !== "auto") throw new Error("Invalid sharing mode returned by the local server.");
    if (!Array.isArray(result.reports) || result.reports.some((item) => typeof item.id !== "string" || typeof item.report_id !== "string" || typeof item.report !== "object" || item.report === null)) throw new Error("Invalid sharing preview returned by the local server.");
    setMode(result.mode);
    setPreview(result.reports);
    return result;
  }

  useEffect(() => {
    let active = true;
    void getJSON<CommunityPreview>("/api/community/preview").then((result) => {
      if (!active) return;
      if ((result.mode === "manual" || result.mode === "auto") && Array.isArray(result.reports) && result.reports.every((item) => typeof item.id === "string" && typeof item.report_id === "string" && typeof item.report === "object" && item.report !== null)) {
        setMode(result.mode);
        setPreview(result.reports);
      } else setMessage("The local sharing service returned an invalid response.");
    }).catch((error: unknown) => {
      if (active) setMessage(`Sharing is unavailable: ${error instanceof Error ? error.message : String(error)}`);
    });
    return () => { active = false; };
  }, []);

  async function postJSON(path: string, payload: unknown): Promise<void> {
    const response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json", "X-Certainted-Intent": "1" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error((await response.text()).slice(0, 250) || `HTTP ${response.status}`);
  }

  async function openPreview(forAuto: boolean): Promise<void> {
    setMessage("");
    setDialogMessage("");
    setLoading(true);
    try {
      await loadPreview();
      setSelected([]);
      setPendingAuto(forAuto);
      dialog.current?.showModal();
    } catch (error) {
      setMessage(`Could not load the exact sharing preview: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function turnOffAuto(): Promise<void> {
    setSaving(true);
    try {
      await postJSON("/api/community/mode", { mode: "manual" });
      setMode("manual");
      setMessage("Auto share is off. Reports remain local until you choose Share.");
    } catch (error) {
      setMessage(`Could not change sharing mode: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setSaving(false);
    }
  }

  async function confirm(): Promise<void> {
    setSaving(true);
    setMessage("");
    setDialogMessage("");
    let sharedCount = 0;
    try {
      if (pendingAuto) {
        await postJSON("/api/community/mode", { mode: "auto" });
        setMode("auto");
        setMessage("Auto share is on for future eligible reports. You can turn it off here at any time.");
      } else {
        for (const id of selected) {
          const item = preview.find((report) => report.id === id);
          if (!item) throw new Error("A selected report is no longer in the preview. Review the reports again before sharing.");
          await postJSON("/api/community/share", { id, report_id: item.report_id });
          sharedCount++;
          setPreview((current) => current.map((report) => report.id === id ? { ...report, shared: true } : report));
          setSelected((current) => current.filter((selectedID) => selectedID !== id));
        }
        setMessage(`${sharedCount} report${sharedCount === 1 ? "" : "s"} submitted to certainted.com. Public submissions are unverified claims.`);
      }
      dialog.current?.close();
      setSelected([]);
    } catch (error) {
      const failure = `Could not complete sharing${sharedCount ? ` after ${sharedCount} report${sharedCount === 1 ? "" : "s"} was submitted` : ""}: ${error instanceof Error ? error.message : String(error)}`;
      setMessage(failure);
      setDialogMessage(failure);
      // Keep the preview open so the user can review or retry.
    } finally {
      setSaving(false);
    }
  }

  function toggleSelection(id: string, checked: boolean): void {
    setSelected((current) => checked ? [...current, id] : current.filter((item) => item !== id));
  }

  const unshared = preview.filter((item) => !item.shared);
  return <aside class="community-share" aria-labelledby="community-share-title">
    <div class="community-share-head">
      <div><h3 id="community-share-title">Share a finding</h3><p>Send eligible independent-probe reports to <strong>certainted.com</strong>. Shared reports include public hostnames and certificate evidence. They do not include private destinations, workload identity, collector metadata, or local probe IDs.</p></div>
      <div class="community-share-actions">
        <label class="community-share-switch" htmlFor="community-auto-share"><input id="community-auto-share" type="checkbox" role="switch" checked={mode === "auto"} disabled={mode === null || loading || saving} onChange={(event) => { const requestedAuto = event.currentTarget.checked; event.currentTarget.checked = mode === "auto"; if (requestedAuto) void openPreview(true); else void turnOffAuto(); }} /> Auto share</label>
        {mode === "manual" && <button type="button" disabled={loading || saving} onClick={() => void openPreview(false)}>{loading ? "Loading preview…" : "Share…"}</button>}
      </div>
    </div>
    <p class="community-share-help">Manual is the default. Auto share is opt-in and sends future eligible reports; turning it on does not submit earlier findings. A public hostname and certificate fingerprint can reveal your interest in that destination. The public dashboard has no account verification, so every report is labeled unverified.</p>
    <p class="community-share-message" role="status" aria-live="polite">{message}</p>
    <dialog ref={dialog} class="import-dialog community-share-dialog" aria-labelledby="community-preview-title" onCancel={(event) => { if (saving) event.preventDefault(); }} onClose={() => { setPendingAuto(false); setSelected([]); }}>
      <div class="import-dialog-heading"><h3 id="community-preview-title">{pendingAuto ? "Enable Auto share" : "Review reports to share"}</h3><button type="button" class="dialog-close" aria-label="Close sharing preview" disabled={saving} onClick={() => dialog.current?.close()}>×</button></div>
      <p class="import-dialog-description">These are the exact public report payloads prepared by your local Certainted server. They include public hostnames and certificate evidence. The receiving site accepts unauthenticated submissions and does not independently verify the probe.</p>
      {pendingAuto && <p class="import-dialog-note">Enabling Auto share sends <strong>future</strong> eligible reports to certainted.com without asking again. Reports below are examples from existing findings and are not sent when you enable Auto share.</p>}
      {!preview.length && <p class="empty">No eligible public reports are available to preview yet.</p>}
      <div class="community-preview-list">{preview.map((item, index) => {
        const id = String(item.id);
        return <div class="community-preview-item" key={`${id}-${index}`}>
          <div class="community-preview-label">{pendingAuto ? <strong>Example {index + 1}</strong> : <label><input type="checkbox" checked={selected.includes(id)} disabled={item.shared || saving} onChange={(event) => toggleSelection(id, event.currentTarget.checked)} /> Report {index + 1}</label>}{item.shared && <span class="badge success">Already shared</span>}</div>
          <pre>{JSON.stringify(item.report, null, 2)}</pre>
        </div>;
      })}</div>
      <p class="import-dialog-note">A certificate fingerprint and revocation or watchlist metadata help others check the claim, but the public site cannot establish what an application actually received or trusted.</p>
      <p class="community-dialog-message" role="status" aria-live="polite">{dialogMessage}</p>
      <div class="dialog-actions"><button type="button" class="secondary-button" autoFocus disabled={saving} onClick={() => dialog.current?.close()}>Cancel</button><button type="button" class="community-confirm" disabled={saving || (!pendingAuto && (!selected.length || !unshared.length))} onClick={() => void confirm()}>{saving ? "Sending…" : pendingAuto ? "Enable Auto share" : `Share ${selected.length} selected`}</button></div>
    </dialog>
  </aside>;
}

function Exposure({ watches, destinations, findings, alerts, filter, setFilter, search, setSearch }: {
  watches: Watch[]; destinations: DestinationEvent[]; findings: Finding[]; alerts: Alert[];
  filter: TimeFilter; setFilter: (filter: TimeFilter) => void; search: string; setSearch: (value: string) => void;
}) {
  const watchByID = new Map(watches.map((watch) => [watch.id, watch]));
  const destinationByID = new Map(destinations.map((destination) => [destination.id, destination]));
  const needle = search.trim().toLowerCase();
  const alertRows: Row[] = alerts.filter((alert) => {
    const haystack = `${watchByID.get(alert.watch_id)?.name || ""} ${destinationTextOrID(destinationByID.get(alert.destination_id), alert.destination_id)}`.toLowerCase();
    return !needle || haystack.includes(needle);
  }).sort((a, b) => timestamp(b.last_seen) - timestamp(a.last_seen)).map((alert) => {
    const watch = watchByID.get(alert.watch_id);
    return { key: `${alert.watch_id}-${alert.destination_id}-${alert.evidence}`, cells: [
      <Stacked primary={watch?.name || `Watch #${alert.watch_id}`} secondary={watch?.status} />,
      destinationTextOrID(destinationByID.get(alert.destination_id), alert.destination_id),
      <Badge evidence={alert.evidence}>{evidenceText(alert.evidence)}</Badge>,
      alert.observation_count,
      <Stacked primary={dateText(alert.first_seen)} secondary={`Last: ${dateText(alert.last_seen)}`} />,
    ] };
  });
  const findingRows: Row[] = findings.filter((finding) => {
    const watch = watchByID.get(finding.watch_id);
    const destination = destinationByID.get(finding.destination_id);
    const haystack = `${watch?.name || ""} ${watch?.group || ""} ${destinationTextOrID(destination, finding.destination_id)} ${finding.certificate_fingerprint}`.toLowerCase();
    return !needle || haystack.includes(needle);
  }).sort((a, b) => timestamp(b.time) - timestamp(a.time)).map((finding) => {
    const watch = watchByID.get(finding.watch_id);
    const destination = destinationByID.get(finding.destination_id);
    return { key: String(finding.id), cells: [
      <Stacked primary={watch?.name || `Watch #${finding.watch_id}`} secondary={watch ? `${watch.status} · ${watch.severity}` : undefined} />,
      <Stacked primary={destinationTextOrID(destination, finding.destination_id)} secondary={destination?.vantage ? `Vantage: ${destination.vantage}` : undefined} />,
      <Badge evidence={finding.evidence}>{evidenceText(finding.evidence)}</Badge>,
      <code class="mono">{finding.certificate_fingerprint || "—"}</code>,
      dateText(finding.time),
      <code class="mono">{finding.probe_id}</code>,
    ] };
  });
  return <section id="exposure" aria-labelledby="exposure-title">
    <SectionHeader number="04" eyebrow="Investigation" title="Potential CA exposure" titleID="exposure-title" exportResource="findings" filter={filter} />
    <p class="section-description">Direct means the watched certificate or key was presented to a probe. Candidate means it appeared only in a reconstructed path using the configured trust store. Name only requires investigation.</p>
    <CommunityShare />
    <div class="filters">
      <div><label htmlFor="finding-watch">Watched CA</label><select id="finding-watch" value={filter.watchID} onChange={(event) => setFilter({ ...filter, watchID: event.currentTarget.value })}><option value="">All watched CAs</option>{watches.map((watch) => <option key={watch.id} value={watch.id}>{watch.name}</option>)}</select></div>
      <div><label htmlFor="finding-from">From</label><input id="finding-from" type="datetime-local" value={filter.from} onChange={(event) => setFilter({ ...filter, from: event.currentTarget.value })} /></div>
      <div><label htmlFor="finding-to">Through</label><input id="finding-to" type="datetime-local" value={filter.to} onChange={(event) => setFilter({ ...filter, to: event.currentTarget.value })} /></div>
      <div><label htmlFor="finding-search">Search</label><input id="finding-search" type="search" placeholder="Destination or CA" value={search} onInput={(event) => setSearch(event.currentTarget.value)} /></div>
    </div>
    <h3>Grouped alerts</h3><div class="table-wrap"><DataTable caption={`${alertRows.length} grouped alert${alertRows.length === 1 ? "" : "s"}`} headers={["Watched CA", "Destination", "Evidence", "Observations", "First / last seen"]} rows={alertRows} empty="No grouped alerts match these filters." /></div>
    <h3>Observation history</h3><div class="table-wrap"><DataTable caption={`${findingRows.length} potential exposure finding${findingRows.length === 1 ? "" : "s"}${findings.length >= 10000 ? " (API limit reached; use export for a wider result)" : ""}`} headers={["Watched CA", "Destination", "Evidence", "Matched certificate", "Observed", "Probe ID"]} rows={findingRows} empty="No findings match these filters." /></div>
  </section>;
}

function DestinationsView({ destinations, probes, search, setSearch }: {
  destinations: DestinationEvent[]; probes: Probe[]; search: string; setSearch: (value: string) => void;
}) {
  const recentByKey = new Map<string, DestinationEvent>();
  const byID = new Map(destinations.map((destination) => [destination.id, destination]));
  for (const destination of destinations) {
    const key = destinationKey(destination);
    const previous = recentByKey.get(key);
    if (!previous || timestamp(destination.time) > timestamp(previous.time)) recentByKey.set(key, destination);
  }
  const probesByKey = new Map<string, Probe[]>();
  for (const probe of probes) {
    const destination = byID.get(probe.destination_id);
    if (!destination) continue;
    const key = destinationKey(destination);
    const list = probesByKey.get(key) || [];
    list.push(probe);
    probesByKey.set(key, list);
  }
  const needle = search.trim().toLowerCase();
  const rows: Row[] = [...recentByKey.values()].filter((destination) => {
    const haystack = `${destinationText(destination)} ${destination.collector} ${destination.vantage} ${destination.workload || ""}`.toLowerCase();
    return !needle || haystack.includes(needle);
  }).sort((a, b) => timestamp(b.time) - timestamp(a.time)).map((destination) => {
    const list = [...(probesByKey.get(destinationKey(destination)) || [])].sort((a, b) => timestamp(b.time) - timestamp(a.time));
    const latest = list[0];
    const leafVersions = new Set(list.map((probe) => probe.presented?.[0]?.fingerprint_sha256).filter(Boolean));
    const history = latest ? <div>
      <Stacked primary={dateText(latest.time)} secondary={`${list.length} probe${list.length === 1 ? "" : "s"}; ${leafVersions.size} observed leaf version${leafVersions.size === 1 ? "" : "s"}`} />
      <ProbeDetails probe={latest} />
      {list.length > 1 && <details><summary>Certificate history</summary><ol class="detail-content">{list.map((probe) => {
        const leaf = probe.presented?.[0];
        return <li key={probe.id}>{dateText(probe.time)} · {leaf?.subject || (probe.failure ? `Probe failed: ${probe.failure}` : "No leaf recorded")} · {shortHash(leaf?.fingerprint_sha256)}</li>;
      })}</ol></details>}
    </div> : "Not probed yet";
    return { key: destinationKey(destination), cells: [
      <Stacked primary={destinationText(destination)} secondary={destination.hostname && destination.ip ? `Resolved target IP: ${destination.ip}` : undefined} />,
      <Stacked primary={destination.collector || "Unknown"} secondary={`Vantage: ${destination.vantage || "unknown"}`} />,
      destination.attribution_reliable && destination.workload ? destination.workload : "Not supplied reliably",
      dateText(destination.time),
      history,
    ] };
  });
  return <section id="destinations" aria-labelledby="destinations-title">
    <SectionHeader number="05" eyebrow="Collection" title="Destinations" titleID="destinations-title" exportResource="destinations" />
    <p class="section-description">Destination identities and optional workload attribution come from collectors. Chain evidence comes only from independent probes.</p>
    <div class="filters"><div><label htmlFor="destination-search">Search destinations</label><input id="destination-search" type="search" placeholder="Hostname, IP, source, or vantage" value={search} onInput={(event) => setSearch(event.currentTarget.value)} /></div></div>
    <div class="table-wrap"><DataTable caption={`${rows.length} unique destination${rows.length === 1 ? "" : "s"} shown${destinations.length >= 10000 ? " (recent API limit reached)" : ""}`} headers={["Destination", "Collector", "Workload attribution", "Last event", "Latest independent probe"]} rows={rows} empty="No destinations have been collected yet." /></div>
  </section>;
}

function CAView({ cas, destinations, probes, search, setSearch }: {
  cas: CARecord[]; destinations: DestinationEvent[]; probes: Probe[]; search: string; setSearch: (value: string) => void;
}) {
  const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
  const associated = new Map<string, Set<string>>();
  function add(certificate: Certificate, label: string): void {
    if (!certificate.is_ca || !certificate.fingerprint_sha256) return;
    const key = certificate.fingerprint_sha256.toLowerCase();
    const labels = associated.get(key) || new Set<string>();
    labels.add(label);
    associated.set(key, labels);
  }
  for (const probe of probes) {
    const label = destinationText(destinationsByID.get(probe.destination_id));
    for (const certificate of probe.presented || []) add(certificate, label);
    for (const path of probe.candidate_paths || []) for (const certificate of path.certificates || []) add(certificate, label);
  }
  const needle = search.trim().toLowerCase();
  const rows: Row[] = cas.filter(({ certificate }) => {
    const haystack = `${certificate.subject} ${certificate.issuer} ${certificate.fingerprint_sha256} ${certificate.spki_sha256}`.toLowerCase();
    return !needle || haystack.includes(needle);
  }).sort((a, b) => timestamp(b.last_seen) - timestamp(a.last_seen)).map((record) => {
    const certificate = record.certificate;
    const labels = [...(associated.get(certificate.fingerprint_sha256.toLowerCase()) || [])].sort();
    return { key: certificate.fingerprint_sha256, cells: [
      <Stacked primary={certificate.subject || "Unknown subject"} secondary={`Issuer: ${certificate.issuer || "unknown"}`} />,
      <div><div class="mono">Cert: {certificate.fingerprint_sha256 || "unknown"}</div><div class="mono">Key: {certificate.spki_sha256 || "unknown"}</div></div>,
      <div>{record.presented_observations > 0 && <Badge evidence="direct">Presented · {record.presented_observations}</Badge>}{record.candidate_observations > 0 && <Badge evidence="candidate">Candidate · {record.candidate_observations}</Badge>}</div>,
      <div>{record.watch_matches?.length ? record.watch_matches.map((watch) => <Badge evidence={watch.evidence} key={`${watch.watch_id}-${watch.evidence}`}>{watch.name}: {watch.status}</Badge>) : "—"}</div>,
      <div>{record.destination_count ?? 0}{labels.length > 0 && <details><summary>View recent loaded destinations</summary><ul class="detail-content">{labels.map((label) => <li key={label}>{label}</li>)}</ul></details>}</div>,
      <Stacked primary={dateText(record.first_seen)} secondary={`Last: ${dateText(record.last_seen)}`} />,
    ] };
  });
  return <section id="ca-inventory" aria-labelledby="ca-title">
    <SectionHeader number="06" eyebrow="Certificates" title="CA inventory" titleID="ca-title" exportResource="cas" />
    <p class="section-description">Presented intermediates are observed directly. Candidate roots are supplied by a configured trust store and are labeled inferred.</p>
    <div class="filters"><div><label htmlFor="ca-search">Search CA certificates</label><input id="ca-search" type="search" placeholder="Subject, issuer, fingerprint, or key" value={search} onInput={(event) => setSearch(event.currentTarget.value)} /></div></div>
    <div class="table-wrap"><DataTable caption={`${rows.length} CA certificate${rows.length === 1 ? "" : "s"}`} headers={["Certificate", "SHA-256 identities", "Evidence", "Watch status", "Destinations", "First / last observation"]} rows={rows} empty="No CA certificates have been inventoried yet." /></div>
  </section>;
}

function ProbeView({ probes, destinations, filter, setFilter }: { probes: Probe[]; destinations: DestinationEvent[]; filter: "all" | "failed"; setFilter: (filter: "all" | "failed") => void }) {
  const destinationsByID = new Map(destinations.map((destination) => [destination.id, destination]));
  const rows: Row[] = probes.filter((probe) => filter === "all" || Boolean(probe.failure)).sort((a, b) => timestamp(b.time) - timestamp(a.time)).map((probe) => ({
    key: String(probe.id), cells: [
      dateText(probe.time),
      <Stacked primary={destinationTextOrID(destinationsByID.get(probe.destination_id), probe.destination_id)} secondary={`Vantage: ${probe.vantage || "unknown"}`} />,
      <div><Badge evidence={probe.failure ? "failed" : "success"}>{probe.failure ? "Inspection failed" : "Connection completed"}</Badge><div class="secondary">{probe.failure || probe.validation_error || (probe.incomplete_chain ? "Incomplete presented chain" : "No validation error recorded")}</div></div>,
      probe.presented?.length || 0,
      <ProbeDetails probe={probe} />,
    ],
  }));
  return <section id="probes" aria-labelledby="probes-title">
    <SectionHeader number="07" eyebrow="Independent connections" title="Probe history" titleID="probes-title" exportResource="probes" />
    <p class="section-description">Failures and validation errors are inspection results, not evidence of compromise. Expand a probe for presented certificates and candidate paths.</p>
    <div class="filters"><div><label htmlFor="probe-result-filter">Result</label><select id="probe-result-filter" value={filter} onChange={(event) => setFilter(event.currentTarget.value as "all" | "failed")}><option value="all">All probes</option><option value="failed">Failed probes</option></select></div></div>
    <div class="table-wrap"><DataTable caption={`${rows.length} ${filter === "failed" ? "failed " : ""}independent TLS probe${rows.length === 1 ? "" : "s"}${probes.length >= 10000 ? " (recent API limit reached)" : ""}`} headers={["Time", "Destination", "Result", "Presented certificates", "Evidence"]} rows={rows} empty={filter === "failed" ? "No failed probes are in the loaded history." : "No independent probes have run yet."} /></div>
  </section>;
}

function WatchView({ watches, crls, incident, onSaved }: { watches: Watch[]; crls: CRLRecord[]; incident: IncidentManifest | null; onSaved: () => Promise<void> }) {
  const rows: Row[] = [...watches].sort((a, b) => a.name.localeCompare(b.name)).map((watch) => ({
    key: String(watch.id), cells: [
      <Stacked primary={watch.name} secondary={watch.group} />,
      <Stacked primary={watch.match_type} secondary={<code class="mono">{watch.value}</code>} />,
      <div><Badge>{watch.status}</Badge><div class="secondary">Severity: {watch.severity}</div></div>,
      watch.reason || "—",
      <Stacked primary={watch.source || "Manual dashboard entry"} secondary={`${dateText(watch.effective_from)} to ${dateText(watch.effective_to)}`} />,
    ],
  }));
  const incidentRows: Row[] = (incident?.intermediates || []).flatMap((ca) => ca.certificates.map((cert) => ({
    key: cert.sha256, cells: [
      <Stacked primary={ca.name} secondary={ca.usage === "tls" ? "TLS intermediate" : "Code-signing intermediate"} />,
      cert.issued_by,
      <code class="mono">{cert.sha256}</code>,
      <code class="mono">{cert.serial_hex}</code>,
      <code class="mono">{ca.spki_sha256}</code>,
    ],
  })));
  return <section id="watchlist" aria-labelledby="watchlist-title">
    <SectionHeader number="02" eyebrow="Monitoring sources" title="CA watchlist & CRLs" titleID="watchlist-title" exportResource="watches" />
    <p class="section-description">Certainted starts with eight exact eMudhra intermediate-key watches covering 16 certificates reported revoked in the 2026 incident. Six keys are for TLS and two are for code signing, which ordinary TLS probes will not encounter. These incident reports are source-based watch entries, not imported or signature-verified CRLs. You can also load JSON or CSV watches or import a signed CRL here. Historical probes are reevaluated when watches are added.</p>
    <MonitoringImports onImported={onSaved} />
    <h3>CA watches</h3>
    <div class="table-wrap"><DataTable caption={`${rows.length} watchlist entr${rows.length === 1 ? "y" : "ies"}`} headers={["CA / group", "Match rule", "Status", "Reason", "Provenance / effective dates"]} rows={rows} empty="No watchlist entries have been configured yet." /></div>
    {incident && <details class="watch-form-wrap"><summary>View the 16 documented eMudhra certificate identities</summary>
      <p>Each pair shares one watched public key. This bundled incident record is source-attributed, but Certainted has not verified a CRL for these entries. A match is potential exposure from an independent probe, not proof of what an application received. Historical matches may predate revocation. Active watches are listed above and may be edited or removed.</p>
      <div class="table-wrap" role="region" aria-label="eMudhra incident certificate identities" tabIndex={0}><DataTable caption={`${incidentRows.length} reported revoked certificate variants`} headers={["Intermediate", "Issued by", "Certificate SHA-256", "Serial (hex)", "Public-key SHA-256"]} rows={incidentRows} empty="Incident identifiers unavailable." /></div>
      <p>Sources: <a href={incident.sources[0]} target="_blank" rel="noopener noreferrer">Mozilla incident record</a> and <a href={incident.sources[2]} target="_blank" rel="noopener noreferrer">eMudhra statement</a>. Bundled as of {incident.as_of}.</p>
    </details>}
    <WatchForm onSaved={onSaved} />
    <p class="monitoring-crl-link">{crls.length} imported CRL{crls.length === 1 ? "" : "s"}. <a href="#imported-crls">View CRL history and freshness</a>.</p>
  </section>;
}

function App() {
  const [stats, setStats] = useState<Stats>({});
  const [destinations, setDestinations] = useState<DestinationEvent[]>([]);
  const [probes, setProbes] = useState<Probe[]>([]);
  const [cas, setCAs] = useState<CARecord[]>([]);
  const [watches, setWatches] = useState<Watch[]>([]);
  const [incident, setIncident] = useState<IncidentManifest | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [revocationFindings, setRevocationFindings] = useState<RevocationFinding[]>([]);
  const [allRevocationFindings, setAllRevocationFindings] = useState<RevocationFinding[]>([]);
  const [crls, setCRLs] = useState<CRLRecord[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<TimeFilter>({ watchID: "", from: "", to: "" });
  const [revocationFilter, setRevocationFilter] = useState<RevocationFilter>({ from: "", to: "", evidence: "" });
  const [revocationSearch, setRevocationSearch] = useState("");
  const [findingSearch, setFindingSearch] = useState("");
  const [destinationSearch, setDestinationSearch] = useState("");
  const [caSearch, setCASearch] = useState("");
  const [probeFilter, setProbeFilter] = useState<"all" | "failed">("all");
  const [status, setStatus] = useState("Loading local inventory…");
  const [refreshKey, setRefreshKey] = useState(0);
  const refreshInventory = useCallback(() => setRefreshKey((key) => key + 1), []);
  const openExposure = useCallback(() => {
    setFilter({ watchID: "", from: "", to: "" });
    setFindingSearch("");
    window.location.hash = "exposure";
  }, []);
  const openRevocations = useCallback(() => { window.location.hash = "revocations"; }, []);

  useEffect(() => {
    let active = true;
    setStatus("Loading local inventory…");
    const paths = ["stats", "destinations?limit=10000", "probes?limit=10000", "cas", "watches", "revocations/crls", "revocations/findings?limit=10000", "incidents"];
    void Promise.allSettled(paths.map((path) => getJSON<unknown>(`/api/${path}`))).then((results) => {
      if (!active) return;
      const errors: string[] = [];
      for (const [index, result] of results.entries()) {
        if (result.status === "rejected") {
          errors.push(result.reason instanceof Error ? result.reason.message : String(result.reason));
          continue;
        }
        const value = result.value;
        if (index === 0) setStats((value || {}) as Stats);
        if (index === 1) setDestinations(asList(value as DestinationEvent[]));
        if (index === 2) setProbes(asList(value as Probe[]));
        if (index === 3) setCAs(asList(value as CARecord[]));
        if (index === 4) setWatches(asList(value as Watch[]));
        if (index === 5) setCRLs(asList(value as CRLRecord[]));
        if (index === 6) setAllRevocationFindings(asList(value as RevocationFinding[]));
        if (index === 7) setIncident(value as IncidentManifest);
      }
      setStatus(errors.length ? `Some local data could not be loaded: ${errors.join("; ")}` : `Inventory updated ${new Date().toLocaleTimeString()}.`);
    });
    return () => { active = false; };
  }, [refreshKey]);

  useEffect(() => {
    let active = true;
    const query = timeQuery(filter);
    void Promise.all([
      getJSON<Finding[]>(`/api/findings?${query.toString()}`),
      getJSON<Alert[]>(`/api/alerts?${query.toString()}`),
    ]).then(([findingData, alertData]) => {
      if (!active) return;
      setFindings(asList(findingData));
      setAlerts(asList(alertData));
    }).catch((error: unknown) => {
      if (active) setStatus(`Could not load historical findings: ${error instanceof Error ? error.message : String(error)}`);
    });
    return () => { active = false; };
  }, [filter.watchID, filter.from, filter.to, refreshKey]);

  useEffect(() => {
    let active = true;
    const query = revocationQuery(revocationFilter);
    void getJSON<RevocationFinding[]>(`/api/revocations/findings?${query.toString()}`).then((data) => {
      if (active) setRevocationFindings(asList(data));
    }).catch((error: unknown) => {
      if (active) setStatus(`Could not load revocation findings: ${error instanceof Error ? error.message : String(error)}`);
    });
    return () => { active = false; };
  }, [revocationFilter.from, revocationFilter.to, revocationFilter.evidence, refreshKey]);

  return <>
    <a class="skip-link" href="#main">Skip to content</a>
    <header class="site-header">
      <div class="brand"><figure class="brand-avatar"><img class="brand-mark" src="/sir-tainted-mark.svg" alt="" width="52" height="52" /><figcaption>Sir Tainted</figcaption></figure><div><strong>Certainted</strong><span>Revoked Certificate Watch</span></div></div>
      <nav aria-label="Sections"><a href="#overview">Overview</a><a href="#watchlist">CA watchlist & CRLs</a><a href="#revocations">Revoked certificates</a><a href="#exposure">CA exposure</a><a href="#destinations">Destinations</a><a href="#ca-inventory">CA inventory</a><a href="#probes">Probes</a></nav>
      <div class="header-actions"><span class="local-pill">Local instance</span><button type="button" onClick={refreshInventory}>Refresh inventory</button></div>
    </header>
    <main id="main" tabIndex={-1}>
      <div class="intro">
        <div class="intro-copy">
          <p class="eyebrow">The field ledger / Local observation</p>
          <h1>Revoked Certificate Watch</h1>
          <p class="intro-lede">Certainted runs on your computer or router. Its optional proxy relays encrypted traffic without decrypting or inspecting your application data, and never terminates your application's TLS session. Certainted opens a separate TLS connection to retrieve the destination's certificate chain.</p>
          <p class="scope-note"><strong>A note from the watchtower</strong> A probe records what a destination presented to Certainted at that time and network vantage. It cannot show the original application's chain or trust decision.</p>
        </div>
        <figure class="intro-portrait">
          <img src="/sir-tainted-mark.svg" alt="Sir Tainted, a smiling face in a knight's helmet" width="400" height="400" />
          <figcaption><strong>Sir Tainted</strong><span>Observer of chains</span></figcaption>
        </figure>
      </div>
      <p class="status" role="status" aria-live="polite">{status}</p>
      <Overview stats={stats} destinations={destinations} probes={probes} findings={findings} revocationFindings={allRevocationFindings} crlCount={crls.length} watchCount={watches.length} onNewAlert={refreshInventory} onOpenAlert={openExposure} onOpenRevocation={openRevocations} onProbeFilter={setProbeFilter} />
      <WatchView watches={watches} crls={crls} incident={incident} onSaved={async () => { refreshInventory(); }} />
      <RevocationsView crls={crls} findings={revocationFindings} destinations={destinations} filter={revocationFilter} setFilter={setRevocationFilter} search={revocationSearch} setSearch={setRevocationSearch} />
      <Exposure watches={watches} destinations={destinations} findings={findings} alerts={alerts} filter={filter} setFilter={setFilter} search={findingSearch} setSearch={setFindingSearch} />
      <DestinationsView destinations={destinations} probes={probes} search={destinationSearch} setSearch={setDestinationSearch} />
      <CAView cas={cas} destinations={destinations} probes={probes} search={caSearch} setSearch={setCASearch} />
      <ProbeView probes={probes} destinations={destinations} filter={probeFilter} setFilter={setProbeFilter} />
    </main>
    <footer><strong>Certainted observes; it does not block connections.</strong> No external reporting unless you enable sharing; no third-party enrichment by default.</footer>
  </>;
}

const mount = document.getElementById("app");
if (mount) render(<App />, mount);
