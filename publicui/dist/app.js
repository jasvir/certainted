(() => {
  // ../publicui/app.ts
  var reportsRoot = document.getElementById("report-list");
  var statsRoot = document.getElementById("stats");
  var status = document.getElementById("load-status");
  var resultCount = document.getElementById("result-count");
  var kindFilter = document.getElementById("kind-filter");
  var evidenceFilter = document.getElementById("evidence-filter");
  var searchFilter = document.getElementById("report-search");
  var refreshButton = document.getElementById("refresh");
  var reports = [];
  function node(tag, className = "", value = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value) element.textContent = value;
    return element;
  }
  function appendText(parent, tag, className, value) {
    parent.append(node(tag, className, value));
  }
  function dateText(value) {
    if (!value) return "\u2014";
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? value : time.toLocaleString();
  }
  function hashText(value) {
    return value || "\u2014";
  }
  function evidenceText(value) {
    return value === "direct" ? "Directly presented to probe" : value === "candidate" ? "Candidate path (inferred)" : value || "Unknown";
  }
  function field(list, term, value) {
    list.append(node("dt", "", term), node("dd", "mono", value || "\u2014"));
  }
  function reportCard(report) {
    const card = node("article", `report-card ${report.evidence === "candidate" ? "candidate-report" : ""}`);
    const heading = node("div", "report-heading");
    const title = node("div");
    appendText(title, "p", "eyebrow", report.kind === "crl" ? "CRL match" : "CA watchlist match");
    appendText(title, "h3", "", `${report.hostname}:${report.port}`);
    heading.append(title, node("span", "badge unverified", "Unverified submission"));
    card.append(heading);
    const meta = node("div", "report-meta");
    meta.append(node("span", `badge ${report.evidence === "direct" ? "direct" : "candidate"}`, evidenceText(report.evidence)));
    meta.append(node("span", "", `Observed day: ${report.observed_day || "unknown"}`));
    meta.append(node("span", "", `Submitted: ${dateText(report.received_at)}`));
    card.append(meta);
    appendText(card, "p", "fingerprint", `Certificate SHA-256: ${hashText(report.certificate_sha256)}`);
    const details = node("details", "report-details");
    details.append(node("summary", "", "View submitted evidence and verification fields"));
    const list = node("dl", "evidence-list");
    field(list, "Report ID", report.id);
    field(list, "Certificate SHA-256", report.certificate_sha256);
    field(list, "Evidence", evidenceText(report.evidence));
    field(list, "Observed day", report.observed_day);
    field(list, "Received", dateText(report.received_at));
    if (report.kind === "crl" && report.crl) {
      field(list, "Certificate serial", report.crl.certificate_serial);
      field(list, "CRL SHA-256", report.crl.crl_sha256);
      field(list, "Issuer certificate SHA-256", report.crl.issuer_cert_sha256);
      field(list, "Issuer public-key SHA-256", report.crl.issuer_spki_sha256);
      field(list, "Revoked at", dateText(report.crl.revoked_at));
      field(list, "CRL this update", dateText(report.crl.this_update));
      field(list, "CRL next update", dateText(report.crl.next_update));
      field(list, "Issuer relationship", report.crl.issuer_match);
    }
    if (report.kind === "watch" && report.watch) {
      field(list, "Watch match type", report.watch.match_type);
      field(list, "Watch fingerprint", report.watch.match_sha256);
      field(list, "Reported CA status", `${report.watch.status} (self-reported)`);
      field(list, "Reported severity", `${report.watch.severity} (self-reported)`);
    }
    details.append(list);
    card.append(details);
    return card;
  }
  function renderStats(data) {
    statsRoot.replaceChildren();
    const cards = [
      ["Reports", String(data.reports ?? 0), "Unauthenticated submissions"],
      ["CRL matches", String(data.crl_reports ?? 0), "Reported revocation evidence"],
      ["CA watches", String(data.watch_reports ?? 0), "Self-reported watchlist matches"],
      ["Latest submission", data.latest_received_at ? dateText(data.latest_received_at) : "\u2014", "The feed may not be current"]
    ];
    for (const [label, value, detail] of cards) {
      const card = node("div", "stat");
      card.append(node("span", "stat-label", label), node("strong", "stat-value", value), node("span", "stat-detail", detail));
      statsRoot.append(card);
    }
  }
  function renderReports() {
    const kind = kindFilter.value;
    const evidence = evidenceFilter.value;
    const query = searchFilter.value.trim().toLowerCase();
    const shown = reports.filter((report) => {
      if (kind && report.kind !== kind) return false;
      if (evidence && report.evidence !== evidence) return false;
      if (!query) return true;
      const searchable = [report.hostname, report.certificate_sha256, report.crl?.crl_sha256, report.crl?.certificate_serial, report.watch?.match_sha256, report.watch?.status].join(" ").toLowerCase();
      return searchable.includes(query);
    });
    resultCount.textContent = `${shown.length} of ${reports.length} loaded report${reports.length === 1 ? "" : "s"} shown. The server returns up to 200 recent reports.`;
    reportsRoot.replaceChildren(...shown.map(reportCard));
    if (!shown.length) reportsRoot.append(node("p", "empty", reports.length ? "No reports match these filters." : "No public reports have been submitted yet."));
  }
  async function getJSON(path) {
    const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }
  async function refresh() {
    refreshButton.disabled = true;
    status.textContent = "Loading community reports\u2026";
    try {
      const [reportData, statData] = await Promise.all([
        getJSON("/api/v1/reports?limit=200"),
        getJSON("/api/v1/stats")
      ]);
      if (!Array.isArray(reportData.reports)) throw new Error("Invalid report list");
      reports = reportData.reports;
      renderStats(statData);
      renderReports();
      status.textContent = `Public feed updated ${(/* @__PURE__ */ new Date()).toLocaleTimeString()}. Submissions are unverified.`;
    } catch (error) {
      status.textContent = `Could not load public reports: ${error instanceof Error ? error.message : String(error)}`;
    } finally {
      refreshButton.disabled = false;
    }
  }
  kindFilter.addEventListener("change", renderReports);
  evidenceFilter.addEventListener("change", renderReports);
  searchFilter.addEventListener("input", renderReports);
  refreshButton.addEventListener("click", () => void refresh());
  void refresh();
})();
