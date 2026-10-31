import React, { useEffect, useMemo, useState } from "react";

const apiUrl = import.meta.env.VITE_API_URL || "";
const statusNames = {
  vulnerable: "Vulnerable",
  no_known_advisory: "No known advisory",
  unresolved: "Unresolved",
  check_failed: "Check failed"
};
const dependencyNames = {
  dependencies: "Production",
  devDependencies: "Development",
  optionalDependencies: "Optional",
  peerDependencies: "Peer"
};

function safeReferenceHost(reference) {
  try {
    const url = new URL(reference);
    return url.protocol === "https:" ? url.hostname : null;
  } catch {
    return null;
  }
}

function severityRank(vulnerabilities) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, "Severity not provided": 4 };
  return vulnerabilities.reduce((best, vulnerability) => Math.min(best, rank[vulnerability.severity] ?? 5), 5);
}

function downloadReport(report, format) {
  let content;
  let mime;
  let filename;
  if (format === "json") {
    content = JSON.stringify(report, null, 2);
    mime = "application/json";
    filename = `depguard-${report.username}.json`;
  } else {
    const rows = [["Repository", "Manifest", "Package", "Declared", "Resolved", "Type", "Status", "Advisories"]];
    for (const repository of report.repositories) {
      for (const manifest of repository.manifests) {
        for (const dependency of manifest.dependencies) {
          rows.push([
            repository.fullName, manifest.path, dependency.name, dependency.declaredVersion,
            dependency.resolvedVersion ?? "", dependencyNames[dependency.dependencyType], statusNames[dependency.status],
            dependency.vulnerabilities.map((vulnerability) => vulnerability.id).join("; ")
          ]);
        }
      }
    }
    content = rows.map((row) => row.map((field) => {
      const value = String(field ?? "");
      const safeValue = /^[\s]*[=+\-@]/.test(value) ? `'${value}` : value;
      return `"${safeValue.replaceAll('"', '""')}"`;
    }).join(",")).join("\r\n");
    mime = "text/csv";
    filename = `depguard-${report.username}.csv`;
  }
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type: mime }));
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function App() {
  const [username, setUsername] = useState("");
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [repositoryFilter, setRepositoryFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sort, setSort] = useState("severity");
  const [overview, setOverview] = useState(null);
  const [overviewError, setOverviewError] = useState("");

  async function refreshOverview() {
    try {
      const response = await fetch(`${apiUrl}/api/showcase`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load saved scan history.");
      setOverview(data);
      setOverviewError("");
    } catch (requestError) {
      setOverviewError(requestError.message || "Could not connect to scan history.");
    }
  }

  useEffect(() => {
    refreshOverview();
  }, []);

  async function openSavedScan(scanId) {
    setError("");
    try {
      const response = await fetch(`${apiUrl}/api/history/${encodeURIComponent(scanId)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load this saved scan.");
      setReport(data.report);
      setUsername(data.report.username);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (requestError) {
      setError(requestError.message || "Could not load this saved scan.");
    }
  }

  async function scan(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const response = await fetch(`${apiUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim() })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Scan failed.");
      setReport(data);
      refreshOverview();
    } catch (requestError) {
      setError(requestError.message || "Could not reach DepGuard. Check the API container and try again.");
    } finally {
      setBusy(false);
    }
  }

  const entries = useMemo(() => {
    if (!report) return [];
    const all = report.repositories.flatMap((repository) => repository.manifests.flatMap((manifest) =>
      manifest.dependencies.map((dependency) => ({ repository, manifest, dependency }))
    ));
    const filtered = all.filter(({ repository, dependency }) =>
      (statusFilter === "all" || dependency.status === statusFilter) &&
      (severityFilter === "all" || dependency.vulnerabilities.some((v) => v.severity === severityFilter)) &&
      (repositoryFilter === "all" || repository.fullName === repositoryFilter) &&
      (typeFilter === "all" || dependency.dependencyType === typeFilter)
    );
    return filtered.sort((a, b) => sort === "package"
      ? a.dependency.name.localeCompare(b.dependency.name)
      : sort === "repository"
        ? a.repository.fullName.localeCompare(b.repository.fullName)
        : severityRank(a.dependency.vulnerabilities) - severityRank(b.dependency.vulnerabilities));
  }, [report, statusFilter, severityFilter, repositoryFilter, typeFilter, sort]);

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#" onClick={() => { setReport(null); setError(""); }}>
          <span className="brand-mark">D</span><span>depguard<span className="brand-dot">.</span></span>
        </a>
        <div className="topnote"><span className="pulse" /> PUBLIC REPOSITORY SCANNER</div>
      </header>

      <section className={`hero ${report ? "hero-compact" : ""}`}>
        <div className="eyebrow"><span className="eyebrow-line" /> DEPENDENCY INTELLIGENCE</div>
        <h1>Know what your<br /><span>dependencies expose.</span></h1>
        <p className="intro">Scan public GitHub repositories for known vulnerabilities in npm dependencies. Evidence-led findings, with coverage gaps made clear.</p>
        <form className="search" onSubmit={scan}>
          <span className="github-glyph">⌘</span>
          <input value={username} onChange={(event) => setUsername(event.target.value)} placeholder="GitHub username" aria-label="GitHub username" required disabled={busy} />
          <button type="submit" disabled={busy || !username.trim()}>{busy ? <><span className="spinner" /> Scanning</> : <>Scan repositories <span aria-hidden="true">↗</span></>}</button>
        </form>
        <div className="privacy"><span>◈</span> Public repositories only <i /> No code is executed <i /> No login required</div>
        {error && <div className="error-banner" role="alert">{error}</div>}
        {busy && <div className="progress-note"><span className="spinner dark" /> Inspecting repositories and checking exact versions against OSV. This can take a moment for large profiles.</div>}
      </section>

      {report ? <section className="results">
        <div className="report-heading">
          <div><div className="eyebrow"><span className="eyebrow-line" /> SCAN REPORT</div><h2>@{report.username}<span className="report-status">{report.status === "completed" ? "Complete" : "Partial coverage"}</span></h2></div>
          <div className="export-actions"><button onClick={() => downloadReport(report, "json")}>Export JSON ↓</button><button onClick={() => downloadReport(report, "csv")}>Export CSV ↓</button></div>
        </div>
        <div className="metrics">
          <Metric label="Public repositories" value={report.summary.repositoriesFound} />
          <Metric label="With manifests" value={report.summary.repositoriesWithPackageJson} />
          <Metric label="Manifests scanned" value={report.summary.manifestsScanned} />
          <Metric label="Versions checked" value={report.summary.dependenciesChecked} />
          <Metric label="Vulnerable" value={report.summary.vulnerableOccurrences} alert />
          <Metric label="Unresolved" value={report.summary.unresolvedOccurrences} />
        </div>

        <div className="section-title"><div><div className="eyebrow"><span className="eyebrow-line" /> FINDINGS</div><h3>Dependency inventory <span className="count">{entries.length}</span></h3></div><span className="timestamp">Scanned {new Date(report.scannedAt).toLocaleString()}</span></div>
        <div className="filters">
          <select aria-label="Filter by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="all">All statuses</option>{Object.entries(statusNames).map(([key, value]) => <option key={key} value={key}>{value}</option>)}</select>
          <select aria-label="Filter by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
          <select aria-label="Filter by repository" value={repositoryFilter} onChange={(event) => setRepositoryFilter(event.target.value)}><option value="all">All repositories</option>{report.repositories.map((repo) => <option key={repo.fullName} value={repo.fullName}>{repo.name}</option>)}</select>
          <select aria-label="Filter by dependency type" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option value="all">All dependency types</option>{Object.entries(dependencyNames).map(([key, value]) => <option key={key} value={key}>{value}</option>)}</select>
          <select aria-label="Sort results" value={sort} onChange={(event) => setSort(event.target.value)}><option value="severity">Sort: severity</option><option value="package">Sort: package</option><option value="repository">Sort: repository</option></select>
        </div>

        <div className="table-wrap">
          <table><thead><tr><th>PACKAGE</th><th>VERSION</th><th>TYPE</th><th>REPOSITORY / MANIFEST</th><th>STATUS</th></tr></thead>
            <tbody>{entries.map(({ repository, manifest, dependency }, index) => <DependencyRow key={`${repository.fullName}:${manifest.path}:${dependency.name}:${dependency.dependencyType}:${index}`} {...{ repository, manifest, dependency }} />)}</tbody>
          </table>
          {!entries.length && <div className="empty">No dependencies match these filters. Try broadening your selection.</div>}
        </div>
        <div className="coverage"><span>ⓘ</span><div><strong>Coverage boundary</strong><p>“No known OSV advisory” is not a guarantee of safety. Only exact versions resolved from npm lockfile v2/v3 are checked. pnpm/Yarn and missing lockfiles remain unresolved; partial GitHub access is shown above.</p></div></div>

        <div className="section-title repositories-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> REPOSITORY COVERAGE</div><h3>Repositories <span className="count">{report.repositories.length}</span></h3></div></div>
        <div className="repo-list">{report.repositories.map((repository) => <details className="repo-item" key={repository.fullName}>
          <summary><span className="repo-name">{repository.name}{repository.archived && <span className="archived">ARCHIVED</span>}</span><span className="repo-meta">{repository.manifests.length} manifest{repository.manifests.length === 1 ? "" : "s"}</span><StatusTag status={repository.status === "failed" ? "check_failed" : repository.manifests.length ? "no_known_advisory" : "unresolved"} label={repository.status === "failed" ? "Failed" : repository.status === "partial" ? "Partial" : repository.manifests.length ? "Inspected" : "No manifest"} /></summary>
          <div className="repo-detail"><a href={repository.url} target="_blank" rel="noreferrer">{repository.fullName} ↗</a>{repository.errors.map((message, index) => <p className="repo-error" key={index}>{message}</p>)}{repository.manifests.map((manifest) => <p key={manifest.path}><code>{manifest.path}</code> · {manifest.dependencies.length} dependencies · {manifest.status}</p>)}</div>
        </details>)}</div>
        <footer className="report-footer">DepGuard reports known npm vulnerabilities from OSV. Findings are not a full security assessment.</footer>
      </section> : <section className="below-fold">
        <div className="signal-card"><span className="card-index">01 / DISCOVER</span><div className="card-icon">⌕</div><h3>Every public repo</h3><p>Paginated repository discovery and nested manifest inspection, including monorepos.</p></div>
        <div className="signal-card"><span className="card-index">02 / RESOLVE</span><div className="card-icon">⌘</div><h3>Exact, not guessed</h3><p>Version ranges are never treated as installed versions. Missing lockfile evidence stays unresolved.</p></div>
        <div className="signal-card"><span className="card-index">03 / VERIFY</span><div className="card-icon">◎</div><h3>OSV-backed findings</h3><p>Vulnerability checks run against exact npm versions, with source references when available.</p></div>
      </section>}
      {!report && <section className="showcase">
        <div className="section-title"><div><div className="eyebrow"><span className="eyebrow-line" /> THE EVIDENCE VAULT</div><h3>Scan history, saved for review</h3></div><span className="database-status">{overview ? "POSTGRESQL · CONNECTED" : "CONNECTING TO DATABASE"}</span></div>
        {overviewError && <div className="error-banner" role="alert">{overviewError}</div>}
        <div className="showcase-metrics">
          <Metric label="Scans saved" value={overview?.totals.totalScans ?? 0} />
          <Metric label="Profiles audited" value={overview?.totals.profilesAudited ?? 0} />
          <Metric label="Repositories seen" value={overview?.totals.repositoriesSeen ?? 0} />
          <Metric label="Advisory occurrences" value={overview?.totals.vulnerableOccurrences ?? 0} alert />
          <Metric label="Distinct advisories" value={overview?.totals.uniqueAdvisories ?? 0} />
        </div>
        <div className="vault-grid">
          <div className="vault-panel"><h4>Recent scans</h4>
            {overview?.recentScans.length ? overview.recentScans.map((savedScan) => <button className="saved-scan" key={savedScan.id} onClick={() => openSavedScan(savedScan.id)}>
              <span><strong>@{savedScan.username}</strong><small>{new Date(savedScan.scannedAt).toLocaleString()}</small></span>
              <span className="saved-scan-count">{savedScan.vulnerableOccurrences} findings · {savedScan.repositoriesFound} repos</span>
            </button>) : <p className="vault-empty">No saved scans yet. Run a public profile scan to create the first evidence record.</p>}
          </div>
          <div className="vault-panel"><h4>Most-seen vulnerable packages</h4>
            {overview?.topVulnerablePackages.length ? overview.topVulnerablePackages.map((packageItem) => <div className="package-stat" key={packageItem.name}>
              <code>{packageItem.name}</code><span>{packageItem.occurrences} occurrence{packageItem.occurrences === 1 ? "" : "s"}</span>
            </div>) : <p className="vault-empty">No vulnerable packages have been recorded in completed scans.</p>}
          </div>
        </div>
        <p className="vault-note">Only results from real scans are stored. History and aggregate counts survive container restarts in the persistent database volume.</p>
      </section>}
      {!report && <footer className="landing-footer"><span>BUILT FOR TRANSPARENCY</span><span>OSV · GITHUB REST API · OPEN WEB</span></footer>}
    </main>
  );
}

function Metric({ label, value, alert }) {
  return <div className={`metric ${alert && value ? "metric-alert" : ""}`}><span>{label}</span><strong>{value.toLocaleString()}</strong></div>;
}

function StatusTag({ status, label }) {
  return <span className={`status-tag ${status}`}>{label || statusNames[status] || status.replaceAll("_", " ")}</span>;
}

function DependencyRow({ repository, manifest, dependency }) {
  return <tr>
    <td><strong className="package-name">{dependency.name}</strong>{dependency.vulnerabilities.map((vulnerability) => <details className="advisory" key={vulnerability.id}>
      <summary>{vulnerability.id} · {vulnerability.severity}</summary><p>{vulnerability.summary}</p>
      {vulnerability.affected.flatMap((item) => item.ranges ?? []).flatMap((range) => range.events ?? []).map((event, index) => event.fixed && <p key={index}>Fixed version: <code>{event.fixed}</code></p>)}
      {vulnerability.references.map((reference) => {
        const host = safeReferenceHost(reference);
        return host && <a key={reference} href={reference} target="_blank" rel="noreferrer">{host} ↗</a>;
      })}
    </details>)}</td>
    <td><code>{dependency.resolvedVersion || "—"}</code><span className="declared">declared {dependency.declaredVersion}</span></td>
    <td>{dependencyNames[dependency.dependencyType]}</td>
    <td><a className="repo-link" href={repository.url} target="_blank" rel="noreferrer">{repository.name} ↗</a><span className="declared">{manifest.path}</span></td>
    <td><StatusTag status={dependency.status} />{dependency.error && <span className="declared">{dependency.error}</span>}</td>
  </tr>;
}

export default App;
