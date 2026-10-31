const cache = new Map();
const concurrency = 8;

function advisorySeverity(vulnerability) {
  const label = vulnerability.database_specific?.severity ?? vulnerability.severity_label;
  if (typeof label !== "string") return "Severity not provided";
  const normalized = label.toLowerCase();
  return ["critical", "high", "moderate", "medium", "low"].includes(normalized)
    ? (normalized === "moderate" ? "medium" : normalized)
    : "Severity not provided";
}

export async function queryOsv(packageName, version) {
  const key = `${packageName}@${version}`;
  if (cache.has(key)) return cache.get(key);
  let response;
  try {
    response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" }, version }),
      signal: AbortSignal.timeout(12000)
    });
  } catch {
    throw new Error("OSV could not be reached or timed out.");
  }
  if (!response.ok) throw new Error(`OSV returned an error (${response.status}).`);
  const result = await response.json();
  const vulnerabilities = (result.vulns ?? []).map((vulnerability) => ({
    id: vulnerability.id,
    summary: vulnerability.summary || vulnerability.details?.slice(0, 400) || "No summary provided.",
    severity: advisorySeverity(vulnerability),
    references: (vulnerability.references ?? []).map((reference) => reference.url).filter(Boolean),
    published: vulnerability.published ?? null,
    modified: vulnerability.modified ?? null,
    affected: vulnerability.affected ?? []
  }));
  cache.set(key, vulnerabilities);
  if (cache.size > 2000) cache.delete(cache.keys().next().value);
  return vulnerabilities;
}

export async function mapWithConcurrency(items, mapper) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await mapper(items[index], index);
    }
  }));
  return results;
}
