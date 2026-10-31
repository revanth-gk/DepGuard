import { readFile } from "node:fs/promises";
import pg from "pg";
import { HttpError } from "./errors.js";

const { Pool } = pg;
const pool = new Pool({
  max: 10,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000
});
pool.on("error", (error) => console.error("Unexpected idle PostgreSQL client error:", error));

export async function initializeDatabase() {
  const schema = await readFile(new URL("./schema.sql", import.meta.url), "utf8");
  await pool.query(schema);
}

export async function checkDatabase() {
  await pool.query("SELECT 1");
}

export async function saveScan(report) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { summary } = report;
    await client.query(
      `INSERT INTO scans (
        id, username, status, scanned_at, repositories_found, repositories_scanned,
        repositories_with_package_json, manifests_scanned, dependencies_checked,
        vulnerable_occurrences, unresolved_occurrences, scan_errors, report
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb)`,
      [
        report.scanId, report.username, report.status, report.scannedAt,
        summary.repositoriesFound, summary.repositoriesScanned, summary.repositoriesWithPackageJson,
        summary.manifestsScanned, summary.dependenciesChecked, summary.vulnerableOccurrences,
        summary.unresolvedOccurrences, summary.scanErrors, JSON.stringify(report)
      ]
    );

    for (const repository of report.repositories) {
      const dependencyCount = repository.manifests.reduce((count, manifest) => count + manifest.dependencies.length, 0);
      const vulnerableCount = repository.manifests.reduce((count, manifest) =>
        count + manifest.dependencies.filter((dependency) => dependency.status === "vulnerable").length, 0);
      const repositoryResult = await client.query(
        `INSERT INTO scan_repositories (
          scan_id, full_name, name, url, default_branch, archived, status,
          manifest_count, dependency_count, vulnerable_count, errors
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
        RETURNING id`,
        [
          report.scanId, repository.fullName, repository.name, repository.url, repository.defaultBranch,
          repository.archived, repository.status, repository.manifests.length, dependencyCount,
          vulnerableCount, JSON.stringify(repository.errors)
        ]
      );
      const repositoryId = repositoryResult.rows[0].id;

      for (const manifest of repository.manifests) {
        const manifestResult = await client.query(
          `INSERT INTO scan_manifests (scan_id, repository_id, path, status, errors, dependency_count)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING id`,
          [report.scanId, repositoryId, manifest.path, manifest.status, JSON.stringify(manifest.errors), manifest.dependencies.length]
        );
        const manifestId = manifestResult.rows[0].id;

        for (const dependency of manifest.dependencies) {
          const dependencyResult = await client.query(
            `INSERT INTO scan_dependencies (
              scan_id, repository_id, manifest_id, package_name, declared_version,
              resolved_version, dependency_type, status, error
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [
              report.scanId, repositoryId, manifestId, dependency.name, dependency.declaredVersion,
              dependency.resolvedVersion, dependency.dependencyType, dependency.status, dependency.error
            ]
          );
          for (const vulnerability of dependency.vulnerabilities) {
            await client.query(
              `INSERT INTO scan_advisories (
                scan_id, dependency_id, advisory_id, summary, severity, source_references, published_at, modified_at
              ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
              [
                report.scanId, dependencyResult.rows[0].id, vulnerability.id, vulnerability.summary,
                vulnerability.severity, JSON.stringify(vulnerability.references), vulnerability.published, vulnerability.modified
              ]
            );
          }
        }
      }
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Could not persist scan:", error);
    throw new HttpError(503, "The scan finished, but its results could not be saved to the database.", "PERSISTENCE_FAILED");
  } finally {
    client.release();
  }
}

export async function getShowcase() {
  const [totals, recentScans, topVulnerablePackages] = await Promise.all([
    pool.query(
      `SELECT
        (SELECT COUNT(*) FROM scans)::int AS "totalScans",
        (SELECT COUNT(DISTINCT LOWER(username)) FROM scans)::int AS "profilesAudited",
        (SELECT COUNT(DISTINCT LOWER(full_name)) FROM scan_repositories)::int AS "repositoriesSeen",
        (SELECT COALESCE(SUM(manifests_scanned), 0) FROM scans)::int AS "manifestsInspected",
        (SELECT COALESCE(SUM(vulnerable_occurrences), 0) FROM scans)::int AS "vulnerableOccurrences",
        (SELECT COUNT(DISTINCT advisory_id) FROM scan_advisories)::int AS "uniqueAdvisories",
        (SELECT COALESCE(SUM(unresolved_occurrences), 0) FROM scans)::int AS "unresolvedOccurrences"`
    ),
    pool.query(
      `SELECT id, username, scanned_at AS "scannedAt", status,
        repositories_found AS "repositoriesFound",
        vulnerable_occurrences AS "vulnerableOccurrences",
        unresolved_occurrences AS "unresolvedOccurrences"
       FROM scans ORDER BY scanned_at DESC LIMIT 8`
    ),
    pool.query(
      `SELECT dependencies.package_name AS name, COUNT(DISTINCT dependencies.id)::int AS occurrences
       FROM scan_advisories advisories
       JOIN scan_dependencies dependencies ON dependencies.id = advisories.dependency_id
       GROUP BY dependencies.package_name
       ORDER BY COUNT(DISTINCT dependencies.id) DESC, dependencies.package_name ASC
       LIMIT 8`
    )
  ]);
  return {
    totals: totals.rows[0],
    recentScans: recentScans.rows,
    topVulnerablePackages: topVulnerablePackages.rows
  };
}

export async function getScanHistory(limit) {
  const result = await pool.query(
    `SELECT id, username, scanned_at AS "scannedAt", status,
      repositories_found AS "repositoriesFound",
      repositories_scanned AS "repositoriesScanned",
      manifests_scanned AS "manifestsScanned",
      dependencies_checked AS "dependenciesChecked",
      vulnerable_occurrences AS "vulnerableOccurrences",
      unresolved_occurrences AS "unresolvedOccurrences",
      scan_errors AS "scanErrors"
     FROM scans ORDER BY scanned_at DESC LIMIT $1`,
    [limit]
  );
  return result.rows;
}

export async function getSavedScan(id) {
  const result = await pool.query("SELECT report FROM scans WHERE id = $1", [id]);
  return result.rows[0]?.report ?? null;
}
