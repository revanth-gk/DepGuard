import { readFile } from "node:fs/promises";
import pg from "pg";
import { HttpError } from "./errors.js";
import { randomUUID } from "node:crypto";
import { hashPassword, sessionLifetimeMs, validateUsername } from "./auth.js";

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
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminPassword) {
    const username = process.env.ADMIN_USERNAME || "admin";
    if (!validateUsername(username)) throw new Error("ADMIN_USERNAME must be a valid GitHub-style username.");
    const passwordHash = await hashPassword(adminPassword);
    await pool.query(
      `INSERT INTO accounts (id, username, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       ON CONFLICT ((LOWER(username))) DO UPDATE SET role = 'admin', password_hash = EXCLUDED.password_hash`,
      [randomUUID(), username, passwordHash]
    );
    await pool.query("DELETE FROM auth_sessions WHERE expires_at <= NOW()");
    console.log(`Admin account "${username}" is ready.`);
  } else {
    console.warn("ADMIN_PASSWORD is unset; admin account bootstrap is disabled.");
  }
}

export async function checkDatabase() {
  await pool.query("SELECT 1");
}

export async function findAccount(username) {
  const result = await pool.query(
    `SELECT id, username, password_hash AS "passwordHash", role
     FROM accounts WHERE LOWER(username) = LOWER($1)`,
    [username]
  );
  return result.rows[0] ?? null;
}

export async function changeAccountPassword(accountId, passwordHash) {
  const result = await pool.query("UPDATE accounts SET password_hash = $2 WHERE id = $1", [accountId, passwordHash]);
  if (!result.rowCount) throw new HttpError(404, "Account was not found.", "ACCOUNT_NOT_FOUND");
  await pool.query("DELETE FROM auth_sessions WHERE account_id = $1", [accountId]);
}

export async function createAccount(username, passwordHash) {
  try {
    const result = await pool.query(
      `INSERT INTO accounts (id, username, password_hash, role)
       VALUES ($1, $2, $3, 'user')
       RETURNING id, username, role, created_at AS "createdAt"`,
      [randomUUID(), username, passwordHash]
    );
    return result.rows[0];
  } catch (error) {
    if (error.code === "23505") throw new HttpError(409, "An account with that GitHub username already exists.", "ACCOUNT_EXISTS");
    throw error;
  }
}

export async function createSession(accountId, tokenHash) {
  const result = await pool.query(
    `INSERT INTO auth_sessions (token_hash, account_id, expires_at)
     VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 millisecond'))
     RETURNING expires_at AS "expiresAt"`,
    [tokenHash, accountId, sessionLifetimeMs]
  );
  return result.rows[0];
}

export async function getSessionAccount(tokenHash) {
  const result = await pool.query(
    `SELECT accounts.id, accounts.username, accounts.role
     FROM auth_sessions
     JOIN accounts ON accounts.id = auth_sessions.account_id
     WHERE auth_sessions.token_hash = $1 AND auth_sessions.expires_at > NOW()`,
    [tokenHash]
  );
  return result.rows[0] ?? null;
}

export async function deleteSession(tokenHash) {
  await pool.query("DELETE FROM auth_sessions WHERE token_hash = $1", [tokenHash]);
}

export async function saveScan(report, accountId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { summary } = report;
    await client.query(
      `INSERT INTO scans (
        id, account_id, username, status, scanned_at, repositories_found, repositories_scanned,
        repositories_with_package_json, manifests_scanned, dependencies_checked,
        vulnerable_occurrences, unresolved_occurrences, scan_errors, report
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb)`,
      [
        report.scanId, accountId, report.username, report.status, report.scannedAt,
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

export async function getScanHistory(limit, accountId) {
  const result = await pool.query(
    `SELECT id, username, report->>'repositoryName' AS "repositoryName", scanned_at AS "scannedAt", status,
      repositories_found AS "repositoriesFound",
      repositories_scanned AS "repositoriesScanned",
      manifests_scanned AS "manifestsScanned",
      dependencies_checked AS "dependenciesChecked",
      vulnerable_occurrences AS "vulnerableOccurrences",
      unresolved_occurrences AS "unresolvedOccurrences",
      scan_errors AS "scanErrors"
     FROM scans WHERE account_id = $1 ORDER BY scanned_at DESC LIMIT $2`,
    [accountId, limit]
  );
  return result.rows;
}

export async function getSavedScan(id, accountId) {
  const result = await pool.query("SELECT report FROM scans WHERE id = $1 AND account_id = $2", [id, accountId]);
  return result.rows[0]?.report ?? null;
}

export async function getRecommendationSource(scanId, accountId, packageName, currentVersion) {
  const result = await pool.query("SELECT report FROM scans WHERE id = $1 AND account_id IS NOT DISTINCT FROM $2", [scanId, accountId]);
  const report = result.rows[0]?.report;
  if (!report) return null;
  for (const repository of report.repositories) {
    for (const manifest of repository.manifests) {
      const dependency = manifest.dependencies.find((item) =>
        item.name === packageName && item.resolvedVersion === currentVersion && item.status === "vulnerable");
      if (dependency) {
        return {
          dependency,
          repository: repository.fullName,
          manifest: manifest.path,
          advisories: dependency.vulnerabilities.map(({ id, summary, severity }) => ({ id, summary, severity }))
        };
      }
    }
  }
  return null;
}

export async function saveRecommendations(accountId, scanId, packageName, currentVersion, suggestions, provider) {
  const result = await pool.query(
    `INSERT INTO scan_recommendations (id, account_id, scan_id, package_name, current_version, suggestions, provider)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
     RETURNING id, created_at AS "createdAt"`,
    [randomUUID(), accountId, scanId, packageName, currentVersion, JSON.stringify(suggestions), provider]
  );
  return result.rows[0];
}

const adminTables = {
  accounts: {
    primaryKey: "id",
    columns: ["id", "username", "role", "created_at"],
    editable: ["username", "role"],
    types: { username: "text", role: "text" }
  },
  auth_sessions: {
    primaryKey: "token_hash",
    columns: ["token_hash", "account_id", "created_at", "expires_at"],
    editable: ["account_id", "expires_at"],
    types: { account_id: "uuid", expires_at: "timestamp" }
  },
  scans: {
    primaryKey: "id",
    columns: ["id", "account_id", "username", "status", "scanned_at", "repositories_found", "repositories_scanned",
      "repositories_with_package_json", "manifests_scanned", "dependencies_checked", "vulnerable_occurrences",
      "unresolved_occurrences", "scan_errors", "report"],
    editable: ["account_id", "username", "status", "scanned_at", "repositories_found", "repositories_scanned",
      "repositories_with_package_json", "manifests_scanned", "dependencies_checked", "vulnerable_occurrences",
      "unresolved_occurrences", "scan_errors", "report"],
    types: {
      account_id: "uuid", username: "text", status: "text", scanned_at: "timestamp",
      repositories_found: "integer", repositories_scanned: "integer", repositories_with_package_json: "integer",
      manifests_scanned: "integer", dependencies_checked: "integer", vulnerable_occurrences: "integer",
      unresolved_occurrences: "integer", scan_errors: "integer", report: "json"
    }
  },
  scan_repositories: {
    primaryKey: "id",
    columns: ["id", "scan_id", "full_name", "name", "url", "default_branch", "archived", "status",
      "manifest_count", "dependency_count", "vulnerable_count", "errors"],
    editable: ["scan_id", "full_name", "name", "url", "default_branch", "archived", "status",
      "manifest_count", "dependency_count", "vulnerable_count", "errors"],
    types: {
      scan_id: "uuid", full_name: "text", name: "text", url: "text", default_branch: "text",
      archived: "boolean", status: "text", manifest_count: "integer", dependency_count: "integer",
      vulnerable_count: "integer", errors: "json"
    }
  },
  scan_manifests: {
    primaryKey: "id",
    columns: ["id", "scan_id", "repository_id", "path", "status", "errors", "dependency_count"],
    editable: ["scan_id", "repository_id", "path", "status", "errors", "dependency_count"],
    types: { scan_id: "uuid", repository_id: "integer", path: "text", status: "text", errors: "json", dependency_count: "integer" }
  },
  scan_dependencies: {
    primaryKey: "id",
    columns: ["id", "scan_id", "repository_id", "manifest_id", "package_name", "declared_version",
      "resolved_version", "dependency_type", "status", "error"],
    editable: ["scan_id", "repository_id", "manifest_id", "package_name", "declared_version",
      "resolved_version", "dependency_type", "status", "error"],
    types: {
      scan_id: "uuid", repository_id: "integer", manifest_id: "integer", package_name: "text",
      declared_version: "text", resolved_version: "text", dependency_type: "text", status: "text", error: "text"
    }
  },
  scan_advisories: {
    primaryKey: "id",
    columns: ["id", "scan_id", "dependency_id", "advisory_id", "summary", "severity", "source_references",
      "published_at", "modified_at"],
    editable: ["scan_id", "dependency_id", "advisory_id", "summary", "severity", "source_references",
      "published_at", "modified_at"],
    types: {
      scan_id: "uuid", dependency_id: "integer", advisory_id: "text", summary: "text", severity: "text",
      source_references: "json", published_at: "timestamp", modified_at: "timestamp"
    }
  },
  scan_recommendations: {
    primaryKey: "id",
    columns: ["id", "account_id", "scan_id", "package_name", "current_version", "suggestions", "provider", "created_at"],
    editable: ["account_id", "scan_id", "package_name", "current_version", "suggestions", "provider"],
    types: {
      account_id: "uuid", scan_id: "uuid", package_name: "text", current_version: "text",
      suggestions: "json", provider: "text"
    }
  }
};

export function listAdminTables() {
  return Object.entries(adminTables).map(([name, table]) => ({
    name,
    primaryKey: table.primaryKey,
    columns: table.columns,
    editable: table.editable,
    types: table.types
  }));
}

export async function listAdminRows(tableName, limit, offset) {
  const table = adminTables[tableName];
  if (!table) throw new HttpError(404, "Database table is not available in the admin console.", "TABLE_NOT_FOUND");
  const columns = table.columns.map((column) => `"${column}"`).join(", ");
  const result = await pool.query(
    `SELECT ${columns} FROM "${tableName}" ORDER BY "${table.primaryKey}" LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const count = await pool.query(`SELECT COUNT(*)::int AS total FROM "${tableName}"`);
  return { rows: result.rows, total: count.rows[0].total, table: listAdminTables().find((item) => item.name === tableName) };
}

function convertAdminValue(value, type, field) {
  if (value === null) return null;
  if (type === "integer") {
    const number = Number(value);
    if (!Number.isSafeInteger(number)) throw new HttpError(400, `${field} must be a whole number.`, "INVALID_FIELD");
    return number;
  }
  if (type === "boolean") {
    if (typeof value !== "boolean") throw new HttpError(400, `${field} must be true or false.`, "INVALID_FIELD");
    return value;
  }
  if (type === "uuid") {
    if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
      throw new HttpError(400, `${field} must be a valid UUID.`, "INVALID_FIELD");
    }
    return value;
  }
  if (type === "json") {
    if (typeof value === "string") {
      try {
        return JSON.parse(value);
      } catch {
        throw new HttpError(400, `${field} must contain valid JSON.`, "INVALID_FIELD");
      }
    }
    return value;
  }
  if (type === "timestamp") {
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) throw new HttpError(400, `${field} must be a valid date.`, "INVALID_FIELD");
    return date.toISOString();
  }
  if (typeof value !== "string") throw new HttpError(400, `${field} must be text.`, "INVALID_FIELD");
  if (value.length > 200000) throw new HttpError(400, `${field} is too long.`, "INVALID_FIELD");
  return value;
}

export async function updateAdminRow(tableName, rowId, values, currentAdminId) {
  const table = adminTables[tableName];
  if (!table) throw new HttpError(404, "Database table is not available in the admin console.", "TABLE_NOT_FOUND");
  if (!values || typeof values !== "object" || Array.isArray(values) || Object.keys(values).length === 0) {
    throw new HttpError(400, "Provide at least one editable column value.", "INVALID_UPDATE");
  }
  const requestedColumns = Object.keys(values);
  if (requestedColumns.some((column) => !table.editable.includes(column))) {
    throw new HttpError(400, "The update includes a protected or unsupported column.", "PROTECTED_COLUMN");
  }
  if (tableName === "accounts" && rowId === currentAdminId && requestedColumns.some((column) => ["username", "role"].includes(column))) {
    throw new HttpError(403, "Use a different administrator account to edit your own access.", "SELF_ADMIN_CHANGE");
  }
  if (tableName === "accounts" && values.role !== undefined) {
    if (!["user", "admin"].includes(values.role)) throw new HttpError(400, "Account role is invalid.", "INVALID_ROLE");
  }
  const parameters = [];
  const assignments = requestedColumns.map((column) => {
    parameters.push(convertAdminValue(values[column], table.types[column], column));
    return `"${column}" = $${parameters.length}${table.types[column] === "json" ? `::jsonb` : ""}`;
  });
  parameters.push(rowId);
  if (tableName !== "accounts" || values.role === undefined) {
    const result = await pool.query(
      `UPDATE "${tableName}" SET ${assignments.join(", ")} WHERE "${table.primaryKey}" = $${parameters.length} RETURNING ${table.columns.map((column) => `"${column}"`).join(", ")}`,
      parameters
    );
    if (!result.rowCount) throw new HttpError(404, "Database row was not found.", "ROW_NOT_FOUND");
    return result.rows[0];
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const target = await client.query("SELECT role FROM accounts WHERE id = $1 FOR UPDATE", [rowId]);
    if (!target.rowCount) throw new HttpError(404, "Database row was not found.", "ROW_NOT_FOUND");
    if (target.rows[0].role === "admin" && values.role === "user") {
      const admins = await client.query("SELECT id FROM accounts WHERE role = 'admin' FOR UPDATE");
      if (admins.rowCount <= 1) throw new HttpError(409, "At least one administrator account must remain.", "LAST_ADMIN");
    }
    const result = await client.query(
      `UPDATE "${tableName}" SET ${assignments.join(", ")} WHERE "${table.primaryKey}" = $${parameters.length} RETURNING ${table.columns.map((column) => `"${column}"`).join(", ")}`,
      parameters
    );
    await client.query("COMMIT");
    return result.rows[0];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function deleteAdminRow(tableName, rowId, currentAdminId) {
  const table = adminTables[tableName];
  if (!table) throw new HttpError(404, "Database table is not available in the admin console.", "TABLE_NOT_FOUND");
  if (tableName === "accounts" && rowId === currentAdminId) {
    throw new HttpError(403, "You cannot delete the administrator account you are using.", "SELF_ADMIN_DELETE");
  }
  if (tableName !== "accounts") {
    const result = await pool.query(
      `DELETE FROM "${tableName}" WHERE "${table.primaryKey}" = $1 RETURNING "${table.primaryKey}"`,
      [rowId]
    );
    if (!result.rowCount) throw new HttpError(404, "Database row was not found.", "ROW_NOT_FOUND");
    return result.rows[0][table.primaryKey];
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const target = await client.query("SELECT role FROM accounts WHERE id = $1 FOR UPDATE", [rowId]);
    if (!target.rowCount) throw new HttpError(404, "Database row was not found.", "ROW_NOT_FOUND");
    if (target.rows[0].role === "admin") {
      const admins = await client.query("SELECT id FROM accounts WHERE role = 'admin' FOR UPDATE");
      if (admins.rowCount <= 1) throw new HttpError(409, "At least one administrator account must remain.", "LAST_ADMIN");
    }
    const result = await client.query(
      `DELETE FROM "${tableName}" WHERE "${table.primaryKey}" = $1 RETURNING "${table.primaryKey}"`,
      [rowId]
    );
    await client.query("COMMIT");
    return result.rows[0][table.primaryKey];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
