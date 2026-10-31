# DepGuard

DepGuard audits public GitHub repositories for known vulnerabilities in npm dependencies. It reads repository files using GitHub's REST API, resolves exact package versions from supported npm lockfiles, and checks those versions against OSV. It never clones repositories, installs packages, or executes repository code.

## Architecture

```text
Browser (React + Vite)
        │ same-origin /api requests
        ▼
Nginx static frontend + API reverse proxy
        │
        ▼
Express API ────── GitHub REST API
    │              OSV vulnerability API
    ├── scan orchestration, parsing, bounded lookups
    │
    ▼
PostgreSQL
    ├── scans              profile, timestamp and summary metrics
    ├── scan_repositories  repository coverage and status
    ├── scan_manifests     manifest paths and parse coverage
    ├── scan_dependencies  declarations, exact versions and result states
    └── scan_advisories    advisory evidence and source references
```

The browser talks only to the DepGuard API. Nginx proxies `/api` inside the Compose network, so the browser does not need a hard-coded API host or direct access to GitHub/OSV. The Express service owns integrations and scan orchestration. PostgreSQL stores both a JSONB copy of each complete report for faithful replay and normalized rows for judge-friendly aggregate queries and history.

## Run with Docker

From this directory:

```powershell
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080). The API health check is at [http://localhost:4000/api/health](http://localhost:4000/api/health).

Compose starts PostgreSQL, waits for its health check, initializes the schema, and then starts the API and web client. PostgreSQL data is kept in the named `depguard-postgres-data` volume across container restarts and rebuilds. Change the local development database password by setting `POSTGRES_PASSWORD` before starting Compose. GitHub allows unauthenticated access with a lower API limit; optionally set `GITHUB_TOKEN` in the server environment to raise that limit. The token stays on the backend.

To clear the database and all saved scan evidence, explicitly remove the volume with `docker compose down --volumes`. This is destructive.

## Saved evidence for demonstrations

Every successful scan is persisted transactionally. The home page's **Evidence vault** uses actual database queries to show:

- profiles and repositories scanned over time;
- manifests inspected and vulnerable occurrences found;
- distinct advisory IDs and frequently occurring vulnerable packages;
- recent scan records, which can be reopened as complete reports.

The vault starts empty. Run a real public-profile scan to populate it; the application does not seed fake repositories, dependencies, or vulnerabilities. The `GET /api/showcase`, `GET /api/history`, and `GET /api/history/:id` endpoints serve the aggregates and saved records. `POST /api/scan` creates a new record only after its full report and normalized rows have been committed.

## Local development

Requires Node.js 22 or newer and a reachable PostgreSQL database. The Compose database is intentionally private to the Compose network; the simplest full-stack development setup is `docker compose up --build`. To run the Node.js processes directly on the host, configure the PG variables for a PostgreSQL instance reachable from the host, then run:

```powershell
npm install
$env:PGHOST = "localhost"
$env:PGPORT = "5432"
$env:PGDATABASE = "depguard"
$env:PGUSER = "depguard"
$env:PGPASSWORD = "depguard-local"
npm run dev
npm test
npm run build
```

Vite proxies `/api` to the local Express service. For local API access, set `GITHUB_TOKEN` only in the server environment if needed.

## Coverage and limitations

The MVP resolves npm lockfile v2/v3 (`package-lock.json` and `npm-shrinkwrap.json`). pnpm and Yarn lockfiles are detected but not parsed and therefore remain unresolved. Version ranges without exact lockfile evidence are never queried against OSV. “No known OSV advisory” is not a guarantee of safety. GitHub limits, inaccessible files, malformed manifests, unsupported lockfiles, and incomplete tree inspection are represented as scan coverage or dependency states rather than hidden.

The API limits scans to 10 requests per client IP in 15 minutes. No MongoDB, authentication, code execution, package installation, or automatic dependency modification is required.
