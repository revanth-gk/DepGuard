# DepGuard

DepGuard scans a public GitHub repository for known npm dependency vulnerabilities, records an account-scoped report, and checks suggested package versions against OSV before presenting them.

## Architecture

```text
Browser: React + Vite
  └─ same-origin /api requests
     └─ Nginx: static assets + reverse proxy
        └─ Express API
           ├─ Account/session service (scrypt + HttpOnly cookies)
           ├─ GitHub REST API (public profile/repository files)
           ├─ npm registry + OSV (versions and advisory verification)
           ├─ Optional Groq API (candidate alternative package names)
           └─ PostgreSQL
              ├─ accounts / auth_sessions
              ├─ scans / scan_repositories / scan_manifests
              ├─ scan_dependencies / scan_advisories
              └─ scan_recommendations
```

Only the API talks to GitHub, npm, OSV, Groq, or PostgreSQL. Nginx proxies `/api` inside Docker, so the browser uses the same origin. Public repository files are parsed as data; DepGuard never clones a repository, runs its code, or installs packages.

PostgreSQL stores scan reports as JSONB for replay and in normalized tables for database-backed summaries and administration. A named Docker volume persists this data across container restarts and rebuilds.

## Start the application

1. Copy `.env.example` to `.env`.
2. Set a unique `ADMIN_PASSWORD` (at least 12 characters). Set a unique `POSTGRES_PASSWORD` for non-local deployments. Keep `.env` private; it is ignored by Git.
3. Optionally add a server-side `GITHUB_TOKEN` for a higher GitHub API limit and `GROQ_API_KEY` for AI-suggested replacement package candidates.
4. Run:

   ```powershell
   docker compose up --build
   ```

5. Open [http://localhost:8080](http://localhost:8080). The API health check is [http://localhost:8080/api/health](http://localhost:8080/api/health). The Express API and PostgreSQL are private to the Compose network.

Compose starts PostgreSQL, waits for its health check, initializes tables, and bootstraps the `admin` account from `ADMIN_USERNAME` and `ADMIN_PASSWORD`. If `ADMIN_PASSWORD` is empty, the service does not create an admin account. Never use a shared or source-controlled default password. In an HTTPS deployment, set `COOKIE_SECURE=true`.

To clear saved state, run `docker compose down --volumes`; this permanently deletes the PostgreSQL data volume.

## Accounts and repository scans

Create an account using the same username as a public GitHub profile, then sign in and enter one repository name owned by that username. A report is stored under the signed-in account and can be reopened from its history. Saved scan and recommendation endpoints enforce account ownership. The account name is checked against GitHub, but this username/password flow does **not** prove control of that GitHub account; do not treat it as GitHub OAuth or identity verification.

Passwords are stored as unique-salt scrypt hashes. Session bearer tokens are random, held in `HttpOnly; SameSite=Strict` cookies, and stored only as SHA-256 digests in PostgreSQL. Account endpoints are rate-limited. Accounts do not grant access to private repositories.

## Recommendations

For a vulnerable resolved dependency, **Find a safer option** checks newer stable npm versions against OSV for the exact proposed version. It prefers a safe release in the installed major version, then checks newer major versions. If `GROQ_API_KEY` is configured, Groq may suggest alternative package names; DepGuard independently verifies that each candidate exists in npm and that its exact selected version has no known OSV advisory before displaying it.

Recommendations are evidence, not guarantees. A clean OSV result is not proof of safety, and an alternative package may not be API-compatible. Review release notes and test changes before adopting them. Groq receives only the package name, installed version, and public advisory IDs/summaries—never repository source code, account passwords, or database contents.

The Groq key previously pasted into chat should be revoked/rotated before adding a replacement to the private `.env` file. DepGuard does not contain or reuse that pasted key.

## Admin data console

The bootstrapped `admin` account can inspect, edit, and delete rows and editable column values in the application tables: accounts, sessions, scans, repositories, manifests, dependencies, advisories, and recommendations. Admins can reset another account's password (revoking its sessions); password hashes and raw session tokens are never exposed. The console protects the active administrator and the last remaining admin from deletion/demotion; foreign-key cascade rules still apply when parent records are deleted.

The browser console does not run arbitrary SQL and cannot create/drop tables or change column definitions. Schema changes must be reviewed and applied as SQL migrations. This keeps administrative data correction useful without exposing unrestricted database execution to a web request.

## API

- `POST /api/auth/register` and `POST /api/auth/login` — create/sign in to a GitHub-username account.
- `POST /api/auth/logout` and `GET /api/auth/me` — end/read the current session.
- `GET /api/repositories` — list public repositories belonging to the signed-in username.
- `POST /api/scan` with `{ "repositoryName": "repo-name" }` — inspect one owned public repository.
- `GET /api/history` and `GET /api/history/:id` — list/open the signed-in account's reports.
- `POST /api/history/:id/recommendations` — recommend verified upgrades and optional verified alternatives.
- `GET /api/showcase` — display aggregate evidence from actual saved scans.
- `/api/admin/tables` — admin-only table metadata, row browsing, row updates, and row deletion.

## Development and tests

Requires Node.js 22 or newer and a reachable PostgreSQL instance:

```powershell
npm install
npm test
npm run build
```

For a host-run backend, configure `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, and `PGPASSWORD`; use `npm run dev`. The Compose database is private to the Compose network by design.

## Coverage limits

The scanner resolves npm lockfile v2/v3 (`package-lock.json` and `npm-shrinkwrap.json`). pnpm and Yarn files are detected but not parsed and remain unresolved. Version ranges without exact lockfile evidence are not queried against OSV. “No known OSV advisory” does not guarantee safety. GitHub limits, inaccessible files, malformed manifests, and incomplete tree inspection appear as coverage gaps.
