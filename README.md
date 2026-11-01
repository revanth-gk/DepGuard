# DepGuard

DepGuard scans public GitHub repositories for known npm dependency vulnerabilities, stores account-scoped or anonymous reports, and checks suggested package versions against OSV before presenting them.

## Architecture

```text
Browser: JavaScript + React 18
  └─ Vite 6 + @vitejs/plugin-react build
  └─ same-origin /api requests
  └─ Docker Compose
     ├─ Nginx 1.27 (static assets + reverse proxy)
     ├─ Node.js 22 + Express 4 API
     │  ├─ GitHub REST API (public repositories and files)
     │  ├─ npm registry + OSV API (versions and advisory verification)
     │  ├─ Optional Groq API (alternative package candidates)
     │  └─ PostgreSQL 17
     └─ PostgreSQL named volume (persistent data)
```

Only the API talks to GitHub, npm, OSV, Groq, or PostgreSQL. Nginx proxies `/api` inside Docker, so the browser uses the same origin. Public repository files are parsed as data; DepGuard never clones a repository, runs its code, or installs packages.

PostgreSQL stores scan reports as JSONB for replay and in normalized tables for database-backed summaries and administration. A named Docker volume persists this data across container restarts and rebuilds.

## Technology stack

| Layer | Technologies | Role |
|---|---|---|
| Application language | JavaScript (ES modules), JSX | Frontend and backend application code |
| Frontend | React 18, React DOM 18 | Interactive scanner, report views, account and admin interfaces |
| Frontend tooling | Vite 6, `@vitejs/plugin-react` | Local development server and optimized production build |
| Backend | Node.js 22, Express 4 | REST API, public scans, authentication, and recommendations |
| Database | PostgreSQL 17, SQL, JSONB | Accounts, sessions, scan summaries, findings, and persisted reports |
| Database client | `pg` | Parameterized PostgreSQL access and connection pooling |
| Reverse proxy / web server | Nginx 1.27 | Serves the built frontend and proxies same-origin `/api` requests |
| Containers | Docker, Docker Compose | Reproducible frontend, API, and database services |
| Package data | npm registry | Published package versions for upgrade and alternative checks |
| Vulnerability data | OSV API | Advisory checks against exact npm package versions |
| Repository data | GitHub REST API | Public repository metadata, manifests, and lockfiles |
| Optional AI suggestions | Groq Chat Completions API | Suggests alternative package names; suggestions are independently verified |
| Password and session security | Node.js `crypto` (`scrypt`, SHA-256, secure random tokens), HttpOnly cookies | Password hashing and server-managed sessions |
| Version handling | `semver` | Orders stable upgrade candidates |
| Testing | Node.js built-in test runner (`node:test`) | Authentication, URL validation, lockfile, and recommendation tests |

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

Anyone can paste a public GitHub repository URL in **Public review** and run the same dependency checks without signing in. Anonymous reports are stored without account ownership for aggregate evidence, but are not added to personal history. There is no per-IP public scan attempt limit; at most two public scans run simultaneously to protect service capacity. Public recommendation requests are limited to ten per IP every 15 minutes.

To keep a private review history, create an account using the same username as a public GitHub profile, then sign in and enter one repository name owned by that username. A report is stored under the signed-in account and can be reopened from its history. Saved scan and recommendation endpoints enforce account ownership. The account name is checked against GitHub, but this username/password flow does **not** prove control of that GitHub account; do not treat it as GitHub OAuth or identity verification.

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
- `POST /api/public-scan` with `{ "repositoryUrl": "https://github.com/owner/repo" }` — inspect a public repository without an account.
- `GET /api/history` and `GET /api/history/:id` — list/open the signed-in account's reports.
- `POST /api/history/:id/recommendations` — recommend verified upgrades and optional verified alternatives.
- `POST /api/public-scans/:id/recommendations` — request verified recommendations for an anonymous public scan.
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
