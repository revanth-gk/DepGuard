# DepGuard — Implementation Specification

## 1. Product goal

DepGuard audits the **public npm dependencies** used across a GitHub user's public repositories.

The user enters a GitHub username. DepGuard discovers all accessible public repositories, finds every eligible root or nested `package.json`, extracts dependencies, resolves exact versions from supported lockfiles, checks those versions against the OSV vulnerability database, and presents a consolidated security report.

**Core flow:** GitHub username → public repositories → `package.json` discovery → dependency extraction → lockfile version resolution → OSV vulnerability checks → frontend report.

The MVP reads public repository data only. No GitHub login or personal access token is required from the user.

## 2. MVP scope

### Must have
- Accept a GitHub username.
- Fetch all public repositories with pagination.
- Inspect each repository's default branch.
- Find root and nested `package.json` files, including monorepos.
- Exclude generated/vendor directories such as `node_modules`, `.git`, `dist`, `build`, `coverage`, `.next` and `vendor`.
- Extract `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies`.
- Resolve exact installed versions from supported lockfiles.
- Check exact npm package/version pairs against OSV.
- Distinguish vulnerable, unresolved, no-known-advisory and failed-check results.
- Display repository and dependency details, advisory links and remediation information.
- Export JSON or CSV.
- Continue after individual repository/file/lookup failures and show partial coverage honestly.

### Out of scope
- Private repositories.
- Executing repository code or installing packages.
- Automatically modifying dependencies or opening pull requests.
- Ecosystems other than npm in the MVP.
- Full malware detection, static code analysis or secret scanning.
- Claiming a package is safe merely because no advisory was returned.

## 3. Technology stack

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React + Vite | Search, progress, dashboard, filters |
| Backend | Node.js + Express | GitHub integration, parsing, scan orchestration |
| Database | MongoDB (optional) | Scan history/cache if needed |
| Repository source | GitHub REST API | Public repositories and files |
| Vulnerability source | OSV API | Known version-specific vulnerabilities |
| Styling | Tailwind CSS or existing UI library | Responsive interface |
| Charts | Recharts (optional) | Severity and repository summaries |

**Keep the first version simple:** return results directly from the backend. Add MongoDB only if scan history or scheduled rescans are required. A separate Flask/ML service is unnecessary for the core product.

## 4. Architecture

```text
React frontend
    |
    | POST /api/scan { username }
    v
Express backend
    |
    +--> GitHub REST API
    |      +--> Paginated public repository listing
    |      +--> Default-branch tree inspection
    |      +--> package.json and lockfile retrieval
    |
    +--> Dependency parser
    |      +--> Extract dependency groups
    |      +--> Resolve exact versions from lockfiles
    |      +--> Mark unresolved declarations
    |
    +--> OSV API
    |      +--> Query npm package + exact version
    |      +--> Normalize advisory data
    |
    v
Normalized scan result
    |
    v
React results dashboard
```

All external API calls, pagination, parsing and vulnerability checks belong on the backend. The browser should call only the DepGuard backend.

## 5. GitHub repository discovery

### 5.1 List public repositories

Use:

`GET https://api.github.com/users/{username}/repos?type=public&per_page=100&page={page}&sort=updated`

- Validate and URL-encode the username.
- Fetch pages until no more repositories are returned.
- Record `full_name`, `html_url`, `default_branch`, description, language, archived status and `updated_at`.
- Include archived repositories in the scan, but label them as archived (or provide a filter).
- Handle unknown users (404), rate limits (403/429), timeouts and network failures.
- Respect GitHub rate-limit response headers. Never attempt to bypass limits.
- An optional server-side GitHub token can be added later to increase API limits. Never ask users to paste tokens into the scan form or expose tokens to the frontend.

### 5.2 Find every package.json

For each repository, inspect its default branch using the Git Trees API:

`GET https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`

Select paths whose filename is exactly `package.json`. Include nested manifests for monorepos.

Exclude paths under directory segments such as `node_modules/`, `.git/`, `dist/`, `build/`, `coverage/`, `.next/` and `vendor/`.

GitHub's recursive tree response can be truncated for large repositories. Check the `truncated` field. If true, traverse subtrees non-recursively or mark the repository **Partially inspected**. Never silently report a complete scan.

### 5.3 Fetch file contents

Use:

`GET https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={default_branch}`

Decode Base64 content and parse it. Handle missing, inaccessible or oversized files without aborting the whole scan.

Treat repository content as untrusted input. Parse files only. Never execute scripts, install dependencies or run repository binaries.

## 6. Dependency extraction and version resolution

For every `package.json`, extract:
- `dependencies`
- `devDependencies`
- `optionalDependencies`
- `peerDependencies`

Retain package name, declared version/range, dependency group, manifest path and repository identity. Support scoped package names such as `@babel/core`.

### Lockfile priority

A declaration such as `^4.2.0` is a range, not proof that the installed version is `4.2.7`. Use lockfiles to resolve exact versions:

1. `package-lock.json` and `npm-shrinkwrap.json`
2. `pnpm-lock.yaml`
3. `yarn.lock`

Implement npm `package-lock.json` v2/v3 first using maintained parsing logic. Add pnpm and Yarn support as separate modules. Avoid fragile regular expressions for complex lockfile formats.

If no supported lockfile exists, retain the declared range and mark it **Unresolved — exact installed version unavailable**. Do not guess a version or label it vulnerable/safe.

Keep occurrences from different manifests and resolved versions distinct. Aggregate them for a convenient repository/package summary.

## 7. Vulnerability checking with OSV

Use the OSV API from the backend:

`POST https://api.osv.dev/v1/query`

Example request:

```json
{
  "package": {
    "name": "example-package",
    "ecosystem": "npm"
  },
  "version": "1.2.3"
}
```

Query exact resolved versions only. Use OSV batch querying where suitable for larger scans, following its current schema and limits.

Normalize available fields:
- Vulnerability/advisory ID
- Summary and concise details
- Affected package and ecosystem
- Affected version ranges
- Fixed versions or introduced/fixed boundaries
- Severity/CVSS data, if supplied
- References/advisory URLs
- Published and modified timestamps

Use bounded concurrency, timeouts, transient-error retries and short-lived caching. If severity is absent, show **Severity not provided**; never invent a score.

### Required result states

| State | Meaning |
|---|---|
| Vulnerable | OSV returned an advisory affecting the exact resolved version |
| No known OSV advisory found | No matching OSV advisory was returned; this is not proof of safety |
| Unresolved version | No exact installed version could be established |
| Check failed | The vulnerability lookup could not complete |
| Manifest error | The package manifest could not be parsed |

**Product boundary:** OSV identifies known vulnerabilities; it is not a complete malware detector. Do not call a package malicious merely because its name looks suspicious. Future reputation signals (npm deprecation, suspicious install scripts, maintainer changes or curated malicious-package feeds) must be shown separately and must not be presented as confirmed malware without evidence.

## 8. Backend API

### `POST /api/scan`

Request:

```json
{
  "username": "octocat"
}
```

Illustrative response shape (sample values are placeholders, not real findings):

```json
{
  "scanId": "scan_123",
  "username": "octocat",
  "status": "completed",
  "summary": {
    "repositoriesFound": 18,
    "repositoriesScanned": 18,
    "repositoriesWithPackageJson": 6,
    "manifestsScanned": 9,
    "dependenciesChecked": 142,
    "vulnerableOccurrences": 4,
    "unresolvedOccurrences": 12,
    "scanErrors": 1
  },
  "repositories": [
    {
      "name": "sample-project",
      "url": "https://github.com/octocat/sample-project",
      "defaultBranch": "main",
      "manifests": [
        {
          "path": "package.json",
          "status": "scanned",
          "dependencies": [
            {
              "name": "example-package",
              "declaredVersion": "^1.0.0",
              "resolvedVersion": "1.0.4",
              "dependencyType": "dependencies",
              "status": "vulnerable",
              "vulnerabilities": [
                {
                  "id": "GHSA-example",
                  "summary": "Example advisory",
                  "severity": "high",
                  "references": []
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "errors": []
}
```

Do not fabricate findings in real responses.

Optional endpoints:
- `GET /api/health`
- `GET /api/scan/:scanId` (if scans are persisted/asynchronous)
- `GET /api/scan/:scanId/export?format=json|csv`

A synchronous endpoint is acceptable for an initial small MVP if scan duration is reasonable. If it becomes slow, use a simple job model: `POST /api/scan` returns a `scanId`, and the frontend polls `GET /api/scan/:scanId` for genuine status/progress. Do not simulate progress percentages. Avoid queues or WebSockets until needed.

## 9. Frontend specification

Build a polished, responsive security dashboard rather than a generic admin template.

### Landing page
- DepGuard name/logo and concise product explanation.
- GitHub username input.
- Primary **Scan public repositories** button.
- Example username hint.
- Privacy note: "Only public repositories are inspected. No repository code is executed."
- Input validation and clear API error messages.

### Scan progress

Show genuine stages:
1. Validating GitHub profile
2. Discovering public repositories
3. Finding package manifests
4. Resolving dependency versions
5. Checking OSV advisories
6. Preparing the report

Where possible, show actual progress such as `7 / 24 repositories inspected`. Only display progress values backed by backend status.

### Results dashboard

**Summary cards**
- Public repositories discovered
- Repositories containing `package.json`
- Manifests scanned
- Dependency occurrences checked
- Vulnerable occurrences
- Unresolved occurrences

**Repository table**
- Repository name and GitHub link
- Manifest count
- Vulnerable dependency count
- Scan status: Complete / Partial / No package manifest / Failed
- Expandable repository details

**Dependency/vulnerability table**
- Package name
- Resolved version and declared range
- Dependency type (production, development, optional, peer)
- Status and severity
- Repository and manifest path
- Advisory ID and external reference
- Fixed-version guidance, when available

**Filters**
- Status
- Severity
- Repository
- Dependency type
- Sort by severity, package name or repository

**Additional UX**
- Expandable advisory details with concise explanation.
- Severity chart only when severity data exists.
- JSON/CSV export.
- Scan timestamp and coverage disclaimer.
- Empty/error states for unknown user, no public repos, no manifests, no advisories, GitHub rate limit, OSV outage and partial scans.

### Visual direction
- Dark, restrained security-product aesthetic.
- Red/orange only for actual risk severity, not decoration.
- Never rely on color alone; include text labels.
- Keep tables readable and responsive.
- Use expandable rows or a side panel for advisory details.
- Do not overload the first screen with every dependency field.

## 10. Suggested folder structure

```text
depguard/
├── client/
│   └── src/
│       ├── components/
│       │   ├── SearchForm.jsx
│       │   ├── ScanProgress.jsx
│       │   ├── SummaryCards.jsx
│       │   ├── RepositoryList.jsx
│       │   ├── DependencyTable.jsx
│       │   ├── VulnerabilityDetails.jsx
│       │   └── Filters.jsx
│       ├── pages/
│       │   ├── Home.jsx
│       │   └── Results.jsx
│       ├── services/api.js
│       ├── App.jsx
│       └── main.jsx
├── server/
│   └── src/
│       ├── routes/scan.routes.js
│       ├── controllers/scan.controller.js
│       ├── services/
│       │   ├── github.service.js
│       │   ├── repository.service.js
│       │   ├── manifest.service.js
│       │   ├── lockfile.service.js
│       │   ├── osv.service.js
│       │   └── scan.service.js
│       ├── utils/
│       │   ├── normalizeResult.js
│       │   ├── errors.js
│       │   └── rateLimiter.js
│       ├── app.js
│       └── server.js
├── README.md
└── implementation.md
```

Keep orchestration in `scan.service.js`, not inside one large Express route handler. Keep GitHub, lockfile and OSV integrations independently testable.

## 11. Implementation sequence

### Phase 1 — App skeleton
- Create React/Vite frontend and Express backend.
- Add `/api/health`, CORS and centralized error handling.
- Connect frontend to backend.

**Acceptance:** Frontend successfully calls the health endpoint.

### Phase 2 — GitHub discovery
- Validate username.
- Fetch all public repositories with pagination.
- Handle unknown users, empty profiles and rate limits.

**Acceptance:** A profile with more than 100 public repositories is not silently truncated.

### Phase 3 — Manifest discovery
- Inspect default-branch trees.
- Find root and nested manifests.
- Exclude generated/vendor folders.
- Handle truncated trees and inaccessible files.

**Acceptance:** A monorepo with several eligible manifests returns all their paths.

### Phase 4 — Dependency and lockfile parsing
- Extract all four dependency groups.
- Implement npm lockfile v2/v3 resolution first.
- Mark missing/unsupported lockfiles as unresolved.
- Add pnpm/Yarn support only after npm parsing is tested.

**Acceptance:** A manifest dependency range is mapped to its exact lockfile version when available.

### Phase 5 — OSV integration
- Query exact npm package/version pairs.
- Normalize advisory IDs, summaries, severity and references.
- Add bounded concurrency, timeouts, retries and caching.
- Return explicit unresolved and failed-check statuses.

**Acceptance:** A known vulnerable test version returns its advisory; a non-affected version is not incorrectly marked vulnerable.

### Phase 6 — Dashboard
- Build summary cards and repository list.
- Add expandable manifest and dependency details.
- Add filters, sorting and advisory links.
- Add partial-scan, no-results and API-error states.
- Add JSON/CSV export.

**Acceptance:** A user can move from GitHub username to a readable repository-by-repository report without inspecting raw JSON.

### Phase 7 — Hardening and demo
- Test GitHub rate-limit and OSV-outage behavior.
- Test malformed manifests and missing default branches.
- Verify no repository scripts or packages are executed.
- Add scan timestamp and coverage disclaimer.
- Test responsive layout and one complete end-to-end scan.

## 12. Security and reliability

- Treat GitHub repository content as untrusted input.
- Never clone and execute repositories for this MVP.
- Never run `npm install`, lifecycle scripts, build scripts or package binaries on the server.
- Limit response sizes, file sizes, request duration and scan concurrency.
- Apply backend rate limiting to the scan endpoint.
- Cache GitHub metadata and OSV lookups with a reasonable TTL.
- Do not expose API tokens or stack traces to the frontend.
- Do not request or store user-supplied GitHub tokens.
- Sanitize text rendered in the UI and use safe external-link handling.
- Make partial coverage visible. A truncated tree or unreadable lockfile must not be presented as fully audited.
- Explain that "No known OSV advisory found" is not a guarantee of safety.
- Include source links and scan time so findings can be independently checked.

## 13. Testing plan

| Test case | Expected behavior |
|---|---|
| Valid user with several public repositories | All pages fetched |
| User with more than 100 repositories | Pagination continues |
| Unknown username | Clear not-found message |
| Repository without `package.json` | Mark no manifest; continue |
| Monorepo with multiple manifests | Inspect each eligible manifest |
| Malformed `package.json` | Manifest error; continue |
| Scoped package names | Parsed correctly |
| Version range with supported lockfile | Resolve exact version |
| Version range without lockfile | Mark unresolved |
| Known vulnerable exact version | Show matching OSV advisory |
| No OSV match | Show no-known-advisory status |
| OSV timeout | Mark check failed; continue |
| GitHub rate limit | Explain limit and preserve partial results |
| Truncated repository tree | Fallback or mark partial |
| Nested manifest under `node_modules` | Ignore |
| Repository contains malicious scripts | Never execute them |

Use local fixture repositories and mocked API responses for repeatable tests. Add a small number of live integration tests separately.

## 14. Demo plan

Prepare a public GitHub account/profile with:
- At least one repository with a root `package.json`.
- At least one monorepo with nested manifests.
- At least one repository with a supported lockfile.
- At least one repository without a Node.js manifest.

Demo sequence:
1. Enter the GitHub username.
2. Show the number of public repositories discovered.
3. Show which repositories contain manifests.
4. Open a repository and inspect its dependency inventory.
5. Open a vulnerable dependency and show its advisory evidence and remediation information.
6. Show an unresolved dependency to demonstrate that the system does not guess versions.
7. Explain the coverage boundary: public repositories, npm dependencies, supported lockfiles and OSV-known vulnerabilities.

Do not stage fake findings as real scan output. Clearly label any fixture data used in a presentation.

## 15. Definition of done

The MVP is complete when:
- A user can enter a GitHub username without authenticating.
- All accessible public repositories are discovered through pagination.
- Eligible root and nested `package.json` files are found, subject to visible GitHub API limitations.
- Dependencies are extracted from all supported groups.
- Exact versions are resolved from supported lockfiles.
- Exact resolved versions are checked against OSV.
- Vulnerable, unresolved, no-known-advisory and failed-check states are distinguished.
- The frontend provides a useful repository-level and dependency-level report.
- Repository code is never executed.
- Errors and partial coverage are visible rather than hidden.

**Product positioning:** DepGuard is a public-repository npm dependency vulnerability auditor. It identifies known vulnerabilities in resolved dependency versions and transparently reports where version resolution or scan coverage is incomplete. It does not guarantee that a repository is free from malware or security risks.
