import { randomUUID } from "node:crypto";
import { listRepositories, listRepositoryFiles, getPublicGithubRepository, getRepositoryFile } from "./github.js";
import { selectLockfileForManifest, resolveWithNpmLock } from "./lockfile.js";
import { mapWithConcurrency, queryOsv } from "./osv.js";
import { HttpError } from "./errors.js";

const dependencyGroups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

function emptySummary(repositoriesFound = 0) {
  return {
    repositoriesFound,
    repositoriesScanned: 0,
    repositoriesWithPackageJson: 0,
    manifestsScanned: 0,
    dependenciesChecked: 0,
    vulnerableOccurrences: 0,
    unresolvedOccurrences: 0,
    scanErrors: 0
  };
}

async function inspectRepository(repository) {
  const result = {
    name: repository.name,
    fullName: repository.full_name,
    url: repository.html_url,
    defaultBranch: repository.default_branch,
    archived: repository.archived,
    manifests: [],
    status: "complete",
    errors: []
  };
  if (!repository.default_branch) {
    result.status = "failed";
    result.errors.push("Repository has no default branch.");
    return result;
  }

  let files;
  try {
    files = await listRepositoryFiles(repository);
  } catch (error) {
    result.status = "failed";
    result.errors.push(error.message);
    return result;
  }
  result.errors.push(...files.partialErrors);
  if (files.partialErrors.length) result.status = "partial";

  const lockContents = new Map();
  for (const manifestPath of files.manifests) {
    const manifest = { path: manifestPath, status: "scanned", dependencies: [], errors: [] };
    try {
      const content = await getRepositoryFile(repository, manifestPath);
      const parsed = JSON.parse(content);
      const lock = selectLockfileForManifest(manifestPath, files.lockfiles);
      let lockText = null;
      if (lock) {
        try {
          if (!lockContents.has(lock.path)) lockContents.set(lock.path, await getRepositoryFile(repository, lock.path));
          lockText = lockContents.get(lock.path);
        } catch (error) {
          manifest.errors.push(`Could not read ${lock.path}: ${error.message}`);
        }
      }
      for (const group of dependencyGroups) {
        const declarations = parsed[group];
        if (!declarations || typeof declarations !== "object" || Array.isArray(declarations)) continue;
        for (const [name, declaredVersion] of Object.entries(declarations)) {
          let resolvedVersion = null;
          if (lockText && lock && ["package-lock.json", "npm-shrinkwrap.json"].includes(lock.kind)) {
            try {
              resolvedVersion = resolveWithNpmLock(lockText, manifestPath, name);
            } catch (error) {
              manifest.errors.push(error.message);
              lockText = null;
            }
          }
          manifest.dependencies.push({
            name,
            declaredVersion: String(declaredVersion),
            resolvedVersion,
            dependencyType: group,
            status: resolvedVersion ? "pending" : "unresolved",
            vulnerabilities: [],
            error: null
          });
        }
      }
      if (manifest.errors.length) manifest.status = "partial";
    } catch (error) {
      manifest.status = "error";
      manifest.errors.push(error instanceof SyntaxError ? "package.json is malformed JSON." : error.message);
    }
    result.manifests.push(manifest);
    if (manifest.status !== "scanned") {
      if (result.status === "complete") result.status = "partial";
      result.errors.push(...manifest.errors.map((message) => `${manifestPath}: ${message}`));
    }
  }
  return result;
}

async function scanRepositories(username, selectedRepositories, repositoriesFound, repositoryName, publicScan) {
  const summary = emptySummary(repositoriesFound);
  summary.repositoriesFound = repositoryName ? selectedRepositories.length : repositoriesFound;
  const repositories = await mapWithConcurrency(selectedRepositories, inspectRepository);
  for (const repository of repositories) {
    summary.repositoriesScanned += repository.status === "failed" ? 0 : 1;
    if (repository.manifests.length) summary.repositoriesWithPackageJson += 1;
    if (repository.errors.length || repository.manifests.some((manifest) => manifest.status !== "scanned")) summary.scanErrors += 1;
    summary.manifestsScanned += repository.manifests.filter((manifest) => manifest.status === "scanned" || manifest.status === "partial").length;
  }

  const dependencies = repositories.flatMap((repository) => repository.manifests.flatMap((manifest) =>
    manifest.dependencies.map((dependency) => ({ repository, manifest, dependency }))
  ));
  const exactVersions = [...new Set(dependencies.filter(({ dependency }) => dependency.resolvedVersion)
    .map(({ dependency }) => `${dependency.name}\u0000${dependency.resolvedVersion}`))];
  const checks = await mapWithConcurrency(exactVersions, async (key) => {
    const [name, version] = key.split("\u0000");
    try {
      return { key, vulnerabilities: await queryOsv(name, version), error: null };
    } catch (error) {
      return { key, vulnerabilities: [], error: error.message };
    }
  });
  const checkResults = new Map(checks.map((check) => [check.key, check]));
  for (const { dependency } of dependencies) {
    if (!dependency.resolvedVersion) {
      summary.unresolvedOccurrences += 1;
      continue;
    }
    const check = checkResults.get(`${dependency.name}\u0000${dependency.resolvedVersion}`);
    if (check.error) {
      dependency.status = "check_failed";
      dependency.error = check.error;
    } else {
      dependency.vulnerabilities = check.vulnerabilities;
      dependency.status = check.vulnerabilities.length ? "vulnerable" : "no_known_advisory";
      if (dependency.status === "vulnerable") summary.vulnerableOccurrences += 1;
    }
    summary.dependenciesChecked += 1;
  }
  summary.scanErrors += dependencies.filter(({ dependency }) => dependency.status === "check_failed").length;

  return {
    scanId: randomUUID(),
    username,
    repositoryName: repositoryName ?? null,
    publicScan,
    status: summary.scanErrors ? "partial" : "completed",
    scannedAt: new Date().toISOString(),
    persisted: true,
    summary,
    repositories,
    errors: repositories.flatMap((repository) => repository.errors.map((message) => ({ repository: repository.fullName, message })))
  };
}

export async function runScan(username, repositoryName) {
  const discovered = await listRepositories(username);
  const selectedRepositories = repositoryName
    ? discovered.filter((repository) =>
      repository.name.toLowerCase() === repositoryName.toLowerCase() &&
      repository.owner.login.toLowerCase() === username.toLowerCase())
    : discovered;
  if (repositoryName && selectedRepositories.length === 0) {
    throw new HttpError(404, "That public repository was not found under your account.", "REPOSITORY_NOT_FOUND");
  }
  if (repositoryName && selectedRepositories.length > 1) {
    throw new HttpError(400, "More than one repository matched that name. Use the full repository name.", "AMBIGUOUS_REPOSITORY");
  }
  return scanRepositories(username, selectedRepositories, discovered.length, repositoryName, false);
}

export async function runPublicRepositoryScan(owner, repositoryName) {
  const repository = await getPublicGithubRepository(owner, repositoryName);
  return scanRepositories(repository.owner.login, [repository], 1, repository.name, true);
}
