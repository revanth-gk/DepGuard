const lockPriority = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"];

function packagePathCandidates(manifestPath, name) {
  const manifestDirectory = manifestPath.includes("/") ? manifestPath.slice(0, manifestPath.lastIndexOf("/")) : "";
  const directories = manifestDirectory ? manifestDirectory.split("/") : [];
  const candidates = [];
  for (let index = directories.length; index >= 0; index -= 1) {
    const prefix = directories.slice(0, index).join("/");
    candidates.push([prefix, "node_modules", name].filter(Boolean).join("/"));
  }
  candidates.push(`node_modules/${name}`);
  return [...new Set(candidates)];
}

export function resolveWithNpmLock(lockText, manifestPath, packageName) {
  let lock;
  try {
    lock = JSON.parse(lockText);
  } catch {
    throw new Error("The npm lockfile is malformed JSON.");
  }
  if (![2, 3].includes(lock.lockfileVersion)) return null;
  for (const candidate of packagePathCandidates(manifestPath, packageName)) {
    const version = lock.packages?.[candidate]?.version;
    if (typeof version === "string" && version) return version;
  }
  const rootVersion = lock.dependencies?.[packageName]?.version;
  return typeof rootVersion === "string" ? rootVersion : null;
}

export function selectLockfileForManifest(manifestPath, lockfiles) {
  const manifestDirectory = manifestPath.includes("/") ? manifestPath.slice(0, manifestPath.lastIndexOf("/")) : "";
  const ancestors = [];
  let current = manifestDirectory;
  while (true) {
    ancestors.push(current);
    if (!current) break;
    current = current.includes("/") ? current.slice(0, current.lastIndexOf("/")) : "";
  }

  for (const directory of ancestors) {
    for (const name of lockPriority) {
      const candidate = directory ? `${directory}/${name}` : name;
      if (lockfiles.includes(candidate)) return { path: candidate, kind: name };
    }
  }
  return null;
}
