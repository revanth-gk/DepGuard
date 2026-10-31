import { HttpError } from "./errors.js";

const API_ROOT = "https://api.github.com";
const excluded = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "vendor"]);

async function githubRequest(path) {
  let response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "DepGuard/1.0",
        ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {})
      },
      signal: AbortSignal.timeout(15000)
    });
  } catch (error) {
    throw new HttpError(502, "GitHub could not be reached. Try again shortly.", "GITHUB_UNAVAILABLE");
  }

  if (!response.ok) {
    if (response.status === 404) throw new HttpError(404, "GitHub user or repository was not found.", "NOT_FOUND");
    if (response.status === 403 || response.status === 429) {
      const reset = response.headers.get("x-ratelimit-reset");
      const retryAt = reset ? ` Try again after ${new Date(Number(reset) * 1000).toLocaleTimeString()}.` : "";
      throw new HttpError(429, `GitHub API rate limit reached.${retryAt}`, "GITHUB_RATE_LIMIT");
    }
    throw new HttpError(502, `GitHub returned an error (${response.status}).`, "GITHUB_ERROR");
  }
  return response.json();
}

export async function listRepositories(username) {
  const repositories = [];
  for (let page = 1; ; page += 1) {
    const batch = await githubRequest(`/users/${encodeURIComponent(username)}/repos?type=public&per_page=100&page=${page}&sort=updated`);
    if (!Array.isArray(batch)) throw new HttpError(502, "GitHub returned an unexpected repository list.", "GITHUB_RESPONSE");
    repositories.push(...batch);
    if (batch.length < 100) return repositories;
  }
}

function isEligibleManifest(path) {
  const parts = path.split("/");
  return parts.at(-1) === "package.json" && !parts.slice(0, -1).some((part) => excluded.has(part));
}

export async function listRepositoryFiles(repository) {
  const root = `/repos/${repository.full_name}/git/trees/`;
  const initial = await githubRequest(`${root}${encodeURIComponent(repository.default_branch)}?recursive=1`);
  const paths = [];
  const partialErrors = [];
  if (initial.truncated) {
    const rootTree = await githubRequest(`${root}${encodeURIComponent(repository.default_branch)}`);
    if (rootTree.truncated) partialErrors.push("The repository root tree is truncated; some paths may not be visible.");
    const pending = rootTree.tree.filter((item) => item.type === "tree").map((item) => ({ sha: item.sha, path: item.path }));
    paths.push(...rootTree.tree.filter((item) => item.type === "blob").map((item) => item.path));
    while (pending.length) {
      const current = pending.shift();
      try {
        const tree = await githubRequest(`${root}${current.sha}`);
        if (tree.truncated) partialErrors.push(`${current.path}: GitHub truncated this subtree; some paths may not be visible.`);
        for (const item of tree.tree) {
          const itemPath = `${current.path}/${item.path}`;
          if (item.type === "tree") pending.push({ sha: item.sha, path: itemPath });
          else if (item.type === "blob") paths.push(itemPath);
        }
      } catch (error) {
        partialErrors.push(`${current.path}: ${error.message}`);
      }
    }
  } else {
    paths.push(...initial.tree.filter((item) => item.type === "blob").map((item) => item.path));
  }

  return {
    manifests: paths.filter(isEligibleManifest),
    lockfiles: paths.filter((path) => ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"].includes(path.split("/").at(-1))),
    partialErrors
  };
}

export async function getRepositoryFile(repository, path) {
  const data = await githubRequest(`/repos/${repository.full_name}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(repository.default_branch)}`);
  if (Array.isArray(data) || data.type !== "file" || !data.content) throw new Error("File is not available through the GitHub contents API.");
  if (data.size > 1_000_000) throw new Error("File exceeds the 1 MB scan limit.");
  return Buffer.from(data.content, "base64").toString("utf8");
}
