import { HttpError } from "./errors.js";

const githubUsernamePattern = /^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i;
const repositoryNamePattern = /^[a-z\d._-]{1,100}$/i;

export function parsePublicGithubRepositoryUrl(value) {
  if (typeof value !== "string" || value.length > 2048) {
    throw new HttpError(400, "Enter a public GitHub repository URL.", "INVALID_REPOSITORY_URL");
  }

  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new HttpError(400, "Enter a valid public GitHub repository URL.", "INVALID_REPOSITORY_URL");
  }

  if (url.protocol !== "https:" || !["github.com", "www.github.com"].includes(url.hostname.toLowerCase()) ||
      url.username || url.password || url.port) {
    throw new HttpError(400, "Use an HTTPS URL from github.com.", "INVALID_REPOSITORY_URL");
  }

  let [owner, repository] = url.pathname.split("/").filter(Boolean).slice(0, 2);
  try {
    owner = decodeURIComponent(owner ?? "");
    repository = decodeURIComponent(repository ?? "");
  } catch {
    throw new HttpError(400, "The GitHub repository URL contains an invalid path.", "INVALID_REPOSITORY_URL");
  }

  if (repository.endsWith(".git")) repository = repository.slice(0, -4);
  if (!githubUsernamePattern.test(owner) || !repositoryNamePattern.test(repository) ||
      repository === "." || repository === "..") {
    throw new HttpError(400, "Use a GitHub repository URL in the form github.com/owner/repository.", "INVALID_REPOSITORY_URL");
  }

  return { owner, repository };
}
