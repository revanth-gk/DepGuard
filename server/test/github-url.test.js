import test from "node:test";
import assert from "node:assert/strict";
import { parsePublicGithubRepositoryUrl } from "../src/github-url.js";

test("accepts public GitHub repository pages and strips tree paths and .git suffixes", () => {
  assert.deepEqual(
    parsePublicGithubRepositoryUrl("https://www.github.com/Some-Owner/a-repo.git/tree/main/src"),
    { owner: "Some-Owner", repository: "a-repo" }
  );
});

test("rejects hosts and URL schemes other than HTTPS GitHub", () => {
  for (const url of [
    "https://github.com.evil.example/owner/repo",
    "http://github.com/owner/repo",
    "https://user@github.com/owner/repo",
    "https://github.com:8443/owner/repo"
  ]) {
    assert.throws(() => parsePublicGithubRepositoryUrl(url), { code: "INVALID_REPOSITORY_URL" });
  }
});

test("rejects malformed, incomplete, or encoded repository paths", () => {
  for (const url of [
    "not a URL",
    "https://github.com/owner",
    "https://github.com/owner/%2Frepo",
    "https://github.com/../repo"
  ]) {
    assert.throws(() => parsePublicGithubRepositoryUrl(url), { code: "INVALID_REPOSITORY_URL" });
  }
});
