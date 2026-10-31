import test from "node:test";
import assert from "node:assert/strict";
import { resolveWithNpmLock, selectLockfileForManifest } from "../src/lockfile.js";

test("resolves scoped and nested npm v3 packages exactly", () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/@scope/tool": { version: "2.3.4" },
      "packages/app/node_modules/@scope/tool": { version: "2.4.0" }
    }
  });
  assert.equal(resolveWithNpmLock(lock, "packages/app/package.json", "@scope/tool"), "2.4.0");
  assert.equal(resolveWithNpmLock(lock, "package.json", "@scope/tool"), "2.3.4");
});

test("does not resolve unsupported npm lock versions", () => {
  assert.equal(resolveWithNpmLock(JSON.stringify({ lockfileVersion: 1 }), "package.json", "pkg"), null);
});

test("prefers a manifest's nearest lockfile", () => {
  assert.deepEqual(selectLockfileForManifest("apps/web/package.json", [
    "package-lock.json",
    "apps/pnpm-lock.yaml"
  ]), { path: "apps/pnpm-lock.yaml", kind: "pnpm-lock.yaml" });
});

test("prefers npm lockfiles at the same directory level", () => {
  assert.deepEqual(selectLockfileForManifest("package.json", [
    "yarn.lock",
    "package-lock.json"
  ]), { path: "package-lock.json", kind: "package-lock.json" });
});
