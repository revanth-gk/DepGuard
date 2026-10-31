import test from "node:test";
import assert from "node:assert/strict";
import { findSafeUpgrade, orderSafeVersionCandidates } from "../src/recommendations.js";

test("prefers stable patched releases in the installed major before major upgrades", () => {
  assert.deepEqual(orderSafeVersionCandidates("1.2.0", [
    "1.1.9", "1.2.0", "1.2.1-beta.1", "2.0.0", "1.3.0", "1.2.2"
  ]), ["1.3.0", "1.2.2", "2.0.0"]);
});

test("handles scoped packages' version candidates independently of package name", () => {
  assert.deepEqual(orderSafeVersionCandidates("0.8.0", ["0.9.0", "1.0.0"]), ["0.9.0", "1.0.0"]);
});

test("does not recommend a candidate for an invalid current version", () => {
  assert.deepEqual(orderSafeVersionCandidates("^1.0.0", ["2.0.0"]), []);
});

test("checks exact candidate versions and returns the first OSV-clean patch", async () => {
  const checked = [];
  const result = await findSafeUpgrade("example", "1.0.0", async () => ["1.0.1", "1.0.2"], async (_name, version) => {
    checked.push(version);
    return version === "1.0.1" ? [{ id: "GHSA-known" }] : [];
  });
  assert.equal(result.version, "1.0.2");
  assert.deepEqual(checked, ["1.0.2"]);
  assert.equal(result.status, "no_known_osv_advisory");
});

test("does not recommend a version if each candidate has an OSV advisory", async () => {
  const result = await findSafeUpgrade("example", "1.0.0", async () => ["1.0.1"], async () => [{ id: "GHSA-known" }]);
  assert.equal(result, null);
});

test("checks newest stable alternatives across majors", async () => {
  const checked = [];
  const result = await findSafeUpgrade("alternative-package", "0.0.0", async () => [
    "0.1.0", "1.0.0", "2.0.0"
  ], async (_name, version) => {
    checked.push(version);
    return [];
  }, true);
  assert.equal(result.version, "2.0.0");
  assert.deepEqual(checked, ["2.0.0"]);
});
