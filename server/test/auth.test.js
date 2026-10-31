import test from "node:test";
import assert from "node:assert/strict";
import {
  clearSessionCookie,
  createSessionToken,
  hashPassword,
  hashSessionToken,
  readSessionCookie,
  sessionCookie,
  validatePassword,
  validateUsername,
  verifyPassword
} from "../src/auth.js";

test("validates GitHub-style account names and requires long passwords", () => {
  assert.equal(validateUsername("revanth-gk"), true);
  assert.equal(validateUsername("-bad"), false);
  assert.equal(validateUsername("bad name"), false);
  assert.equal(validatePassword("long-enough-password"), true);
  assert.equal(validatePassword("short"), false);
});

test("stores a salted scrypt hash and verifies only the matching password", async () => {
  const hash = await hashPassword("correct-horse-staple");
  assert.match(hash, /^scrypt\$32768\$8\$1\$/);
  assert.notEqual(hash, await hashPassword("correct-horse-staple"));
  assert.equal(await verifyPassword("correct-horse-staple", hash), true);
  assert.equal(await verifyPassword("wrong-password", hash), false);
});

test("session cookies contain a random token while the stored value is only its digest", () => {
  const first = createSessionToken();
  const second = createSessionToken();
  assert.notEqual(first.token, second.token);
  assert.equal(first.tokenHash, hashSessionToken(first.token));
  assert.notEqual(first.tokenHash, first.token);
  assert.equal(readSessionCookie(`other=ignored; depguard_session=${first.token}`), first.token);
  assert.equal(readSessionCookie("depguard_session=not-a-valid-token"), null);
  assert.match(sessionCookie(first.token), /HttpOnly; SameSite=Strict/);
  assert.match(clearSessionCookie(true), /Max-Age=0; Secure/);
});
