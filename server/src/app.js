import express from "express";
import cors from "cors";
import { HttpError } from "./errors.js";
import { runPublicRepositoryScan, runScan } from "./scan.js";
import { parsePublicGithubRepositoryUrl } from "./github-url.js";
import {
  checkDatabase,
  changeAccountPassword,
  createAccount,
  createSession,
  deleteAdminRow,
  deleteSession,
  findAccount,
  getSavedScan,
  getScanHistory,
  getSessionAccount,
  getShowcase,
  listAdminRows,
  listAdminTables,
  saveScan,
  updateAdminRow
} from "./database.js";
import { getPublicGithubUser, listRepositories } from "./github.js";
import { recommendForDependency } from "./recommendations.js";
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
} from "./auth.js";

const app = express();
const windows = new Map();
const windowMs = 15 * 60 * 1000;
const maxRequests = 10;
const maxConcurrentPublicScans = 2;
const publicRecommendationAttempts = new Map();
const publicScanWindowMs = 15 * 60 * 1000;
const maxPublicRecommendationsPerWindow = 10;
let activePublicScans = 0;
const authAttempts = new Map();
const authWindowMs = 15 * 60 * 1000;

app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:8080", credentials: true }));
app.use(express.json({ limit: "16kb" }));
app.disable("x-powered-by");
app.set("trust proxy", 1);

function secureCookie(request) {
  return process.env.COOKIE_SECURE === "true" || (process.env.NODE_ENV === "production" && request.secure);
}

function rateLimitAuth(request, response) {
  const now = Date.now();
  if (authAttempts.size > 5000) {
    for (const [ip, entry] of authAttempts) {
      if (now - entry.startedAt >= authWindowMs) authAttempts.delete(ip);
    }
  }
  const current = authAttempts.get(request.ip);
  if (!current || now - current.startedAt >= authWindowMs) {
    authAttempts.set(request.ip, { startedAt: now, count: 1 });
    return false;
  }
  current.count += 1;
  if (current.count <= maxRequests) return false;
  response.status(429).json({ error: "Account request limit reached. Try again in 15 minutes.", code: "AUTH_RATE_LIMITED" });
  return true;
}

function rateLimitPublicRecommendations(request, response) {
  const now = Date.now();
  if (publicRecommendationAttempts.size > 5000) {
    for (const [ip, entry] of publicRecommendationAttempts) {
      if (now - entry.startedAt >= publicScanWindowMs) publicRecommendationAttempts.delete(ip);
    }
  }
  const current = publicRecommendationAttempts.get(request.ip);
  if (!current || now - current.startedAt >= publicScanWindowMs) {
    publicRecommendationAttempts.set(request.ip, { startedAt: now, count: 1 });
    return false;
  }
  current.count += 1;
  if (current.count <= maxPublicRecommendationsPerWindow) return false;
  response.status(429).json({ error: "Public recommendation limit reached. Try again in 15 minutes.", code: "PUBLIC_RECOMMENDATION_RATE_LIMITED" });
  return true;
}

async function requireAccount(request, response, next) {
  const token = readSessionCookie(request.headers.cookie);
  if (!token) {
    response.status(401).json({ error: "Sign in to continue.", code: "AUTH_REQUIRED" });
    return;
  }
  try {
    const account = await getSessionAccount(hashSessionToken(token));
    if (!account) {
      response.setHeader("Set-Cookie", clearSessionCookie(secureCookie(request)));
      response.status(401).json({ error: "Your session expired. Sign in again.", code: "SESSION_EXPIRED" });
      return;
    }
    request.account = account;
    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(request, response, next) {
  if (request.account?.role !== "admin") {
    response.status(403).json({ error: "Administrator access is required.", code: "ADMIN_REQUIRED" });
    return;
  }
  next();
}

function validateLoginInput(username, password) {
  return validateUsername(username) && typeof password === "string" && password.length <= 128;
}

async function startSession(request, response, account) {
  const previousToken = readSessionCookie(request.headers.cookie);
  if (previousToken) await deleteSession(hashSessionToken(previousToken));
  const { token, tokenHash } = createSessionToken();
  await createSession(account.id, tokenHash);
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Set-Cookie", sessionCookie(token, secureCookie(request)));
  response.json({ account: { id: account.id, username: account.username, role: account.role } });
}

app.get("/api/health", async (_request, response, next) => {
  try {
    await checkDatabase();
    response.json({ status: "ok", service: "depguard-api", database: "connected" });
  } catch (error) {
    next(error);
  }
});
app.get("/api/auth/me", async (request, response, next) => {
  const token = readSessionCookie(request.headers.cookie);
  if (!token) {
    response.json({ account: null });
    return;
  }
  try {
    const account = await getSessionAccount(hashSessionToken(token));
    if (!account) response.setHeader("Set-Cookie", clearSessionCookie(secureCookie(request)));
    response.setHeader("Cache-Control", "no-store");
    response.json({ account });
  } catch (error) {
    next(error);
  }
});
app.post("/api/auth/register", async (request, response, next) => {
  if (rateLimitAuth(request, response)) return;
  const { username, password } = request.body ?? {};
  if (!validateUsername(username) || !validatePassword(password)) {
    response.status(400).json({ error: "Use a valid GitHub username and a password of 12–128 bytes.", code: "INVALID_CREDENTIALS" });
    return;
  }
  try {
    const githubUser = await getPublicGithubUser(username);
    const account = await createAccount(githubUser.login, await hashPassword(password));
    await startSession(request, response, account);
  } catch (error) {
    next(error);
  }
});
app.post("/api/auth/login", async (request, response, next) => {
  if (rateLimitAuth(request, response)) return;
  const { username, password } = request.body ?? {};
  if (!validateLoginInput(username, password)) {
    response.status(400).json({ error: "Enter a valid GitHub username and password.", code: "INVALID_CREDENTIALS" });
    return;
  }
  try {
    const account = await findAccount(username);
    const valid = account ? await verifyPassword(password, account.passwordHash) : false;
    if (!valid) {
      response.status(401).json({ error: "Username or password is incorrect.", code: "LOGIN_FAILED" });
      return;
    }
    await startSession(request, response, account);
  } catch (error) {
    next(error);
  }
});
app.post("/api/auth/logout", requireAccount, async (request, response, next) => {
  try {
    const token = readSessionCookie(request.headers.cookie);
    await deleteSession(hashSessionToken(token));
    response.setHeader("Set-Cookie", clearSessionCookie(secureCookie(request)));
    response.json({ status: "signed_out" });
  } catch (error) {
    next(error);
  }
});
app.post("/api/auth/change-password", requireAccount, async (request, response, next) => {
  const { currentPassword, newPassword } = request.body ?? {};
  if (typeof currentPassword !== "string" || !validatePassword(newPassword)) {
    response.status(400).json({ error: "Enter your current password and a new password of 12–128 bytes.", code: "INVALID_PASSWORD" });
    return;
  }
  try {
    const account = await findAccount(request.account.username);
    if (!account || !(await verifyPassword(currentPassword, account.passwordHash))) {
      response.status(401).json({ error: "Current password is incorrect.", code: "PASSWORD_CHECK_FAILED" });
      return;
    }
    await changeAccountPassword(account.id, await hashPassword(newPassword));
    await startSession(request, response, account);
  } catch (error) {
    next(error);
  }
});
app.get("/api/repositories", requireAccount, async (request, response, next) => {
  try {
    const repositories = await listRepositories(request.account.username);
    response.json({
      repositories: repositories
        .filter((repository) => repository.owner.login.toLowerCase() === request.account.username.toLowerCase())
        .map(({ name, full_name, html_url, description, archived, default_branch, updated_at }) => ({
          name, fullName: full_name, url: html_url, description, archived, defaultBranch: default_branch, updatedAt: updated_at
        }))
    });
  } catch (error) {
    next(error);
  }
});
app.get("/api/showcase", async (_request, response, next) => {
  try {
    response.json(await getShowcase());
  } catch (error) {
    next(error);
  }
});
app.get("/api/history", requireAccount, async (request, response, next) => {
  try {
    const requestedLimit = Number.parseInt(request.query.limit, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 20;
    response.json({ scans: await getScanHistory(limit, request.account.id) });
  } catch (error) {
    next(error);
  }
});
app.get("/api/history/:id", requireAccount, async (request, response, next) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
    response.status(400).json({ error: "Scan ID is invalid.", code: "INVALID_SCAN_ID" });
    return;
  }
  try {
    const report = await getSavedScan(request.params.id, request.account.id);
    if (!report) {
      response.status(404).json({ error: "Saved scan was not found.", code: "SCAN_NOT_FOUND" });
      return;
    }
    response.json({ report });
  } catch (error) {
    next(error);
  }
});
app.post("/api/history/:id/recommendations", requireAccount, async (request, response, next) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
    response.status(400).json({ error: "Scan ID is invalid.", code: "INVALID_SCAN_ID" });
    return;
  }
  const { packageName, currentVersion } = request.body ?? {};
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(packageName ?? "") ||
      typeof currentVersion !== "string" || currentVersion.length > 128) {
    response.status(400).json({ error: "Provide a package name and exact version from this report.", code: "INVALID_DEPENDENCY" });
    return;
  }
  try {
    response.json(await recommendForDependency(request.account.id, request.params.id, packageName, currentVersion));
  } catch (error) {
    next(error);
  }
});
app.post("/api/public-scans/:id/recommendations", async (request, response, next) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
    response.status(400).json({ error: "Scan ID is invalid.", code: "INVALID_SCAN_ID" });
    return;
  }
  const { packageName, currentVersion } = request.body ?? {};
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(packageName ?? "") ||
      typeof currentVersion !== "string" || currentVersion.length > 128) {
    response.status(400).json({ error: "Provide a package name and exact version from this report.", code: "INVALID_DEPENDENCY" });
    return;
  }
  if (rateLimitPublicRecommendations(request, response)) return;
  try {
    response.json(await recommendForDependency(null, request.params.id, packageName, currentVersion));
  } catch (error) {
    next(error);
  }
});
app.post("/api/scan", requireAccount, async (request, response, next) => {
  const now = Date.now();
  const ip = request.ip;
  const record = windows.get(ip);
  if (!record || now - record.startedAt > windowMs) windows.set(ip, { startedAt: now, count: 1 });
  else if (++record.count > maxRequests) {
    response.status(429).json({ error: "Scan limit reached. Try again in 15 minutes.", code: "RATE_LIMITED" });
    return;
  }

  const repositoryName = request.body?.repositoryName;
  if (typeof repositoryName !== "string" || repositoryName.length > 100 ||
      !/^[a-zA-Z0-9._-]+$/.test(repositoryName) || repositoryName === "." || repositoryName === "..") {
    response.status(400).json({ error: "Enter the name of a repository owned by your GitHub account.", code: "INVALID_REPOSITORY" });
    return;
  }
  try {
    const report = await runScan(request.account.username, repositoryName);
    await saveScan(report, request.account.id);
    response.json(report);
  } catch (error) {
    next(error);
  }
});
app.post("/api/public-scan", async (request, response, next) => {
  let repository;
  try {
    repository = parsePublicGithubRepositoryUrl(request.body?.repositoryUrl);
  } catch (error) {
    next(error);
    return;
  }

  if (activePublicScans >= maxConcurrentPublicScans) {
    response.status(503).json({ error: "Public scans are busy. Try again shortly.", code: "PUBLIC_SCANS_BUSY" });
    return;
  }
  activePublicScans += 1;
  try {
    const report = await runPublicRepositoryScan(repository.owner, repository.repository);
    await saveScan(report, null);
    response.json(report);
  } catch (error) {
    next(error);
  } finally {
    activePublicScans -= 1;
  }
});
app.get("/api/admin/tables", requireAccount, requireAdmin, (_request, response) => {
  response.json({ tables: listAdminTables(), schemaChanges: "Use reviewed SQL migrations; the web console does not alter database structure." });
});
app.get("/api/admin/tables/:table", requireAccount, requireAdmin, async (request, response, next) => {
  try {
    const requestedLimit = Number.parseInt(request.query.limit, 10);
    const requestedOffset = Number.parseInt(request.query.offset, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 25;
    const offset = Number.isFinite(requestedOffset) ? Math.max(requestedOffset, 0) : 0;
    response.json(await listAdminRows(request.params.table, limit, offset));
  } catch (error) {
    next(error);
  }
});
app.patch("/api/admin/tables/:table/:rowId", requireAccount, requireAdmin, async (request, response, next) => {
  try {
    const row = await updateAdminRow(request.params.table, request.params.rowId, request.body?.values, request.account.id);
    response.json({ row });
  } catch (error) {
    next(error);
  }
});
app.delete("/api/admin/tables/:table/:rowId", requireAccount, requireAdmin, async (request, response, next) => {
  try {
    const deleted = await deleteAdminRow(request.params.table, request.params.rowId, request.account.id);
    response.json({ deleted });
  } catch (error) {
    next(error);
  }
});
app.post("/api/admin/accounts/:id/reset-password", requireAccount, requireAdmin, async (request, response, next) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
    response.status(400).json({ error: "Account ID is invalid.", code: "INVALID_ACCOUNT_ID" });
    return;
  }
  if (request.params.id === request.account.id) {
    response.status(403).json({ error: "Use the signed-in account password-change flow to update your own password.", code: "SELF_PASSWORD_RESET" });
    return;
  }
  const { password } = request.body ?? {};
  if (!validatePassword(password)) {
    response.status(400).json({ error: "New password must be 12–128 bytes.", code: "INVALID_PASSWORD" });
    return;
  }
  try {
    await changeAccountPassword(request.params.id, await hashPassword(password));
    response.json({ status: "password_reset", sessionsRevoked: true });
  } catch (error) {
    next(error);
  }
});

app.use((error, _request, response, _next) => {
  if (error instanceof HttpError) {
    response.status(error.status).json({ error: error.message, code: error.code });
    return;
  }
  if (error.code === "ECONNREFUSED" || error.code === "57P03") {
    response.status(503).json({ error: "The scan database is unavailable. Try again shortly.", code: "DATABASE_UNAVAILABLE" });
    return;
  }
  if (error.code === "23505") {
    response.status(409).json({ error: "A row with those unique values already exists.", code: "DATABASE_CONFLICT" });
    return;
  }
  if (["23503", "23514", "22P02", "22007", "22003"].includes(error.code)) {
    response.status(400).json({ error: "One or more values violate database constraints.", code: "INVALID_DATABASE_VALUE" });
    return;
  }
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: "Request body must be valid JSON.", code: "INVALID_JSON" });
    return;
  }
  console.error("Unhandled API error:", error);
  response.status(500).json({ error: "An unexpected scan error occurred.", code: "INTERNAL_ERROR" });
});

export default app;
