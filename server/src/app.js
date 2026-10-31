import express from "express";
import cors from "cors";
import { HttpError } from "./errors.js";
import { runScan } from "./scan.js";
import { checkDatabase, getSavedScan, getScanHistory, getShowcase, saveScan } from "./database.js";

const app = express();
const windows = new Map();
const windowMs = 15 * 60 * 1000;
const maxRequests = 10;

app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:8080" }));
app.use(express.json({ limit: "16kb" }));
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.get("/api/health", async (_request, response, next) => {
  try {
    await checkDatabase();
    response.json({ status: "ok", service: "depguard-api", database: "connected" });
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
app.get("/api/history", async (request, response, next) => {
  try {
    const requestedLimit = Number.parseInt(request.query.limit, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 20;
    response.json({ scans: await getScanHistory(limit) });
  } catch (error) {
    next(error);
  }
});
app.get("/api/history/:id", async (request, response, next) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.params.id)) {
    response.status(400).json({ error: "Scan ID is invalid.", code: "INVALID_SCAN_ID" });
    return;
  }
  try {
    const report = await getSavedScan(request.params.id);
    if (!report) {
      response.status(404).json({ error: "Saved scan was not found.", code: "SCAN_NOT_FOUND" });
      return;
    }
    response.json({ report });
  } catch (error) {
    next(error);
  }
});
app.post("/api/scan", async (request, response, next) => {
  const now = Date.now();
  const ip = request.ip;
  const record = windows.get(ip);
  if (!record || now - record.startedAt > windowMs) windows.set(ip, { startedAt: now, count: 1 });
  else if (++record.count > maxRequests) {
    response.status(429).json({ error: "Scan limit reached. Try again in 15 minutes.", code: "RATE_LIMITED" });
    return;
  }

  const username = request.body?.username;
  if (typeof username !== "string" || !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(username)) {
    response.status(400).json({ error: "Enter a valid GitHub username.", code: "INVALID_USERNAME" });
    return;
  }
  try {
    const report = await runScan(username);
    await saveScan(report);
    response.json(report);
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
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: "Request body must be valid JSON.", code: "INVALID_JSON" });
    return;
  }
  console.error("Unhandled API error:", error);
  response.status(500).json({ error: "An unexpected scan error occurred.", code: "INTERNAL_ERROR" });
});

export default app;
