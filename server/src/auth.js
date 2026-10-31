import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const keyLength = 64;
const cost = 32768;
const blockSize = 8;
const parallelization = 1;
const maxMemory = 64 * 1024 * 1024;
export const sessionCookieName = "depguard_session";
export const sessionLifetimeMs = 7 * 24 * 60 * 60 * 1000;

export function validateUsername(username) {
  return typeof username === "string" &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/.test(username);
}

export function validatePassword(password) {
  return typeof password === "string" && password.length >= 12 && Buffer.byteLength(password, "utf8") <= 128;
}

export async function hashPassword(password) {
  if (!validatePassword(password)) throw new Error("Password must be 12–128 bytes.");
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, keyLength, {
    N: cost,
    r: blockSize,
    p: parallelization,
    maxmem: maxMemory
  });
  return `scrypt$${cost}$${blockSize}$${parallelization}$${salt.toString("hex")}$${derived.toString("hex")}`;
}

export async function verifyPassword(password, encodedHash) {
  const [algorithm, n, r, p, saltHex, keyHex] = encodedHash.split("$");
  if (algorithm !== "scrypt" || Number(n) !== cost || Number(r) !== blockSize || Number(p) !== parallelization ||
      !/^[0-9a-f]{32}$/i.test(saltHex) || !/^[0-9a-f]{128}$/i.test(keyHex)) return false;
  const expected = Buffer.from(keyHex, "hex");
  const actual = await scrypt(password, Buffer.from(saltHex, "hex"), expected.length, {
    N: cost,
    r: blockSize,
    p: parallelization,
    maxmem: maxMemory
  });
  return timingSafeEqual(expected, actual);
}

export function createSessionToken() {
  const token = randomBytes(32).toString("base64url");
  return { token, tokenHash: hashSessionToken(token) };
}

export function hashSessionToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function readSessionCookie(cookieHeader = "") {
  const entry = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${sessionCookieName}=`));
  if (!entry) return null;
  const token = entry.slice(sessionCookieName.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

export function sessionCookie(token, secure = false) {
  return `${sessionCookieName}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(sessionLifetimeMs / 1000)}${secure ? "; Secure" : ""}`;
}

export function clearSessionCookie(secure = false) {
  return `${sessionCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;
}
