import semver from "semver";
import { getRecommendationSource, saveRecommendations } from "./database.js";
import { queryOsv } from "./osv.js";
import { HttpError } from "./errors.js";

const REGISTRY = "https://registry.npmjs.org";
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const MAX_PACKUMENT_BYTES = 8 * 1024 * 1024;
const MAX_CANDIDATES = 18;

export function orderSafeVersionCandidates(currentVersion, versions, preferLatest = false) {
  const current = semver.valid(currentVersion);
  if (!current) return [];
  const valid = [...new Set(versions)]
    .map((version) => semver.valid(version))
    .filter((version) => version && semver.gt(version, current) && semver.prerelease(version) === null);
  const sortDescending = (left, right) => semver.rcompare(left, right);
  if (preferLatest) return valid.sort(sortDescending).slice(0, MAX_CANDIDATES + 5);
  const sameMajor = valid.filter((version) => semver.major(version) === semver.major(current)).sort(sortDescending);
  const newerMajors = valid.filter((version) => semver.major(version) !== semver.major(current)).sort(sortDescending);
  return [...sameMajor.slice(0, MAX_CANDIDATES), ...newerMajors.slice(0, 5)];
}

async function loadNpmVersions(packageName) {
  const path = packageName.split("/").map(encodeURIComponent).join("/");
  let response;
  try {
    response = await fetch(`${REGISTRY}/${path}`, {
      headers: { Accept: "application/vnd.npm.install-v1+json", "User-Agent": "DepGuard/1.0" },
      signal: AbortSignal.timeout(15000)
    });
  } catch {
    throw new HttpError(502, "The npm registry could not be reached to check upgrade candidates.", "NPM_REGISTRY_UNAVAILABLE");
  }
  if (response.status === 404) throw new HttpError(404, "This package is not available in the npm registry.", "NPM_PACKAGE_NOT_FOUND");
  if (!response.ok) throw new HttpError(502, `The npm registry returned an error (${response.status}).`, "NPM_REGISTRY_ERROR");
  const declaredSize = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_PACKUMENT_BYTES) {
    throw new HttpError(502, "The npm package metadata is too large to inspect safely.", "NPM_METADATA_TOO_LARGE");
  }
  const body = await response.text();
  if (Buffer.byteLength(body) > MAX_PACKUMENT_BYTES) {
    throw new HttpError(502, "The npm package metadata is too large to inspect safely.", "NPM_METADATA_TOO_LARGE");
  }
  let metadata;
  try {
    metadata = JSON.parse(body);
  } catch {
    throw new HttpError(502, "The npm registry returned invalid package metadata.", "NPM_REGISTRY_RESPONSE");
  }
  return Object.entries(metadata.versions ?? {})
    .filter(([, version]) => !version.deprecated)
    .map(([version]) => version);
}

export async function findSafeUpgrade(
  packageName,
  currentVersion,
  loadVersions = loadNpmVersions,
  checkVersion = queryOsv,
  preferLatest = false
) {
  const versions = orderSafeVersionCandidates(currentVersion, await loadVersions(packageName), preferLatest);
  for (const version of versions) {
    const vulnerabilities = await checkVersion(packageName, version);
    if (vulnerabilities.length === 0) {
      return {
        packageName,
        version,
        kind: "upgrade",
        status: "no_known_osv_advisory",
        majorUpgrade: semver.major(version) !== semver.major(currentVersion),
        evidence: "Checked against OSV for this exact version; absence of a known advisory is not a safety guarantee."
      };
    }
  }
  return null;
}

async function getGroqAlternatives(packageName, currentVersion, advisories) {
  if (!process.env.GROQ_API_KEY) return { alternatives: [], note: "Alternative-package suggestions require a server-side GROQ_API_KEY." };
  let response;
  try {
    response = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
        temperature: 0.1,
        max_tokens: 350,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: "Suggest up to three actively maintained npm package alternatives for the same general use as the named package. Return JSON only: {\"alternatives\":[{\"name\":\"npm-package-name\",\"reason\":\"brief reason\"}]}. Do not claim security or compatibility. Never suggest the input package."
          },
          {
            role: "user",
            content: JSON.stringify({
              package: packageName,
              currentVersion,
              knownAdvisories: advisories.map(({ id, summary }) => ({ id, summary: summary.slice(0, 240) }))
            })
          }
        ]
      }),
      signal: AbortSignal.timeout(20000)
    });
  } catch {
    return { alternatives: [], note: "Groq could not be reached; verified version upgrades remain available." };
  }
  if (!response.ok) {
    return { alternatives: [], note: `Groq alternative suggestions failed (${response.status}); verified version upgrades remain available.` };
  }
  let body;
  try {
    body = await response.json();
    const parsed = JSON.parse(body.choices?.[0]?.message?.content ?? "");
    const candidates = (Array.isArray(parsed.alternatives) ? parsed.alternatives : [])
      .filter((item) => item && typeof item.name === "string" && item.name !== packageName)
      .filter((item) => /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(item.name))
      .map((item) => ({ name: item.name, reason: typeof item.reason === "string" ? item.reason.slice(0, 240) : null }))
      .filter((item, index, list) => list.findIndex((candidate) => candidate.name === item.name) === index);
    const names = [...new Set(candidates.map((item) => item.name))]
      .slice(0, 3)
      .map((name) => candidates.find((candidate) => candidate.name === name));
    return { alternatives: names, note: null };
  } catch {
    return { alternatives: [], note: "Groq returned invalid alternative suggestions; verified version upgrades remain available." };
  }
}

export async function recommendForDependency(accountId, scanId, packageName, currentVersion) {
  const source = await getRecommendationSource(scanId, accountId, packageName, currentVersion);
  if (!source) throw new HttpError(404, "No vulnerable dependency with this exact package and version exists in your saved scan.", "DEPENDENCY_NOT_FOUND");

  const suggestions = [];
  let upgradeError = null;
  try {
    const upgrade = await findSafeUpgrade(packageName, currentVersion);
    if (upgrade) suggestions.push(upgrade);
    else upgradeError = "No newer stable version in the checked candidate set had zero known OSV advisories.";
  } catch (error) {
    upgradeError = error.message;
  }

  const groq = await getGroqAlternatives(packageName, currentVersion, source.advisories);
  const alternativeErrors = [];
  for (const alternative of groq.alternatives) {
    try {
      const verified = await findSafeUpgrade(alternative.name, "0.0.0", loadNpmVersions, queryOsv, true);
      if (verified) {
        suggestions.push({
          ...verified,
          kind: "alternative",
          reason: `${alternative.reason ? `${alternative.reason} ` : ""}Suggested by Groq; npm publication and this exact version were checked against OSV. API compatibility requires your review.`
        });
      } else {
        alternativeErrors.push(`${alternative.name} did not have a newer stable candidate with zero known OSV advisories.`);
      }
    } catch (error) {
      alternativeErrors.push(`${alternative.name}: ${error.message}`);
    }
  }

  const notes = [upgradeError, groq.note, ...alternativeErrors].filter(Boolean);
  const provider = process.env.GROQ_API_KEY ? "groq+osv+npm" : "osv+npm";
  const saved = await saveRecommendations(accountId, scanId, packageName, currentVersion, suggestions, provider);
  return {
    id: saved.id,
    createdAt: saved.createdAt,
    packageName,
    currentVersion,
    repository: source.repository,
    manifest: source.manifest,
    suggestions,
    notes,
    checkedAgainst: ["npm registry", "OSV"],
    disclaimer: "A clean OSV lookup is not proof of safety. Review release notes and test API compatibility before updating."
  };
}
