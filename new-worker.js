// --- Simple helpers ---------------------------------------------------------
const num = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};
const bool = (v, d) => {
  if (v === undefined || v === null) return d;
  const s = String(v).toLowerCase().trim();
  return s === "true" || s === "1" || s === "yes";
};
const bytes = (s) => new TextEncoder().encode(String(s)).length;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function withRetry(fn, { retries = 2, baseMs = 600, factor = 1.8, jitter = true } = {}) {
  let attempt = 0;
  let delay = baseMs;
  let lastError;
  while (attempt <= retries) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const message = String(err?.message || err);
      if (!/timeout|timed out|429|5\d\d|unavailable|quota|exhausted/i.test(message) || attempt === retries) {
        break;
      }
      const wait = jitter ? Math.round(delay * (0.7 + Math.random() * 0.6)) : delay;
      await sleep(wait);
      delay = Math.min(delay * factor, 8000);
      attempt += 1;
    }
  }
  throw lastError;
}

function stable(obj) {
  const seen = new WeakSet();
  const sort = (value) => {
    if (value && typeof value === "object") {
      if (seen.has(value)) return null;
      seen.add(value);
      if (Array.isArray(value)) return value.map(sort);
      return Object.keys(value)
        .sort()
        .reduce((out, key) => {
          out[key] = sort(value[key]);
          return out;
        }, {});
    }
    return value;
  };
  return JSON.stringify(sort(obj));
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function normalizeTranscript(text) {
  if (!text) return "";
  return String(text)
    .replace(/\t/g, " ")
    .replace(/[ \u00A0]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

async function simpleSkillKeyHash({ cacheVersion, transcript, sellerId, skillName }) {
  const payload = {
    v: String(cacheVersion || "1"),
    sellerId: String(sellerId || ""),
    skillName: String(skillName || ""),
    transcript: normalizeTranscript(transcript || ""),
  };
  return sha256Hex(stable(payload));
}

async function kvGetJSON(ns, key) {
  if (!ns) return null;
  const raw = await ns.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function kvPutJSON(ns, key, value, ttlSecs, cacheVersion) {
  if (!ns) return;
  await ns.put(key, JSON.stringify(value), {
    expirationTtl: ttlSecs,
    metadata: { createdAt: Date.now(), version: cacheVersion },
  });
}

function providerPrefs(env) {
  const order = (env.PROVIDER_ORDER || "fireworks,together,groq,google,openai")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allow_fallbacks = String(env.ALLOW_FALLBACKS || "1") === "1";
  return { order, allow_fallbacks };
}

async function chatOpenRouter(env, payload, { hint = "openrouter" } = {}) {
  if (!env.OPENROUTER_KEY) throw new Error(`${hint} missing OPENROUTER_KEY`);
  const base = (env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1").replace(/\/+$/, "");
  const timeoutMs = num(env.OPENROUTER_TIMEOUT_MS, 120000);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs);

  let response;
  let raw = "";
  try {
    response = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.OPENROUTER_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://yourapp.example",
        "X-Title": "Sales Skills Worker",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    raw = await response.text();
  } catch (err) {
    clearTimeout(timer);
    throw new Error(`${hint} request failed: ${err?.message || err}`);
  }
  clearTimeout(timer);

  if (!response.ok) {
    throw new Error(`${hint} ${response.status}: ${raw.slice(0, 400)}`);
  }

  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new Error(`${hint} returned non-JSON: ${raw.slice(0, 200)}`);
  }

  const servedBy =
    response.headers.get("openrouter-proxy-provider") ||
    response.headers.get("x-openrouter-provider") ||
    json?.provider?.name ||
    json?.model ||
    "unknown";
  const content = json?.choices?.[0]?.message?.content ?? "";
  return { json, raw, content, servedBy };
}

async function callGeminiJSON(env, prompt, { model, hint = "gemini", temperature = 0 } = {}) {
  const GEMINI_API_KEY = env.GEMINI_API_KEY;
  if (!GEMINI_API_KEY) {
    throw new Error(`${hint} missing GEMINI_API_KEY`);
  }

  const modelId = (model || env.INDEX_MODEL || "gemini-2.5-flash").trim();
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelId}:generateContent?key=${GEMINI_API_KEY}`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: "application/json",
        temperature,
      },
      safetySettings: [
        { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
      ],
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`${hint} ${response.status} ${errText}`);
  }

  const result = await response.json();
  return result.candidates?.[0]?.content?.parts?.[0]?.text || "";
}

// --- Prompt scaffolding -----------------------------------------------------
const OR_SYSTEM_JUDGE = `
You are an objective rubric grader. Your entire response MUST be a single, valid JSON object that calls the 'extract_rubric_analysis' tool. Do not add any text outside the JSON.

MANDATORY RULES:
- Include EVERY level and EVERY characteristic from the provided rubric.
- Evidence MUST be a direct, verbatim quote from the user-provided transcript and be less than 160 characters.
- For EVERY check, you MUST provide a 'reason' and attempt to find 'evidence', even if 'met' is false.

- **CONTEXT IS PARAMOUNT:** Your assessment must be based on the overall conversational flow. Do not penalize rhetorical questions.

- **LIMITATION LOGIC:** For any check with 'polarity: "limitation"', you MUST follow this two-step process:
  1. First, ask internally: 'Was the seller's performance WORSE than the described limitation?'
  2. If the answer is YES, you MUST set 'met: false'. If the answer is NO (meaning performance was the same as OR better), you MUST set 'met: true'.
  3. **IMPORTANT:** If the seller's performance is EXACTLY EQUAL to the described limitation (not worse, not better), you MUST set 'met: true'. Do NOT penalize for being exactly at the limitation threshold. Your 'reason' must explicitly state which of these conditions was met.
  4. **EXCEPTION FOR ABSENCE:** If a Level 1 limitation describes a complete lack of a skill (e.g., "Demonstrates little to no understanding"), and you find no evidence of that skill in the entire transcript, you MUST set 'met: true' and your reason should state "The skill was not demonstrated at any point in the conversation."

- **DO NOT HALLUCINATE:** You are strictly forbidden from inventing evidence or using any text from this system prompt in your 'evidence' field. All evidence must originate from the user's transcript.
`;

const OR_SYSTEM_COACH = `
You are a practical, expert sales coach. Your task is to provide concise, actionable feedback based on a provided analysis. You MUST follow the JSON schema and rules below perfectly.

{
  "strengths": ["..."],
  "improvements": [{
    "point": "High-level area for improvement.",
    "example": {
      "instead_of": "The seller's actual quote demonstrating the gap.",
      "try_this": "A better, alternative phrase the seller could have used."
    }
  }],
  "coaching_tips": ["..."]
}

**CRITICAL RULES FOR YOUR TASK:**

1.  **Generate 'strengths':** Write 2-4 strengths from the highest-rated "met: true" positive characteristics. If none are met, this MUST be an empty array.

2.  **Generate 'improvements':** This is your most important task. Generate 3-5 improvements.
    - Base your improvements on the **unmet 'positive' characteristics** from the rubric, starting with the lowest levels first. These are the foundational skills.
    - For the 'example' object:
        - **'instead_of'**: Use the verbatim quote provided in the analysis. **If the quote seems generic or irrelevant**, explain the conversational context where the skill was missed. For example: "When the customer expressed concern about the product's fit, the seller changed the subject."
        - **'try_this'**: Write a short, practical, and superior alternative the seller could have used in that specific situation.

3.  **Generate 'coaching_tips':** Write 3-6 actionable tips directly related to the 'improvements'. Your tips must be grounded in the conversational context.
`;

// --- Utility: parsing OpenRouter responses ---------------------------------
function extractToolJSON(resp) {
  if (!resp) return null;
  const choice = resp.json?.choices?.[0];
  const toolCall = choice?.message?.tool_calls?.[0];
  if (toolCall?.function?.arguments) {
    try {
      return JSON.parse(toolCall.function.arguments);
    } catch (err) {
      console.log("[parse] failed tool call parse", err);
    }
  }
  const alt = choice?.message?.content ?? resp.content;
  if (typeof alt === "string" && alt.trim()) {
    try {
      return JSON.parse(alt);
    } catch (err) {
      console.log("[parse] failed content parse", err, alt.slice(0, 400));
    }
  }
  return null;
}

// --- Transcript driven helpers ---------------------------------------------
function normalizeRubric(rubricData) {
  if (!rubricData || !Array.isArray(rubricData.levels)) return rubricData;
  const copy = JSON.parse(JSON.stringify(rubricData));
  copy.levels.sort((a, b) => (a.level || 0) - (b.level || 0));
  for (const level of copy.levels) {
    if (Array.isArray(level.checks)) {
      level.checks.sort((a, b) => String(a.characteristic || "").localeCompare(String(b.characteristic || "")));
    }
  }
  return copy;
}

function computeRating(levelChecks) {
  if (!Array.isArray(levelChecks)) return 1;
  const ordered = [...levelChecks].sort((a, b) => (a.level || 0) - (b.level || 0));
  let highest = 1;
  for (const level of ordered) {
    const checks = Array.isArray(level.checks) ? level.checks : [];
    const positives = checks.filter((c) => (c.polarity || "positive") === "positive");
    const limitations = checks.filter((c) => c.polarity === "limitation");
    const negatives = checks.filter((c) => c.polarity === "negative");
    const positivesMet = positives.every((c) => c.met === true);
    const limitsMet = limitations.every((c) => c.met !== false);
    const noNegativeTriggered = negatives.every((c) => c.met !== true);
    if (positivesMet && limitsMet && noNegativeTriggered) {
      highest = Math.max(highest, level.level || 0);
    }
  }
  return highest;
}

function buildGatingSummary(levelChecks) {
  if (!Array.isArray(levelChecks)) return [];
  return levelChecks.map((level) => {
    const checks = Array.isArray(level.checks) ? level.checks : [];
    const positives = checks.filter((c) => (c.polarity || "positive") === "positive");
    const limitations = checks.filter((c) => c.polarity === "limitation");
    const negatives = checks.filter((c) => c.polarity === "negative");
    return {
      level: level.level || 0,
      name: level.name || "",
      positives_met: positives.filter((c) => c.met === true).map((c) => c.characteristic),
      positives_unmet: positives.filter((c) => c.met !== true).map((c) => c.characteristic),
      limitations_unmet: limitations.filter((c) => c.met === false).map((c) => c.characteristic),
      negatives_triggered: negatives.filter((c) => c.met === true).map((c) => c.characteristic),
    };
  });
}

function collectStrengthCandidates(levelChecks) {
  const out = [];
  for (const level of levelChecks || []) {
    for (const check of level.checks || []) {
      if ((check.polarity || "positive") === "positive" && check.met === true) {
        out.push({
          level: level.level || 0,
          characteristic: check.characteristic,
          evidence: Array.isArray(check.evidence) ? check.evidence : [],
        });
      }
    }
  }
  return out.sort((a, b) => (b.level || 0) - (a.level || 0));
}

function collectImprovementSeeds(levelChecks) {
  const out = [];
  for (const level of levelChecks || []) {
    for (const check of level.checks || []) {
      if ((check.polarity || "positive") === "positive" && check.met !== true) {
        out.push({
          level: level.level || 0,
          characteristic: check.characteristic,
          evidence: Array.isArray(check.evidence) ? check.evidence : [],
          reason: check.reason || "",
        });
      }
    }
  }
  return out.sort((a, b) => (a.level || 0) - (b.level || 0));
}

function pickQuote(quotes = []) {
  for (const q of quotes) {
    const trimmed = String(q || "").trim();
    if (trimmed) return trimmed;
  }
  return "";
}

function buildJudgePrompt(skillName, rubric, transcript, eligibility) {
  const rubricText = stable(normalizeRubric(rubric));
  const quotes = Array.isArray(eligibility?.quotes) ? eligibility.quotes : [];
  const reason = eligibility?.reason ? String(eligibility.reason).trim() : "";
  const confidence = eligibility?.confidence;
  const guidance = [];
  if (reason) {
    guidance.push(`Eligibility summary: ${reason}`);
  }
  if (Number.isFinite(confidence)) {
    guidance.push(`Eligibility confidence: ${(confidence * 100).toFixed(0)}%`);
  }
  if (quotes.length) {
    guidance.push(`Eligibility quotes:\n${quotes.map((q) => `- ${q}`).join("\n")}`);
  }
  const eligibilityText =
    guidance.length > 0
      ? `${guidance.join("\n")}\n\nVerify each quote directly against the transcript before making a decision.\n\n`
      : "";
  return `
You are grading the skill "${skillName}".

${eligibilityText}Use the transcript to evaluate EVERY rubric characteristic. Apply these guardrails:
- Quote directly from the transcript. If evidence is missing, leave the evidence array empty and set met: false.
- Treat each level independently. Do not assume higher levels are met because lower levels are met.
- Keep quotes under 160 characters and copy them verbatim.

Transcript:
---
${transcript}
---

Rubric:
${rubricText}
`;
}

function buildCoachPrompt(skillName, rating, strengths, improvements) {
  const payload = {
    skill: skillName,
    rating,
    strengths,
    improvement_opportunities: improvements,
  };
  return `
The analysis for "${skillName}" is complete. Final rating: ${rating}/5.
You MUST rely only on this structured analysis:
${stable(payload)}

Generate JSON via extract_coaching_feedback following the schema in the system prompt. Use the provided quotes exactly as written for 'instead_of'. If a gap has no quote, explain the moment succinctly in place of the quote.
`;
}

function buildEligibilityPrompt(skills, transcript) {
  return `
You review sales call transcripts. Decide which skills from the provided list have enough direct, objective evidence to score accurately.

Return JSON ONLY in this format:
[
  {
    "skill": "Skill name from the list",
    "can_assess": true,
    "confidence": 0.0,
    "reason": "One sentence summary",
    "quotes": ["verbatim quote" , ...]
  }
]

Rules:
- Only mark can_assess true if the transcript contains clear moments that demonstrate the skill.
- Provide 1-3 short verbatim quotes for each assessable skill.
- If a skill is barely mentioned or has no strong evidence, set can_assess false.
- Return an empty array if nothing is assessable.

Skills:
${JSON.stringify(skills, null, 2)}

Transcript:
---
${transcript}
---
`;
}

function sanitizeEligibilityEntry(entry, allowedSkills) {
  if (!entry) return null;
  const skill = String(entry.skill || "").trim();
  if (!skill || (allowedSkills && !allowedSkills.has(skill))) return null;
  const quotes = Array.isArray(entry.quotes)
    ? entry.quotes
        .map((q) => String(q || "").trim())
        .filter(Boolean)
        .slice(0, 5)
    : [];
  const confidence = Number(entry.confidence);
  const normalizedConfidence = Number.isFinite(confidence)
    ? Math.min(Math.max(confidence, 0), 1)
    : null;
  return {
    skill,
    can_assess: entry.can_assess === true,
    confidence: normalizedConfidence,
    reason: entry.reason ? String(entry.reason).trim() : "",
    quotes,
  };
}

async function runEligibilityCheck({ env, transcript, skills, hint = "eligibility" }) {
  const skillList = Array.from(
    new Set((skills || []).map((s) => String(s || "").trim()).filter(Boolean))
  );
  if (skillList.length === 0) return [];
  const allowed = new Set(skillList);
  const prompt = buildEligibilityPrompt(skillList, transcript);
  const rawText = await callGeminiJSON(env, prompt, { hint, temperature: 0 });
  if (!rawText || !rawText.trim()) return [];
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    throw new Error(`${hint} returned invalid JSON`);
  }
  if (!Array.isArray(parsed)) return [];
  const sanitized = parsed
    .map((entry) => sanitizeEligibilityEntry(entry, allowed))
    .filter(Boolean);
  return sanitized;
}

function transcriptTokenEstimate(text) {
  return Math.ceil(bytes(text) / 4);
}

// --- Rubric resolution ------------------------------------------------------
async function fetchJSON(url, options = {}) {
  const { hint = "upstream", timeoutMs = 120000 } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs);
  let response;
  let text = "";
  try {
    response = await fetch(url, { ...options, signal: controller.signal });
    text = await response.text();
  } catch (err) {
    clearTimeout(timer);
    throw new Error(`${hint} request failed: ${err?.message || err}`);
  }
  clearTimeout(timer);
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {}
  if (!response.ok) {
    const snippet = (text || "").slice(0, 400).replace(/\s+/g, " ");
    throw new Error(`${hint} ${response.status} ${response.statusText} – ${snippet || "no body"}`);
  }
  if (!data) {
    const snippet = (text || "").slice(0, 400).replace(/\s+/g, " ");
    throw new Error(`${hint} returned non-JSON – ${snippet || "empty body"}`);
  }
  return data;
}

async function resolveRubrics(env, body, url) {
  const headers = { "Content-Type": "application/json; charset=utf-8" };
  const MAX_RUBRICS_BYTES = num(env.MAX_RUBRICS_BYTES, 1_000_000);

  if (body?.rubrics && typeof body.rubrics === "object") {
    return { rubrics: body.rubrics, source: "inline" };
  }

  if (body?.rubrics_url) {
    const rubrics = await fetchJSON(body.rubrics_url, { hint: "rubrics_url" });
    return { rubrics, source: `url:${body.rubrics_url}` };
  }

  let setKey = body?.rubric_set || url.searchParams.get("rubric_set") || env.DEFAULT_RUBRIC_SET;
  if (setKey && env.RUBRICS) {
    let value = await env.RUBRICS.get(String(setKey), "text");
    if (value && /^rubrics:/.test(value.trim())) {
      const alias = await env.RUBRICS.get(value.trim(), "text");
      if (alias) value = alias;
    }
    if (!value) {
      throw new Error(`rubric_set not found in KV: ${setKey}`);
    }
    if (value.length > MAX_RUBRICS_BYTES) {
      throw new Error(`KV rubrics too large (> ${MAX_RUBRICS_BYTES} bytes)`);
    }
    try {
      const rubrics = JSON.parse(value);
      return { rubrics, source: `kv:${setKey}` };
    } catch {
      throw new Error(`Invalid JSON in KV rubric_set ${setKey}`);
    }
  }

  if (env.RUBRICS_FALLBACK_URL) {
    const rubrics = await fetchJSON(env.RUBRICS_FALLBACK_URL, { hint: "rubrics_fallback" });
    return { rubrics, source: `fallback:${env.RUBRICS_FALLBACK_URL}` };
  }

  throw new Error("No rubrics provided and no RUBRICS binding configured.");
}

function findRubricForSkill(rubrics, skillName, competencyFilter) {
  for (const [competency, payload] of Object.entries(rubrics || {})) {
    if (competencyFilter && competency !== competencyFilter) continue;
    const skill = payload?.skills?.[skillName];
    if (skill) return { competency, rubricData: skill };
  }
  return null;
}

// --- HTTP handlers ----------------------------------------------------------
export default {
  async fetch(request, env) {
    const allowOrigin = (env.ALLOW_ORIGIN && String(env.ALLOW_ORIGIN)) || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": allowOrigin,
          "Vary": "Origin",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/healthz")) {
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": allowOrigin,
          "Vary": "Origin",
        },
      });
    }

    if (url.pathname === "/env-test") {
      return new Response(JSON.stringify({
        hasOpenRouterKey: !!env.OPENROUTER_KEY,
        hasVoyageKey: !!env.VOYAGEAI_KEY,
        judgeModel: env.JUDGE_MODEL,
        writerModel: env.WRITER_MODEL,
        providerPrefs: providerPrefs(env),
      }, null, 2), {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": allowOrigin,
          "Vary": "Origin",
        },
      });
    }

    let handler;
    if (url.pathname === "/pre-assess") {
      handler = handlePreAssessment;
    } else if (url.pathname === "/check-cache-status") {
      handler = handleCacheCheck;
    } else {
      handler = handleFullAssessment;
    }

    let response = await handler(request, env, url);
    if (!(response instanceof Response)) {
      response = new Response(typeof response === "string" ? response : JSON.stringify(response), {
        headers: { "Content-Type": "application/json; charset=utf-8" },
      });
    }
    const headers = new Headers(response.headers);
    headers.set("Access-Control-Allow-Origin", allowOrigin);
    headers.set("Vary", "Origin");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
};

async function handlePreAssessment(request, env) {
  const headers = { "Content-Type": "application/json; charset=utf-8" };
  try {
    const body = await request.json().catch(() => ({}));
    const { transcript, allSkills } = body || {};
    if (!transcript || !Array.isArray(allSkills) || allSkills.length === 0) {
      return new Response(JSON.stringify({ error: "Missing 'transcript' or 'allSkills' in request body." }), {
        status: 400,
        headers,
      });
    }
    const CACHE_VERSION = String(env.CACHE_VERSION || "1");
    const KV_TTL_SECS = num(env.KV_TTL_SECS, 60 * 60 * 24 * 7);
    const normalizedTranscript = normalizeTranscript(transcript);
    const skillsList = allSkills.map((s) => String(s || "").trim()).filter(Boolean);
    if (skillsList.length === 0) {
      return new Response(JSON.stringify({ error: "No valid skills provided." }), { status: 400, headers });
    }

    const cacheKeyHash = await sha256Hex(
      stable({ v: CACHE_VERSION, transcript: normalizedTranscript, skills: skillsList })
    );
    const kvKey = `v${CACHE_VERSION}:pre-assess:${cacheKeyHash}`;

    if (env.ASSESS_CACHE) {
      const cached = await kvGetJSON(env.ASSESS_CACHE, kvKey);
      if (cached) {
        return new Response(JSON.stringify(cached), { headers });
      }
    }
    const eligibility = await runEligibilityCheck({
      env,
      transcript: normalizedTranscript,
      skills: skillsList,
      hint: "pre-assessment",
    });

    const eligible = eligibility.filter(
      (entry) => entry.can_assess === true && Array.isArray(entry.quotes) && entry.quotes.length > 0
    );
    const responsePayload = {
      skills: eligible.map((entry) => entry.skill).filter(Boolean),
      details: eligible,
    };

    if (env.ASSESS_CACHE) {
      await kvPutJSON(env.ASSESS_CACHE, kvKey, responsePayload, KV_TTL_SECS, CACHE_VERSION);
    }

    return new Response(JSON.stringify(responsePayload), { headers });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
  }
}

async function handleCacheCheck(request, env) {
  const headers = { "Content-Type": "application/json; charset=utf-8" };
  try {
    const body = await request.json().catch(() => ({}));
    const { transcript, sellerId, skills } = body || {};
    if (!transcript || !sellerId || !Array.isArray(skills) || skills.length === 0) {
      return new Response(JSON.stringify({ error: "Missing required fields for cache check." }), { status: 400, headers });
    }

    const CACHE_VERSION = String(env.CACHE_VERSION || "1");
    const normalizedTranscript = normalizeTranscript(transcript);

    const status = {};
    await Promise.all(
      skills.map(async (skillName) => {
        const hash = await simpleSkillKeyHash({
          cacheVersion: CACHE_VERSION,
          transcript: normalizedTranscript,
          sellerId,
          skillName,
        });
        const key = `v${CACHE_VERSION}:assess_skill:${hash}`;
        const cached = env.ASSESS_CACHE ? await kvGetJSON(env.ASSESS_CACHE, key) : null;
        status[skillName] = !!(cached && cached.assessment && !cached.assessment.__error);
      })
    );

    return new Response(JSON.stringify(status), { headers });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
  }
}

async function handleFullAssessment(request, env, url) {
  const headers = { "Content-Type": "application/json; charset=utf-8" };
  const requireAuth = bool(env.REQUIRE_AUTH, false);
  const token = env.SERVICE_TOKEN || "";

  if (requireAuth) {
    const authHeader = request.headers.get("Authorization") || "";
    const provided = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    if (!provided || provided !== token) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });
    }
  }

  let bodyText = "";
  try {
    bodyText = await request.text();
  } catch {
    bodyText = "";
  }
  let body = {};
  try {
    body = bodyText ? JSON.parse(bodyText) : {};
  } catch {
    body = {};
  }

  console.log("[WORKER] /assess incoming", {
    method: request.method,
    url: url.toString(),
    payload: {
      sellerId: body.sellerId,
      skills: body.skills,
      transcriptLen: typeof body.transcript === "string" ? body.transcript.length : 0,
    },
  });

  const GEMINI_KEY = env.GEMINI_API_KEY;
  if (!GEMINI_KEY) {
    return new Response(JSON.stringify({ error: "API key not configured in Cloudflare secrets." }), { status: 500, headers });
  }

  const CACHE_VERSION = String(env.CACHE_VERSION || "1");
  const KV_TTL_SECS = num(env.KV_TTL_SECS, 60 * 60 * 24 * 14);
  const MAX_SKILLS_CAP = num(env.MAX_SKILLS_CAP, 50);
  const MAX_CONCURRENCY = num(env.MAX_CONCURRENCY, 3);

  const {
    transcript,
    skills: requestedSkills,
    sellerId,
  } = body || {};

  if (!transcript || !Array.isArray(requestedSkills) || requestedSkills.length === 0) {
    return new Response(JSON.stringify({ error: "Missing 'transcript' or 'skills'." }), { status: 400, headers });
  }

  if (requestedSkills.length > MAX_SKILLS_CAP) {
    return new Response(JSON.stringify({ error: `Too many skills requested (max ${MAX_SKILLS_CAP}).` }), { status: 400, headers });
  }

  let rubricsInfo;
  try {
    rubricsInfo = await resolveRubrics(env, body, url);
  } catch (error) {
    console.error("resolveRubrics error", error);
    return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
  }

  const competencyFilter = url.searchParams.get("competency") || body?.competency;
  const normalizedTranscript = normalizeTranscript(transcript);
  const missingSkills = [];
  const resolvedSkills = [];
  for (const skillName of requestedSkills) {
    const match = findRubricForSkill(rubricsInfo.rubrics, skillName, competencyFilter);
    if (!match) {
      missingSkills.push(skillName);
      continue;
    }
    resolvedSkills.push({
      skillName,
      rubricData: match.rubricData,
      competency: match.competency,
    });
  }

  if (resolvedSkills.length === 0) {
    return new Response(JSON.stringify({ error: "None of the requested skills exist in the rubric set.", missingSkills }), {
      status: 400,
      headers,
    });
  }

  const sellerIdentity = body?.seller_label || "Seller";
  const results = new Map();
  const timing = [];
  const skipEligibility =
    bool(body?.skip_precheck, false) || bool(url.searchParams.get("skip_precheck"), false);
  const requestedSkillSet = new Set(resolvedSkills.map((item) => item.skillName));

  const eligibilityMap = new Map();
  function mergeEligibilityPayload(payload) {
    if (!payload) return;
    const buckets = [];
    if (Array.isArray(payload)) buckets.push(payload);
    if (Array.isArray(payload.details)) buckets.push(payload.details);
    if (Array.isArray(payload.eligibility)) buckets.push(payload.eligibility);
    for (const bucket of buckets) {
      for (const raw of bucket) {
        const sanitized = sanitizeEligibilityEntry(raw, requestedSkillSet);
        if (sanitized) {
          eligibilityMap.set(sanitized.skill, sanitized);
        }
      }
    }
  }

  mergeEligibilityPayload(body?.eligibility);
  mergeEligibilityPayload(body?.eligibility_details);
  mergeEligibilityPayload(body?.pre_assessment);
  mergeEligibilityPayload(body?.preAssessment);

  if (!skipEligibility) {
    const skillsNeedingCheck = resolvedSkills
      .map((item) => item.skillName)
      .filter((skill) => !eligibilityMap.has(skill));
    if (skillsNeedingCheck.length > 0) {
      const fresh = await runEligibilityCheck({
        env,
        transcript: normalizedTranscript,
        skills: skillsNeedingCheck,
        hint: "assessment-precheck",
      });
      for (const entry of fresh) {
        eligibilityMap.set(entry.skill, entry);
      }
    }
  }

  const assessableSkills = skipEligibility
    ? [...resolvedSkills]
    : resolvedSkills.filter((item) => {
        const detail = eligibilityMap.get(item.skillName);
        return detail?.can_assess === true && Array.isArray(detail.quotes) && detail.quotes.length > 0;
      });

  const assessableSet = new Set(assessableSkills.map((item) => item.skillName));
  const blockedSkills = skipEligibility
    ? []
    : resolvedSkills
        .filter((item) => !assessableSet.has(item.skillName))
        .map((item) => {
          const detail = eligibilityMap.get(item.skillName);
          return {
            skill: item.skillName,
            reason: detail?.reason || "No qualifying evidence returned from eligibility check.",
            quotes: detail?.quotes || [],
          };
        });

  if (!skipEligibility && assessableSkills.length === 0) {
    return new Response(
      JSON.stringify({
        error: "No assessable skills with supporting evidence in transcript.",
        blocked_skills: blockedSkills,
      }),
      { status: 422, headers }
    );
  }

  const queue = assessableSkills.map((item) => ({
    ...item,
    eligibility: eligibilityMap.get(item.skillName) || null,
  }));

  async function processNext() {
    if (queue.length === 0) return;
    const item = queue.shift();
    if (!item) return;
    const start = Date.now();
    try {
      const assessment = await assessSkill({
        env,
        transcript: normalizedTranscript,
        rawTranscript: transcript,
        sellerId,
        skillName: item.skillName,
        rubricData: item.rubricData,
        cacheVersion: CACHE_VERSION,
        kv: env.ASSESS_CACHE,
        kvTtl: KV_TTL_SECS,
        eligibility: item.eligibility,
      });
      results.set(item.skillName, assessment);
    } catch (error) {
      console.error(`[assess:${item.skillName}] error`, error);
      results.set(item.skillName, {
        skill: item.skillName,
        __error: String(error?.message || error),
      });
    } finally {
      timing.push({ skill: item.skillName, ms: Date.now() - start });
    }
  }

  const workers = [];
  for (let i = 0; i < Math.min(MAX_CONCURRENCY, queue.length); i += 1) {
    workers.push((async () => {
      while (queue.length) {
        await processNext();
      }
    })());
  }
  await Promise.all(workers);

  const orderedAssessments = assessableSkills
    .map((entry) => results.get(entry.skillName))
    .filter(Boolean);
  const eligibilityDetails = Array.from(eligibilityMap.values()).sort((a, b) =>
    a.skill.localeCompare(b.skill)
  );
  const blockedSkillsSorted = blockedSkills.slice().sort((a, b) => a.skill.localeCompare(b.skill));

  const meta = {
    run_id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    duration_ms: timing.reduce((sum, t) => sum + t.ms, 0),
    judge_model: env.JUDGE_MODEL || "meta-llama/llama-3.1-70b-instruct",
    writer_model: env.WRITER_MODEL || "openai/gpt-4o-mini",
    provider_order: providerPrefs(env).order,
    rubric_source: rubricsInfo.source,
    assessed_skills: orderedAssessments.map((a) => a.skill),
    requested_skills: resolvedSkills.map((entry) => entry.skillName),
    blocked_skills: blockedSkillsSorted,
    missing_skills,
    token_estimate: transcriptTokenEstimate(transcript),
    timing,
    eligibility: {
      skipped: skipEligibility,
      details: eligibilityDetails,
    },
  };

  return new Response(JSON.stringify({
    assessments: orderedAssessments,
    meta,
    seller_identity: sellerIdentity,
  }), { headers });
}

async function assessSkill({
  env,
  transcript,
  rawTranscript,
  sellerId,
  skillName,
  rubricData,
  cacheVersion,
  kv,
  kvTtl,
  eligibility,
}) {
  const CACHE_VERSION = cacheVersion;
  const normalizedTranscript = transcript;
  const sellerKey = sellerId || "";

  const skillKeyHash = await simpleSkillKeyHash({
    cacheVersion: CACHE_VERSION,
    transcript: normalizedTranscript,
    sellerId: sellerKey,
    skillName,
  });
  const kvKey = `v${CACHE_VERSION}:assess_skill:${skillKeyHash}`;

  if (kv) {
    const cached = await kvGetJSON(kv, kvKey);
    if (cached?.assessment && !cached.assessment.__error) {
      return { ...cached.assessment, _cached: true };
    }
  }

  const judgePrompt = buildJudgePrompt(skillName, rubricData, rawTranscript, eligibility);
  const judgeResp = await withRetry(
    () =>
      chatOpenRouter(env, {
        model: env.JUDGE_MODEL || "meta-llama/llama-3.1-70b-instruct",
        temperature: 0,
        max_tokens: 6000,
        tools: [
          {
            type: "function",
            function: {
              name: "extract_rubric_analysis",
              description: "Extract the rubric analysis based on the transcript.",
              parameters: {
                type: "object",
                properties: {
                  level_checks: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        level: { type: "integer" },
                        name: { type: "string" },
                        checks: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              characteristic: { type: "string" },
                              polarity: { enum: ["positive", "negative", "limitation"] },
                              met: { type: "boolean" },
                              evidence: { type: "array", items: { type: "string" } },
                              reason: { type: "string" },
                            },
                            required: ["characteristic", "polarity", "met", "evidence", "reason"],
                          },
                        },
                      },
                      required: ["level", "name", "checks"],
                    },
                  },
                },
                required: ["level_checks"],
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "extract_rubric_analysis" } },
        messages: [
          { role: "system", content: OR_SYSTEM_JUDGE },
          { role: "user", content: judgePrompt },
        ],
        provider: providerPrefs(env),
      }, { hint: "judge" }),
    { retries: num(env.ASSESS_RETRY_MAX, 1), baseMs: num(env.ASSESS_RETRY_BASE_MS, 700) }
  );

  const judgeJSON = extractToolJSON(judgeResp);
  if (!judgeJSON?.level_checks) {
    const error = new Error("Judge returned no level_checks");
    const payload = {
      skill: skillName,
      __error: error.message,
      _raw_judge: judgeResp?.raw?.slice?.(0, 800) || null,
    };
    if (kv) await kvPutJSON(kv, kvKey, { assessment: payload }, kvTtl, CACHE_VERSION);
    return payload;
  }

  const levelChecks = judgeJSON.level_checks;
  const rating = computeRating(levelChecks);
  const gatingSummary = buildGatingSummary(levelChecks);
  const strengthCandidates = collectStrengthCandidates(levelChecks).slice(0, 6);
  const improvementSeeds = collectImprovementSeeds(levelChecks).slice(0, 8);

  const strengthsSnapshot = strengthCandidates.map((item) => ({
    level: item.level,
    characteristic: item.characteristic,
    quote: pickQuote(item.evidence),
  }));

  const improvementSnapshot = improvementSeeds.map((item) => ({
    level: item.level,
    characteristic: item.characteristic,
    quote: pickQuote(item.evidence),
    reason: item.reason,
  }));

  const coachPrompt = buildCoachPrompt(skillName, rating, strengthsSnapshot, improvementSnapshot);

  const coachResp = await withRetry(
    () =>
      chatOpenRouter(env, {
        model: env.WRITER_MODEL || "openai/gpt-4o-mini",
        temperature: 0.2,
        max_tokens: 4000,
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "coaching_feedback_schema",
            schema: {
              type: "object",
              additionalProperties: false,
              properties: {
                strengths: { type: "array", items: { type: "string" } },
                improvements: {
                  type: "array",
                  items: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                      point: { type: "string" },
                      example: {
                        type: "object",
                        additionalProperties: false,
                        properties: {
                          instead_of: { type: "string" },
                          try_this: { type: "string" },
                        },
                        required: ["instead_of", "try_this"],
                      },
                    },
                    required: ["point", "example"],
                  },
                },
                coaching_tips: { type: "array", items: { type: "string" } },
              },
              required: ["strengths", "improvements", "coaching_tips"],
            },
          },
        },
        messages: [
          { role: "system", content: OR_SYSTEM_COACH },
          { role: "user", content: coachPrompt },
        ],
        provider: providerPrefs(env),
      }, { hint: "coach" }),
    { retries: 1, baseMs: 600 }
  );

  let coachJSON = null;
  try {
    if (coachResp?.json?.choices?.[0]?.message?.content) {
      coachJSON = JSON.parse(coachResp.json.choices[0].message.content);
    } else if (typeof coachResp?.content === "string" && coachResp.content.trim()) {
      coachJSON = JSON.parse(coachResp.content);
    }
  } catch (err) {
    console.log(`[coach:${skillName}] parse error`, err);
  }

  const strengths = Array.isArray(coachJSON?.strengths) ? coachJSON.strengths : [];
  const improvements = Array.isArray(coachJSON?.improvements) ? coachJSON.improvements : [];
  const coaching_tips = Array.isArray(coachJSON?.coaching_tips) ? coachJSON.coaching_tips : [];

  const assessment = {
    skill: skillName,
    rating,
    strengths,
    improvements,
    coaching_tips,
    level_checks: levelChecks,
    gating_summary: gatingSummary,
    _served_by: {
      judge: judgeResp?.servedBy || null,
      coach: coachResp?.servedBy || null,
    },
    _prompts: {
      judge_chars: judgePrompt.length,
      coach_chars: coachPrompt.length,
    },
  };

  if (kv) {
    await kvPutJSON(kv, kvKey, { assessment }, kvTtl, CACHE_VERSION);
  }

  return assessment;
}
