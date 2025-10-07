// --- SHARED HELPER FUNCTIONS ---
const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
const bool = (v, d) => { if (v === undefined || v === null) return d; const s = String(v).toLowerCase().trim(); return s === "true" || s === "1" || s === "yes"; };
const bytes = (s) => new TextEncoder().encode(String(s)).length;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function withRetry(fn, { retries = 2, baseMs = 500, factor = 1.8, jitter = true } = {}) {
  let attempt = 0, delay = baseMs, lastErr;
  while (attempt <= retries) {
    try { return await fn(); }
    catch (e) {
      lastErr = e;
      const msg = String(e?.message || e);
      if (!/timeout|timed out|429|5\d\d|unavailable|quota|exhausted/i.test(msg) || attempt === retries) break;
      const wait = jitter ? Math.round(delay * (0.7 + Math.random() * 0.6)) : delay;
      await sleep(wait);
      delay = Math.min(delay * factor, 8000);
      attempt++;
    }
  }
  throw lastErr;
}
async function fetchJSON(url, options = {}) {
  const { hint = "upstream", timeoutMs = 120000 } = options;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs);
  let res, text;
  try {
    res = await fetch(url, { ...options, signal: ac.signal });
    text = await res.text();
  } catch (e) {
    clearTimeout(timer);
    throw new Error(`${hint} request failed: ${e?.message || e}`);
  }
  clearTimeout(timer);
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) {
    const snippet = (text || "").slice(0, 400).replace(/\s+/g, " ");
    throw new Error(`${hint} ${res.status} ${res.statusText} – ${snippet || "no body"}`);
  }
  if (!data) {
    const snippet = (text || "").slice(0, 400).replace(/\s+/g, " ");
    throw new Error(`${hint} returned non-JSON – ${snippet || "empty body"}`);
  }
  return data;
}
function stable(obj) {
  const seen = new WeakSet();
  const sorter = (x) => {
    if (x && typeof x === "object") {
      if (seen.has(x)) return null;
      seen.add(x);
      if (Array.isArray(x)) return x.map(sorter);
      return Object.keys(x).sort().reduce((o, k) => ((o[k] = sorter(x[k])), o), {});
    }
    return x;
  };
  return JSON.stringify(sorter(obj));
}
async function sha256Hex(s) {
  const data = new TextEncoder().encode(s);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function kvGetJSON(ns, key) {
  if (!ns) return null;
  const s = await ns.get(key);
  if (!s) return null;
  try { return JSON.parse(s); } catch { return null; }
}
async function kvPutJSON(ns, key, obj, ttlSecs, cacheVersion) {
  if (!ns) return;
  await ns.put(key, JSON.stringify(obj), {
    expirationTtl: ttlSecs,
    metadata: { createdAt: Date.now(), version: cacheVersion },
  });
}

// --- Provider preferences (Groq-first with fallback) ------------------------
function providerPrefs(env) {
  const order = (env.PROVIDER_ORDER || "fireworks,together,groq,google,openai")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);
  const allow_fallbacks = String(env.ALLOW_FALLBACKS || "1") === "1";
  return { order, allow_fallbacks };
}

// --- OpenRouter client that returns provider + raw (with timeout + key guard) ---
async function chatOpenRouter(env, payload, { hint = "openrouter" } = {}) {
  if (!env.OPENROUTER_KEY) throw new Error(`${hint} missing OPENROUTER_KEY`);
  const base = (env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1").replace(/\/+$/,"");
  const timeoutMs = num(env.OPENROUTER_TIMEOUT_MS, 120000);

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs);

  let res, raw;
  try {
    res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.OPENROUTER_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://yourapp.example",
        "X-Title": "Sales Skills Worker"
      },
      body: JSON.stringify(payload),
      signal: ac.signal
    });
    raw = await res.text();
  } catch (e) {
    clearTimeout(t);
    throw new Error(`${hint} request failed: ${e?.message || e}`);
  }
  clearTimeout(t);

  if (!res.ok) throw new Error(`${hint} ${res.status}: ${raw.slice(0,400)}`);
  let json;
  try { json = JSON.parse(raw); } catch {
    throw new Error(`${hint} returned non-JSON: ${raw.slice(0,200)}`);
  }
  const servedBy = res.headers.get("openrouter-proxy-provider")
                || res.headers.get("x-openrouter-provider")
                || json?.provider?.name
                || json?.model
                || "unknown";
  const content = json?.choices?.[0]?.message?.content ?? "";
  return { content, servedBy, raw, json };
}

// --- OpenRouter system prompts ---------------------------------------------
const OR_SYSTEM_JUDGE = `
You are a strict, objective rubric grader. Your entire response MUST be a single, valid JSON object that calls the 'extract_rubric_analysis' tool. Do not add any text outside the JSON.

MANDATORY RULES:
- Include EVERY level and EVERY characteristic from the provided rubric.
- Evidence MUST be a direct, verbatim quote from the user-provided transcript and be less than 160 characters.
- For EVERY check, you MUST provide a 'reason' and attempt to find 'evidence', even if 'met' is false.

- **CONTEXT IS PARAMOUNT:** Your assessment must be based on the overall conversational flow. Do not penalize rhetorical questions.

- **LIMITATION LOGIC:** For any check with 'polarity: "limitation"', you MUST follow this two-step process:
  1. First, ask internally: 'Was the seller's performance WORSE than the described limitation?'
  2. If the answer is YES, you MUST set 'met: false'. If the answer is NO (meaning performance was the same as OR better), you MUST set 'met: true'.
  3. **IMPORTANT:** If the seller's performance is EXACTLY EQUAL to the described limitation (not worse, not better), you MUST set 'met: true'. Do NOT penalize for being exactly at the limitation threshold. Your 'reason' must explicitly state which of these conditions was met.

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

1.  **Generate 'strengths':** Write 2-4 strengths from the highest-rated "met: true" positive characteristics.

2.  **Generate 'improvements':** This is the most important step. You MUST generate 3-5 items in this array. Every item in the 'improvements' array MUST be an object with two keys: "point" and "example".
    - For the "point", describe the high-level skill to improve based on an unmet 'positive' characteristic.
    - For the "example", you must generate a nested object with two keys: "instead_of" and "try_this".
        - **'instead_of'**: Find a real, verbatim quote from the seller that demonstrates the gap or missed opportunity. If no quote is a good fit, use an empty string.
        - **'try_this'**: Write a short, practical, and superior alternative phrase the seller could have used in that situation.

3.  **Generate 'coaching_tips':** Write 3-6 actionable tips that directly relate to the 'improvements'.
`;

// --- SHARED WHITELIST HELPERS ---
const BUCKET_ORDER = [
  "ask_probe","clarify_validate","summarize_synthesize","empathize_label",
  "quantify_measure","connect_link","document_commit","explain_teach",
  "position_value","other"
];

function makeNormalizeQuote(maxQuoteWords = 50, enforce = true) {
  return function normalizeQuote(q) {
    const t = String(q || "").replace(/\s+/g, " ").trim();
    if (!t) return "";
    if (!enforce) return t;
    const words = t.split(" ");
    return words.length <= maxQuoteWords ? t : words.slice(0, maxQuoteWords).join(" ");
  };
}
function getQuotePosMap(transcript, quotes, normalizeQuote) {
  const lower = String(transcript || "").toLowerCase();
  const m = new Map();
  for (const q of (quotes || [])) {
    const t = normalizeQuote(q);
    if (!t) continue;
    const pos = lower.indexOf(t.toLowerCase());
    m.set(t, pos >= 0 ? pos : Number.MAX_SAFE_INTEGER);
  }
  return m;
}
function selectWhitelistForSkill(index, skillName, maxN, transcript, opts = {}) {
  const normalizeQuote = makeNormalizeQuote(
    opts.maxQuoteWords ?? 50,
    opts.enforce ?? true
  );
  const all = (index?.seller_quotes || []).map(normalizeQuote).filter(Boolean);
  if (!all.length) return [];

  const posMap = getQuotePosMap(transcript, all, normalizeQuote);
  const eb = index?.evidence_buckets || {};
  const picked = [];
  const seen = new Set();

  for (const b of BUCKET_ORDER) {
    const inBucket = (eb[b] || [])
      .map(normalizeQuote)
      .filter(q => q && all.includes(q))
      .sort((a, bq) => (posMap.get(a) || 1e15) - (posMap.get(bq) || 1e15));
    for (const q of inBucket) {
      if (!seen.has(q)) {
        picked.push(q);
        seen.add(q);
        if (picked.length >= maxN) return picked;
      }
    }
  }

  const remaining = all
    .filter(q => !seen.has(q))
    .sort((a, bq) => (posMap.get(a) || 1e15) - (posMap.get(bq) || 1e15));
  for (const q of remaining) {
    picked.push(q);
    if (picked.length >= maxN) break;
  }
  return picked;
}

// Keep a single definition used across the file
function sortQuotesDeterministic(arr) {
  const uniq = [...new Set((arr || []).map(String).map(s => s.trim()).filter(Boolean))];
  return uniq.sort((a, b) => {
    const lc = a.toLowerCase().localeCompare(b.toLowerCase());
    return lc !== 0 ? lc : (a.length - b.length);
  });
}

// --- TOP-LEVEL ROUTER ---
export default {
  async fetch(request, env, ctx) {
    const allowOrigin = (env.ALLOW_ORIGIN && String(env.ALLOW_ORIGIN)) || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": allowOrigin,
          "Vary": "Origin",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400"
        },
      });
    }

    const url = new URL(request.url);

    // tiny healthcheck (no secrets)
    if (request.method === "GET" && (url.pathname === "/healthz" || url.pathname === "/")) {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": allowOrigin, "Vary": "Origin" }
      });
    }

    // --- Quick debug route ----------------------------------
    if (url.pathname === "/env-test") {
      return new Response(JSON.stringify({
        hasOpenRouterKey: !!env.OPENROUTER_KEY,
        hasVoyageKey: !!env.VOYAGEAI_KEY,
        judgeModel: env.JUDGE_MODEL,
        writerModel: env.WRITER_MODEL,
        providerPrefs: providerPrefs(env)
      }, null, 2), {
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": allowOrigin, "Vary": "Origin" }
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

    const response = await handler(request, env);

    const newHeaders = new Headers(response.headers);
    newHeaders.set("Access-Control-Allow-Origin", allowOrigin);
    newHeaders.set("Vary", "Origin");
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  },
};

// --- PRE-ASSESSMENT HANDLER ---
async function handlePreAssessment(request, env) {
  try {
    // be forgiving if content-type is missing
    const body = await request.json().catch(() => ({}));
    const { transcript, allSkills } = body;
    const GEMINI_API_KEY = env.GEMINI_API_KEY;
    const INDEX_MODEL = (env.INDEX_MODEL || "gemini-2.5-flash").trim();
    const CACHE_VERSION   = String(env.CACHE_VERSION || "1");
    const KV_TTL_SECS     = num(env.KV_TTL_SECS,   60 * 60 * 24 * 7);

    if (!transcript || !Array.isArray(allSkills) || allSkills.length === 0) {
      return new Response(JSON.stringify({ error: "Missing 'transcript' or 'allSkills' in request body." }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
    }

    const cacheKeyInput = stable({ v: CACHE_VERSION, transcript, allSkills });
    const cacheKeyHash = await sha256Hex(cacheKeyInput);
    const kvKey = `v${CACHE_VERSION}:pre-assess:${cacheKeyHash}`;

    if (env.ASSESS_CACHE) {
      const cached = await kvGetJSON(env.ASSESS_CACHE, kvKey);
      if (cached) {
        return new Response(JSON.stringify(cached), { headers: { "Content-Type": "application/json; charset=utf-8" } });
      }
    }

    function buildPreAssessmentPrompt(transcript, skillsList) {
      return `
          You are an efficient AI analyst. Your task is to review a sales call transcript and determine which predefined skills are demonstrably present in the seller's dialogue.

          Analyze the following transcript. Based on the conversation, identify which of the skills from the provided list are clearly and substantially discussed or demonstrated by the speakers.

          **CRITICAL RULES:**
          - Only return skills that have significant evidence in the text. Do not include skills that are only briefly mentioned or tangentially related.
          - Your response MUST be a valid JSON array of strings, containing only the names of the relevant skills from the list.
          - If no skills are clearly present, return an empty array [].

          **Full List of Possible Skills:**
          ${JSON.stringify(skillsList, null, 2)}

          **Transcript:**
          ---
          ${transcript}
          ---

          Return ONLY the JSON array.
          `;
    }

    const prompt = buildPreAssessmentPrompt(transcript, allSkills);
    const googleURL = (model) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
    const requestBody = {
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        responseMimeType: "application/json",
        temperature: 0.0,
      },
      safetySettings: [
        { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
        { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
      ],
    };

    const response = await fetch(googleURL(INDEX_MODEL), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Gemini API Error: ${response.status} ${errorText}`);
    }

    const result = await response.json();
    const relevantSkillsText = result.candidates?.[0]?.content?.parts?.[0]?.text;
    
    let responsePayload = { skills: [] };
    if (relevantSkillsText) {
      try {
        responsePayload.skills = JSON.parse(relevantSkillsText);
      } catch (e) {
        throw new Error("Pre-assessment AI returned invalid JSON.");
      }
    }

    if (env.ASSESS_CACHE) {
      await kvPutJSON(env.ASSESS_CACHE, kvKey, responsePayload, KV_TTL_SECS, CACHE_VERSION);
    }
    
    return new Response(JSON.stringify(responsePayload), { headers: { "Content-Type": "application/json; charset=utf-8" } });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { "Content-Type": "application/json; charset=utf-8" } });
  }
}

// --- CACHE CHECK HANDLER ---
async function handleCacheCheck(request, env) {
  const headers = { "Content-Type": "application/json; charset=utf-8" };
  try {
    const body = await request.json().catch(() => ({}));
    const { transcript, sellerId, skills, rubrics } = body;

    const CACHE_VERSION = String(env.CACHE_VERSION || "1");
    const INDEX_MODEL   = (env.INDEX_MODEL   || "gemini-2.5-pro").trim();
    const ASSESS_MODEL  = (env.ASSESS_MODEL  || "gemini-2.5-pro").trim();

    const WHITELIST_MAX = num(env.WHITELIST_MAX, 24);
    const MAX_QUOTE_WORDS = num(env.MAX_QUOTE_WORDS, 50);
    const ENFORCE_MAX_WORDS_IN_EVIDENCE = bool(env.ENFORCE_MAX_WORDS_IN_EVIDENCE, true);

    if (!transcript || !sellerId || !Array.isArray(skills) || !rubrics) {
      return new Response(JSON.stringify({ error: "Missing required fields for cache check." }), { status: 400, headers });
    }

    const normalizeTranscript = (s) => {
      if (!s) return "";
      let t = String(s);
      t = t.replace(/\t/g, " ")
           .replace(/[ \u00A0]{2,}/g, " ")
           .replace(/\n{3,}/g, "\n\n")
           .trim();
      return t;
    };

    const normTranscript = normalizeTranscript(transcript);

    const indexKeyInput = stable({
      v: CACHE_VERSION,
      INDEX_MODEL,
      MAX_SELLER_QUOTES: num(env.MAX_SELLER_QUOTES, 40),
      MAX_CUSTOMER_CUES: num(env.MAX_CUSTOMER_CUES, 20),
      MAX_QUOTE_WORDS:   MAX_QUOTE_WORDS,
      INDEX_SEGMENT_CHARS:   num(env.INDEX_SEGMENT_CHARS, 3000),
      INDEX_SEGMENT_MAX:     num(env.INDEX_SEGMENT_MAX, 10),
      INDEX_SPLIT_MAX_DEPTH: num(env.INDEX_SPLIT_MAX_DEPTH, 3),
      transcript: normTranscript,
      sellerId
    });
    const indexKeyHash = await sha256Hex(indexKeyInput);
    const indexKVKey   = `v${CACHE_VERSION}:index:${indexKeyHash}`;

    const cachedIndex = env.ASSESS_CACHE ? await kvGetJSON(env.ASSESS_CACHE, indexKVKey) : null;

    const findRubricForSkill = (allRubrics, skillName) => {
      for (const competency in allRubrics) {
        if (allRubrics[competency]?.skills?.[skillName]) {
          return allRubrics[competency].skills[skillName];
        }
      }
      return null;
    };

    async function buildAssessSkillKeyHash({ cacheVersion, assessModel, minQuotesPerPositivePass, requireDistinctEvidence, maxEvidenceReuse, enforceMaxWords, bucketsInPrompt, bucketSampleN, skillName, rubricData, whitelist, indexKeyHash }) {
      const input = {
        v: String(cacheVersion || "1"),
        assessModel: String(assessModel || ""),
        limits: {
          minQuotesPerPositivePass: Number(minQuotesPerPositivePass || 0),
          requireDistinctEvidence:  !!requireDistinctEvidence,
          maxEvidenceReuse:         Number(maxEvidenceReuse || 0),
          enforceMaxWords:          !!enforceMaxWords,
          bucketsInPrompt:          String(bucketsInPrompt || "none"),
          bucketSampleN:            Number(bucketSampleN || 0)
        },
        skillName: String(skillName || ""),
        rubric: rubricData || {},
        whitelist: (whitelist || []).map(String),
        indexKeyHash: String(indexKeyHash || "")
      };
      const stableStr = stable(input);
      return await sha256Hex(stableStr);
    }

    const cachedStatus = {};
    await Promise.all(
      skills.map(async (skillName) => {
        const rubricData = findRubricForSkill(rubrics, skillName);
        if (!rubricData) { cachedStatus[skillName] = false; return; }

        const wl = cachedIndex
          ? selectWhitelistForSkill(
              cachedIndex,
              skillName,
              WHITELIST_MAX,
              normTranscript,
              { maxQuoteWords: MAX_QUOTE_WORDS, enforce: ENFORCE_MAX_WORDS_IN_EVIDENCE }
            )
          : [];

        const skillKeyHash = await buildAssessSkillKeyHash({
          cacheVersion: CACHE_VERSION,
          assessModel:  ASSESS_MODEL,
          minQuotesPerPositivePass: num(env.MIN_QUOTES_PER_POSITIVE_PASS, 1),
          requireDistinctEvidence:  bool(env.REQUIRE_DISTINCT_EVIDENCE, false),
          maxEvidenceReuse:         num(env.MAX_EVIDENCE_REUSE, 5),
          enforceMaxWords:          ENFORCE_MAX_WORDS_IN_EVIDENCE,
          bucketsInPrompt:          String(env.BUCKETS_IN_PROMPT || "none").toLowerCase(),
          bucketSampleN:            num(env.BUCKET_SAMPLE_N, 3),
          skillName, rubricData, whitelist: wl,
          indexKeyHash
        });

        const kvKey = `v${CACHE_VERSION}:assess_skill:${skillKeyHash}`;
        const cached = env.ASSESS_CACHE ? await kvGetJSON(env.ASSESS_CACHE, kvKey) : null;
        cachedStatus[skillName] = !!(cached && cached.assessment && !cached.assessment.__error);
      })
    );

    return new Response(JSON.stringify(cachedStatus), { headers });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
  }
}

// --- FULL ASSESSMENT HANDLER ---
async function handleFullAssessment(request, env) {
  const url = new URL(request.url);
  const headers = { "Content-Type": "application/json; charset=utf-8" };

  // -------- Optional Bearer auth ----------
  const requireAuth =
    String(env.REQUIRE_AUTH || "").toLowerCase() === "true" ||
    String(env.REQUIRE_AUTH || "").trim() === "1";
  const serviceToken = env.SERVICE_TOKEN || "";
  function isAuthorized(req) {
    if (!requireAuth) return true;
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    return !!token && token === serviceToken;
  }

  const DEBUG_PROMPT_FLAG =
  url.searchParams.get("debug_prompt") === "1" ||
  String(env.DEBUG_PROMPT || "").trim() === "1";
  function dlog(...args) { if (DEBUG_PROMPT_FLAG) console.log(...args); }

  // -------- Optional admin KV ----------
  const adminEnabled =
    String(env.ADMIN_API || "").toLowerCase() === "true" ||
    String(env.ADMIN_API || "").trim() === "1";

  if (request.method === "POST" && url.pathname.startsWith("/admin/kv/")) {
    if (!adminEnabled) return new Response(JSON.stringify({ error: "Admin API disabled" }), { status: 404, headers });
    if (!isAuthorized(request)) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers });

    const body = await request.json().catch(() => ({}));
    const ns = env.ASSESS_CACHE;
    if (!ns) return new Response(JSON.stringify({ error: "KV binding ASSESS_CACHE missing" }), { status: 500, headers });

    if (url.pathname === "/admin/kv/purge") {
      const { kind, hash, cache_version } = body || {};
      const v = String(cache_version ?? env.CACHE_VERSION ?? "1");
      if (!kind || !hash) return new Response(JSON.stringify({ error: "kind and hash required" }), { status: 400, headers });
      const key = `v${v}:${kind}:${hash}`;
      await ns.delete(key);
      return new Response(JSON.stringify({ ok: true, deleted: key }), { headers });
    }

    if (url.pathname === "/admin/kv/list") {
      const prefix = url.searchParams.get("prefix") || "";
      const out = await ns.list({ prefix, limit: 1000 });
      return new Response(JSON.stringify(out), { headers });
    }

    return new Response(JSON.stringify({ error: "Unknown admin route" }), { status: 404, headers });
  }

  const t0 = Date.now();
  const timing = {
    index_ms: 0,
    index_segments: 0,
    assess_calls: [],
    assess_ms_total: 0,
    prompt_bytes_total: 0,
  };

  try {
    const GEMINI_API_KEY = env.GEMINI_API_KEY;
    if (!GEMINI_API_KEY) {
      return new Response(JSON.stringify({ error: "API key not configured in Cloudflare secrets." }), { status: 500, headers });
    }

    // ===== Tunables =====
    const INDEX_MODEL  = (env.INDEX_MODEL  || "gemini-2.5-pro").trim();
    const ASSESS_MODE  = (env.ASSESS_MODE  || "parallel").toLowerCase();

    const MAX_CONCURRENCY   = num(env.MAX_CONCURRENCY, 4);
    const MAX_RUBRICS_BYTES = num(env.MAX_RUBRICS_BYTES, 1_000_000);
    const MAX_SKILLS_CAP    = num(env.MAX_SKILLS_CAP, 50);

    const ASSESS_RETRY_MAX        = num(env.ASSESS_RETRY_MAX, 1);
    const ASSESS_RETRY_BASE_MS    = num(env.ASSESS_RETRY_BASE_MS, 700);

    const MIN_QUOTES_PER_POSITIVE_PASS   = num(env.MIN_QUOTES_PER_POSITIVE_PASS, 1);
    const MIN_QUOTES_PER_HIGH_LEVEL_PASS = num(env.MIN_QUOTES_PER_HIGH_LEVEL_PASS, 1);
    const HIGH_LEVEL_START               = num(env.HIGH_LEVEL_START, 4);
    
    const EVIDENCE_FUZZ      = num(env.EVIDENCE_FUZZ, 0.78);
    const NGRAM_N            = num(env.NGRAM_N, 3);
    const NGRAM_THRESHOLD    = num(env.NGRAM_THRESHOLD, 0.6);
    const SOFT_CONTAINS_MIN  = num(env.SOFT_CONTAINS_MIN, 10);
    
    const REQUIRE_DISTINCT_EVIDENCE       = bool(env.REQUIRE_DISTINCT_EVIDENCE, false);
    const MAX_EVIDENCE_REUSE              = num(env.MAX_EVIDENCE_REUSE, 5);
    const ENFORCE_MAX_WORDS_IN_EVIDENCE   = bool(env.ENFORCE_MAX_WORDS_IN_EVIDENCE, false);

    const MAX_SELLER_QUOTES = num(env.MAX_SELLER_QUOTES, 100);
    const MAX_CUSTOMER_CUES = num(env.MAX_CUSTOMER_CUES, 50);
    const MAX_QUOTE_WORDS   = num(env.MAX_QUOTE_WORDS, 100);

    const INDEX_SEGMENT_CHARS     = num(env.INDEX_SEGMENT_CHARS, 3000);
    const INDEX_SEGMENT_MAX       = num(env.INDEX_SEGMENT_MAX, 10);
    const INDEX_SPLIT_MAX_DEPTH   = num(env.INDEX_SPLIT_MAX_DEPTH, 3);
    
    const WHITELIST_MAX     = num(env.WHITELIST_MAX, 150);
    const BUCKETS_IN_PROMPT = String(env.BUCKETS_IN_PROMPT || "none").toLowerCase();
    const BUCKET_SAMPLE_N   = num(env.BUCKET_SAMPLE_N, "none");

    const GEMINI_TIMEOUT_MS   = num(env.GEMINI_TIMEOUT_MS, 120000);
    const INDEX_RETRY_MAX     = num(env.INDEX_RETRY_MAX, 3);
    const INDEX_RETRY_BASE_MS = num(env.INDEX_RETRY_BASE_MS, 800);

    const CACHE_VERSION   = String(env.CACHE_VERSION || "1");
    const KV_TTL_SECS     = num(env.KV_TTL_SECS,   60 * 60 * 24 * 14);
    const EDGE_TTL_SECS   = num(env.EDGE_TTL_SECS,   60 * 60 * 24 * 7);
    const WARM_EDGE_CACHE = bool(env.WARM_EDGE_CACHE, true);

    const normalizeQuote = makeNormalizeQuote(MAX_QUOTE_WORDS, ENFORCE_MAX_WORDS_IN_EVIDENCE);

    // ===== Parse body =====
    const body = await request.json().catch(() => ({}));
    let {
      transcript,
      rubrics,          // ignored unless rubrics_url explicitly used
      rubrics_url,
      skills,
      include_presentation,
      rubric_version,
      sellerId
    } = body || {};

    if (!transcript && typeof body?.transcript === "string") transcript = body.transcript;

    const rubricSetParam = url.searchParams.get("rubric_set");
    const skillsParamQS  = url.searchParams.get("skills");
    const competencyQS   = url.searchParams.get("competency");

    if (!Array.isArray(skills) && typeof skillsParamQS === "string") {
      skills = skillsParamQS.split(",").map((s) => s.trim()).filter(Boolean);
    }

    // ---- ALWAYS prefer server-side rubric sources ----
    // 1) explicit URL (if provided) -> 2) KV (rubric_set or default) -> error
    let rubric_source = null;
    let loadedRubrics = null;

    if (rubrics_url) {
      if (!/^https:\/\/.+/i.test(rubrics_url)) {
        return new Response(JSON.stringify({ error: "rubrics_url must be HTTPS" }), { status: 400, headers });
      }
      const rubricsRes = await fetch(rubrics_url, { method: "GET" });
      const ct = (rubricsRes.headers.get("content-type") || "").toLowerCase();
      if (!ct.includes("application/json")) {
        return new Response(JSON.stringify({ error: "rubrics_url did not return JSON" }), { status: 400, headers });
      }
      const rubricsText = await rubricsRes.text();
      if (rubricsText.length > MAX_RUBRICS_BYTES) {
        return new Response(JSON.stringify({ error: `rubrics JSON too large (>${MAX_RUBRICS_BYTES} bytes)` }), { status: 400, headers });
      }
      try { loadedRubrics = JSON.parse(rubricsText); }
      catch { return new Response(JSON.stringify({ error: "Invalid JSON from rubrics_url" }), { status: 400, headers }); }
      rubric_source = "url";
    } else {
      // Pull from KV (default when no URL)
      if (!env.RUBRICS) {
        return new Response(JSON.stringify({ error: "KV binding RUBRICS missing" }), { status: 500, headers });
      }
      const setKey = rubricSetParam || env.DEFAULT_RUBRIC_SET || "rubrics:v1";
      let kvVal = await env.RUBRICS.get(setKey, "text");

      // alias support: if the KV value is itself a KV key
      if (kvVal && /^rubrics:/.test(kvVal.trim())) {
        const aliasVal = await env.RUBRICS.get(kvVal.trim(), "text");
        if (aliasVal) kvVal = aliasVal;
      }

      if (!kvVal) {
        return new Response(JSON.stringify({
          error: "rubric_set not found in KV",
          rubric_set: setKey
        }), { status: 404, headers });
      }
      if (kvVal.length > MAX_RUBRICS_BYTES) {
        return new Response(JSON.stringify({ error: `KV rubrics too large (>${MAX_RUBRICS_BYTES} bytes)` }), { status: 400, headers });
      }
      try { loadedRubrics = JSON.parse(kvVal); }
      catch {
        return new Response(JSON.stringify({
          error: "Invalid JSON in KV rubric_set",
          rubric_set: setKey
        }), { status: 400, headers });
      }
      rubric_source = `kv:${setKey}`;
    }

    // If a competency filter is present, narrow to that competency (structure preserved)
    if (competencyQS) {
      const comp = loadedRubrics?.[competencyQS];
      if (!comp?.skills) {
        return new Response(JSON.stringify({ error: `Unknown competency: ${competencyQS}` }), { status: 400, headers });
      }
      loadedRubrics = { [competencyQS]: { skills: comp.skills } };
    }

    // Final assign: use server-side rubrics only
    rubrics = loadedRubrics;

    if (!transcript || !rubrics) {
      return new Response(JSON.stringify({ error: "Missing 'transcript' or could not load 'rubrics'." }), { status: 400, headers });
    }
    
    const googleURL = (model) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
    const edgeCache = caches.default;
    function edgeKey(kind, hash) { return new Request(`https://cache.internal/${kind}/${hash}`, { method: "GET" }); }
    async function edgePutJSON(reqKey, json) {
      if (!WARM_EDGE_CACHE) return;
      const res = new Response(JSON.stringify(json), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${EDGE_TTL_SECS}, s-maxage=${EDGE_TTL_SECS}`,
          "X-Cached-By": "sales-coach-worker",
        },
      });
      await edgeCache.put(reqKey, res);
    }

    // ---------- helpers used later ----------
    function normalizeTranscript(s) {
      if (!s) return "";
      let t = String(s);
      t = t.replace(/\t/g, " ").replace(/[ \u00A0]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();
      return t;
    }
    function sortRubricDeterministically(rubricData) {
      if (!rubricData || !Array.isArray(rubricData.levels)) { return rubricData; }
      const sortedRubric = JSON.parse(JSON.stringify(rubricData));
      sortedRubric.levels.sort((a, b) => (a.level || 0) - (b.level || 0));
      for (const level of sortedRubric.levels) {
        if (Array.isArray(level.checks)) {
          level.checks.sort((a, b) => String(a.characteristic).localeCompare(String(b.characteristic)));
        }
      }
      return sortedRubric;
    }
    function isCustomerEvidenceRequired(characteristicText) {
      const lowerText = String(characteristicText || '').toLowerCase();
      if (!lowerText) return false;
      const keywords = ['prompting', 'prompted', 'guidance', 'support', 'feedback', 'objections', 'cues', 'led by'];
      return keywords.some(keyword => lowerText.includes(keyword));
    }
    function isCharacteristicObservable(characteristicText) {
      const NON_OBSERVABLE_KEYWORDS = ['document', 'documents', 'documented', 'documentation', 'write', 'writes', 'written', 'update', 'updates', 'updated', 'schedule', 'schedules', 'scheduled', 'send', 'sends', 'sent', 'log', 'logs', 'logged', 'report', 'reports', 'reported', 'crm', 'email', 'calendar', 'invite', 'follow-up', 'follow up'];
      const lowerText = String(characteristicText || '').toLowerCase();
      if (!lowerText) return true;
      return !NON_OBSERVABLE_KEYWORDS.some(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`);
        return regex.test(lowerText);
      });
    }
    function applyObservableFlags(modelChecks, originalRubric) {
      const characteristicMap = new Map();
      for (const level of originalRubric?.levels || []) {
        for (const check of level?.checks || []) {
          const characteristic = String(check.characteristic || '').trim();
          if (!characteristic) continue;
          let isObservable;
          if (typeof check.observable === 'boolean') {
            isObservable = check.observable;
          } else {
            isObservable = isCharacteristicObservable(characteristic);
          }
          characteristicMap.set(characteristic, isObservable);
        }
      }
      const processedChecks = JSON.parse(JSON.stringify(modelChecks));
      for (const level of processedChecks || []) {
        for (const check of level?.checks || []) {
          const characteristic = String(check.characteristic || '').trim();
          check.observable = characteristicMap.get(characteristic) ?? true;
        }
      }
      return processedChecks;
    }
    function normalizeChecks(levels) {
      for (const lvl of levels || []) {
        for (const c of (lvl.checks || [])) {
          if (typeof c.observable !== "boolean") c.observable = true;
        }
      }
      return levels;
    }
    function correctInconsistentMetStatus(levels) {
      const corrected = JSON.parse(JSON.stringify(levels));
      for (const level of corrected) {
        if (!level.checks) continue;
        for (const check of level.checks) {
          const hasEvidence = check.evidence && check.evidence.length > 0;
          if (check.met === true && !hasEvidence && (check?.observable ?? true)) {
            check.met = false;
            check.reason = `[AUTO-CORRECTED] 'met' was true but no evidence was found. Original reason: ${check.reason}`;
          }
        }
      }
      return corrected;
    }
    function normalizePolarity(levels) {
      const NEG_PATTERNS = [/^does not\b/i, /^fails to\b/i, /^provides an incomplete\b/i, /^rarely\b/i];
      const out = JSON.parse(JSON.stringify(levels || []));
      for (const lvl of out) {
        for (const check of (lvl.checks || [])) {
          const p = String(check.polarity || "").toLowerCase().trim();
          if (p === "positive" || p === "negative" || p === "limitation") {
            check.polarity = p;
            continue;
          }
          const ch = String(check.characteristic || "");
          check.polarity = NEG_PATTERNS.some(rx => rx.test(ch)) ? "negative" : "positive";
        }
      }
      return out;
    }
    function levelRequiredQuotes(lvlNum) {
      return (lvlNum >= HIGH_LEVEL_START) ? MIN_QUOTES_PER_HIGH_LEVEL_PASS : MIN_QUOTES_PER_POSITIVE_PASS;
    }
    function didPassLevelPositives(lvl) {
      if (!lvl || !Array.isArray(lvl.checks)) return true;
      const rq = levelRequiredQuotes(lvl.level || 0);
      const positives = lvl.checks.filter(
        c => (c.polarity || "positive") === "positive" && (c?.observable ?? true) === true
      );
      const allPositivesMet = positives.length === 0 || positives.every(c => c.met === true && Array.isArray(c.evidence) && c.evidence.length >= rq);
      const limitations = lvl.checks.filter(
        c => c.polarity === "limitation" && (c?.observable ?? true) === true
      );
      const allLimitationsMet = limitations.every(c => c.met === true);
      return allPositivesMet && allLimitationsMet;
    }

    function computeHighestDemonstrated(levels) {
      if (!Array.isArray(levels) || levels.length === 0) return 1;
      const normalized = normalizeChecks(levels);
      const sorted = [...normalized].sort((a,b) => (a.level||0)-(b.level||0));
      let highest = 0;
      for (const lvl of sorted) {
        // This version does NOT break; it finds the highest level passed anywhere.
        if (didPassLevelPositives(lvl)) highest = Math.max(highest, lvl.level || 0);
      }
      return highest > 0 ? highest : 1;
    }

    function selectWhitelistForRubrics(index, rubricsSubset, maxN = WHITELIST_MAX, transcript = "") {
      const allSkills = [];
      for (const comp in rubricsSubset || {}) {
        const s = rubricsSubset[comp]?.skills || {};
        for (const k in s) allSkills.push(k);
      }
      const union = [];
      const seen = new Set();
      for (const name of allSkills) {
        const qs = selectWhitelistForSkill(
          index,
          name,
          maxN,
          transcript,
          { maxQuoteWords: MAX_QUOTE_WORDS, enforce: ENFORCE_MAX_WORDS_IN_EVIDENCE }
        );
        for (const q of qs) {
          if (!seen.has(q)) {
            seen.add(q);
            union.push(q);
            if (union.length >= maxN) return union;
          }
        }
      }
      return union.length ? union : (index?.seller_quotes || []).map(normalizeQuote).filter(Boolean).slice(0, maxN);
    }
    function enforceNegativeGuard(levels) {
      const out = JSON.parse(JSON.stringify(levels));
      for (const lvl of out || []) {
        for (const check of (lvl.checks || [])) {
          if ((check.polarity || "positive") !== "negative") continue;
          const hasEvidence = Array.isArray(check.evidence) && check.evidence.length > 0;
          if (check.met === true && hasEvidence) {
            check.met = false;
            check.evidence = [];
            check.reason = `[AUTO-CORRECTED] Negative check cannot be 'met' with verbatim evidence. Set to met:false and removed evidence. ${check.reason || ""}`.trim();
          }
        }
      }
      return out;
    }

    function normKey(s) {
      return String(s || "")
        .toLowerCase()
        .replace(/\s+/g, " ")
        .trim();
    }
    
    function buildSkillMap(rubricsObj) {
      const map = new Map();
      for (const comp in (rubricsObj || {})) {
        const skillsObj = rubricsObj[comp]?.skills || {};
        for (const skillName in skillsObj) {
          map.set(normKey(skillName), { skillName, competency: comp, rubricData: skillsObj[skillName] });
        }
      }
      return map;
    }
    
    function resolveSkill(rubricsObj, requestedName) {
      const m = buildSkillMap(rubricsObj);
      return m.get(normKey(requestedName)) || null;
    }    

    function extractFnCall(resp) {
      const cands = resp?.candidates || [];
      for (const c of cands) {
        const parts = c?.content?.parts || [];
        for (const p of parts) {
          if (p?.functionCall?.name && p?.functionCall?.args) return p.functionCall;
          if (typeof p?.text === "string") {
            try {
              const parsed = JSON.parse(p.text);
              if (parsed && (parsed.level_checks || parsed.levelChecks)) {
                return { name: "extract_analysis", args: { level_checks: parsed.level_checks || parsed.levelChecks } };
              }
            } catch {}
          }
        }
      }
      return null;
    }

    // IMPORTANT: we missed this earlier; add it back.
    function sanitizeEvidenceAgainstIndex(skillLevels, sellerQuotesSet, transcriptText, allowlist) {
      const rawTranscript  = transcriptText || "";
      const normTranscript = normalize(rawTranscript);
      const sellerQuotes = new Set(Array.from(sellerQuotesSet || new Set()).map(normalize).filter(Boolean));
      const allowSet = (() => {
        if (!allowlist) return null;
        const arr = allowlist instanceof Set ? Array.from(allowlist) : Array.isArray(allowlist) ? allowlist : [];
        const s = new Set(arr.map(normalize).filter(Boolean));
        return s.size ? s : null;
      })();
      const getMinForLevel = (level) => (Number(level) >= HIGH_LEVEL_START ? MIN_QUOTES_PER_HIGH_LEVEL_PASS : MIN_QUOTES_PER_POSITIVE_PASS);
      let totalBefore = 0, totalAfter = 0;
      const hasQuote = (q) => {
        if (!q || typeof q !== "string") return false;
        const n = normalize(q);
        if (!n) return false;
        if (allowSet && allowSet.has(n)) return true;
        if (normTranscript.includes(n)) return true;
        if (sellerQuotes.has(n)) return true;
        for (const s of sellerQuotes) {
          if (tokenSim(n, s) >= EVIDENCE_FUZZ || softContains(s, n, SOFT_CONTAINS_MIN) || softContains(n, s, SOFT_CONTAINS_MIN)) return true;
        }
        if (n.length > 40 && ngramContainment(n, normTranscript, NGRAM_N) >= NGRAM_THRESHOLD) return true;
        return false;
      };
      for (const lvl of (skillLevels || [])) {
        const MIN = getMinForLevel(Number(lvl.level) || 0);
        const reuseCounter = new Map();
        for (const check of (lvl.checks || [])) {
          const ev = Array.isArray(check.evidence) ? check.evidence : [];
          totalBefore += ev.length;
          const kept = ev.map(normalize).filter(hasQuote);
          const dedupFinal = [];
          for (const q of kept) {
            const used = reuseCounter.get(q) || 0;
            if (used < MAX_EVIDENCE_REUSE) {
              reuseCounter.set(q, used + 1);
              dedupFinal.push(q);
            }
          }
          check.evidence = dedupFinal;
          totalAfter += dedupFinal.length;
          const isPositive = (check.polarity || "positive") === "positive" && (check?.observable ?? true) === true;
          if (isPositive && check.met === true && check.evidence.length < MIN) check.met = false;
        }
      }
      if (REQUIRE_DISTINCT_EVIDENCE) {
        const used = new Set();
        for (const lvl of (skillLevels || [])) {
          for (const check of (lvl.checks || [])) {
            const isPositive = (check.polarity || "positive") === "positive" && (check?.observable ?? true) === true;
            if (!isPositive) continue;
            let uniqueFound = false;
            for (const q of (check.evidence || [])) {
              if (!used.has(q)) { used.add(q); uniqueFound = true; break; }
            }
            if (check.met === true && !uniqueFound) check.met = false;
          }
        }
      }
      try {
        const loss = totalBefore ? 1 - (totalAfter / totalBefore) : 1;
        skillLevels._debug = Object.assign({}, skillLevels._debug, { evidenceLossRatioPostSanitize: +loss.toFixed(3) });
      } catch {}
      return correctInconsistentMetStatus(skillLevels);

      function normalize(s) { return String(s || "").toLowerCase().replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').replace(/[^a-z0-9\s\?]/g, " ").replace(/\s+/g, " ").trim(); }
      function tokenSim(a, b) { const A = new Set(a.split(" ").filter(Boolean)); const B = new Set(b.split(" ").filter(Boolean)); const inter = [...A].filter(x => B.has(x)).length; const denom = Math.max(A.size, B.size) || 1; return inter / denom; }
      function softContains(longer, shorter, minLen) { if (!longer || !shorter) return false; if (shorter.length < (minLen || 10)) return longer.includes(shorter); const lw = longer.split(" ").filter(Boolean); const sw = shorter.split(" ").filter(Boolean); let i = 0; for (const w of sw) { while (i < lw.length && lw[i] !== w) i++; if (i === lw.length) return false; i++; } return true; }
      function ngramContainment(q, corpus, n) { const toksQ = q.split(" ").filter(Boolean); if (toksQ.length < n) return 0; const grams = new Set(); for (let i = 0; i <= toksQ.length - n; i++) grams.add(toksQ.slice(i, i + n).join(" ")); let hit = 0; for (const g of grams) if (corpus.includes(g)) hit++; return grams.size ? hit / grams.size : 0; }
    }

    // ===== Prompt builders =====
    function buildIndexPrompt(transcript) {
      return `
      You are a STRICT, objective assistant. Your primary goal is to build a SELLER-CENTRIC evidence index from the provided transcript.
      **Seller Identification Logic (in order of priority):**
      1.  **BEHAVIORAL ANALYSIS (Primary Method):** Your primary method for identifying the seller is by analyzing their role. The **SELLER** is the speaker who consistently asks discovery questions, introduces products or solutions, and guides the conversation. The **CUSTOMER** is the one primarily answering questions and describing their challenges.
      2.  **NAMES AS CONFIRMATION (Secondary Method):** Use names mentioned in the dialogue only to confirm your behavioral analysis. A single name mentioned, especially if it's a mistake, should NOT override the behavioral analysis.
      **Your Final Answer:**
      - After your analysis, use the speaker's original label (e.g., 'User', 'Speaker 1') as the final seller_label.
      Output (must call index_transcript). Return ONLY the function call with:
      - seller_label: The final, correct label of the seller (e.g., 'User').
      - seller_quotes[]: Max ${MAX_SELLER_QUOTES} quotes from the seller (<= ${MAX_QUOTE_WORDS} words each).
      - customer_cues[]: Max ${MAX_CUSTOMER_CUES} quotes from the customer (<= ${MAX_QUOTE_WORDS} words each).
      - evidence_buckets: Group SELLER quotes by generic behavior.
      TRANSCRIPT
      ---
      ${transcript}
      ---`;
    }
    function buildDirectedIndexPrompt(transcript, sellerLabel) {
      let customerLabel;
      const lines = transcript.split('\n');
      const speakers = new Set(lines.map(line => line.split(':')[0].trim()).filter(Boolean));
      if (speakers.has('Agent') && speakers.has('User')) {
        customerLabel = sellerLabel === 'User' ? 'Agent' : 'User';
      } else {
        speakers.delete(sellerLabel);
        customerLabel = [...speakers][0] || 'Customer';
      }
      return `
      You are a STRICT, objective assistant. Your goal is to extract quotes from the provided transcript.
      **CRITICAL INSTRUCTION:**
      - The SELLER has been pre-identified. The seller's label is "${sellerLabel}".
      - The CUSTOMER's label is "${customerLabel}".
      - Your ONLY job is to extract and bucket the quotes based on these roles. Do NOT perform your own analysis to identify the seller.
      Output (must call index_transcript). Return ONLY the function call with:
      - seller_label: Use the provided label: "${sellerLabel}".
      - seller_quotes[]: Max ${MAX_SELLER_QUOTES} quotes from the seller ("${sellerLabel}").
      - customer_cues[]: Max ${MAX_CUSTOMER_CUES} quotes from the customer ("${customerLabel}").
      - evidence_buckets: Group the SELLER's quotes by generic behavior.
      TRANSCRIPT
      ---
      ${transcript}
      ---`;
    }
    function buildAnalysisPrompt(skillName, rubricData, index, whitelist) {
    const sortedRubric = sortRubricDeterministically(rubricData);

    // Identify characteristics that need the customer evidence exception rule
    const customerEvidenceChecks = new Set();
    for (const level of rubricData?.levels || []) {
        for (const check of level?.checks || []) {
            if (isCustomerEvidenceRequired(check.characteristic)) {
                customerEvidenceChecks.add(String(check.characteristic || '').trim());
            }
        }
    }

    // Dynamically create the exception rule text for the prompt
    const exceptionRuleText = customerEvidenceChecks.size > 0 
        ? `**Evidence Rule 2 (Exception):** For characteristics describing the seller requiring "prompting," "guidance," or reacting to "feedback" or "objections," you MUST look for evidence in the \`indexed_customer_cues\`. For this skill, this rule applies to: ${stable(Array.from(customerEvidenceChecks))}`
        : `**Evidence Rule 2 (No Exceptions):** For this skill, all evidence must come from the seller's quotes. The \`indexed_customer_cues\` are for context only.`;

    return `
You are an extremely STRICT and OBJECTIVE AI Analyst. Your only function is to compare verbatim quotes from a transcript to a rubric. You must act as a hyper-literal and demanding grader.

**CORE DIRECTIVES:**

1.  **PRINCIPLE OF EVIDENCE:** The evidence MUST be a direct, self-evident demonstration of the characteristic described in the rubric.
    - **Directness:** The quote itself must be the evidence. Do not infer intent or give credit for trying.
    - **Completeness & Context:** A characteristic can be met by a single quote OR by a logical sequence of related quotes. For example, if a characteristic is "Proactively probes for clarification," a series of questions that dig deeper into a topic collectively meets the criteria. You must, however, cite the most representative quotes from that sequence.

2.  **THE FAIR INTERPRETATION RULE:** While you must be literal, you must also be fair. Acknowledge the logical flow of conversation. Do not penalize a seller for asking multiple questions to explore a topic instead of one perfect question. If the seller's questions logically lead to the uncovering of a challenge, that counts as evidence.

3.  **ABSENCE OF EVIDENCE IS FAILURE:** If you cannot find verbatim evidence that directly and completely matches the characteristic, it is **NOT MET**.

**ADDITIONAL GUIDANCE:**
- **Evidence Mandate:** You MUST cite at least one representative quote in the 'evidence' array for EVERY check to support your 'reason', regardless of whether 'met' is true or false.
- **Observability:** For characteristics mentioning non-observable actions (e.g., "documents challenges"), base your assessment ONLY on the observable parts. If the observable part is met, you may set 'met: true'.
- **Polarity Logic:**
    - **Positive:** A desirable skill. Set 'met: true' ONLY if demonstrated according to the Core Directives.
    - **Limitation:** A characteristic of a developing performance, representing a minimum bar.
        - **Crucial Rule:** Set 'met: true' if the performance is **the same as OR better than** the limitation. This means the seller has cleared the minimum bar.
        - Set 'met: false' ONLY if the performance is **worse than** the limitation. This means the seller failed to clear the minimum bar.
    - **Negative:** A critical flaw. Set 'met: true' ONLY if the seller actively demonstrates this negative behavior.
---
**EVIDENCE SOURCES AND RULES:**

**Source 1: Seller Quotes**
indexed_seller_quotes = ${stable(whitelist)}

**Source 2: Customer Cues (Context)**
indexed_customer_cues = ${stable(index.customer_cues || [])}

**Evidence Rule 1 (Primary):** For most characteristics, you MUST use evidence exclusively from the \`indexed_seller_quotes\`.

${exceptionRuleText}
---
**TASK:**
- For EVERY characteristic in EVERY level of the rubric, determine if it was 'met' based on the strict directives above.
- Return ONLY a function call to 'extract_analysis'. Provide a concise 'reason' and cite the specific verbatim 'evidence'.
---
**RUBRIC (Skill: ${skillName})**
---
${stable(sortedRubric)}
---`;
}

    function buildCoachingPrompt(skillName, rating, levelChecks, gatingSummary) {
      return `
      You are an expert AI Sales Coach. The analysis for "${skillName}" has a final rating of ${rating}/5.
      Use ONLY this analysis (do not re-score):
      ${stable({ level_checks: levelChecks, gating_summary: gatingSummary })}
      YOUR TASK:
      - Return ONLY JSON via extract_coaching_feedback.
      - 2-4 strengths (from highest achieved).
      - 3-5 improvements (unmet positives at the next level), include a concise supporting quote when available.
      - 3-6 actionable coaching tips mapped to the improvements.`;
    }

    // ===== Tool schemas (Gemini indexing only) -------
    const coachingTool = {
      functionDeclarations: [{
        name: "extract_coaching_feedback",
        description: "Extract the generated strengths, improvements, and coaching tips.",
        parameters: {
          type: "OBJECT",
          properties: {
            strengths: { type: "ARRAY", items: { type: "STRING" } },
            improvements: { type: "ARRAY", items: { type: "OBJECT", properties: { point: { type: "STRING" }, quote: { type: "STRING" } }, required: ["point", "quote"] } },
            coaching_tips: { type: "ARRAY", items: { type: "STRING" } },
          },
          required: ["strengths", "improvements", "coaching_tips"],
        },
      }],
    };
    const indexingTool = {
      functionDeclarations: [{
        name: "index_transcript",
        description: "Identify the seller and extract seller-only quotes (no paraphrase). Also bucket quotes by generic behavior types. KEEP OUTPUT SMALL.",
        parameters: {
          type: "OBJECT",
          properties: {
            seller_label: { type: "STRING" },
            seller_quotes: { type: "ARRAY", items: { type: "STRING" } },
            customer_cues: { type: "ARRAY", items: { type: "STRING" } },
            evidence_buckets: {
              type: "OBJECT",
              properties: {
                ask_probe: { type: "ARRAY", items: { type: "STRING" } },
                clarify_validate: { type: "ARRAY", items: { type: "STRING" } },
                summarize_synthesize: { type: "ARRAY", items: { type: "STRING" } },
                empathize_label: { type: "ARRAY", items: { type: "STRING" } },
                quantify_measure: { type: "ARRAY", items: { type: "STRING" } },
                connect_link: { type: "ARRAY", items: { type: "STRING" } },
                document_commit: { type: "ARRAY", items: { type: "STRING" } },
                explain_teach: { type: "ARRAY", items: { type: "STRING" } },
                position_value: { type: "ARRAY", items: { type: "STRING" } },
                other: { type: "ARRAY", items: { type: "STRING" } },
              },
            },
          },
          required: ["seller_label", "seller_quotes", "customer_cues", "evidence_buckets"],
        },
      }],
    };

    // ===== Utility: evidence pickers for UI quotes =========================
    function flattenAllEvidence(levelChecks) {
      const out = [];
      for (const lvl of levelChecks || []) {
        for (const c of (lvl.checks || [])) {
          const ev = Array.isArray(c.evidence) ? c.evidence : [];
          for (const q of ev) out.push({ level: lvl.level, name: lvl.name, characteristic: c.characteristic, quote: q, met: !!c.met, polarity: c.polarity || "positive" });
        }
      }
      return out;
    }

    function pickRepresentativeEvidenceForCharacteristic(levelChecks, characteristic, exclude = new Set()) {
      const all = flattenAllEvidence(levelChecks);
  
      // Find all checks that are NOT the target characteristic but are related (same skill area)
      // and were MET with POSITIVE polarity, and are NOT in the exclude set.
      const candidates = all.filter(e =>
          e.characteristic !== characteristic &&
          e.polarity === 'positive' &&
          e.met === true &&
          e.quote &&
          !exclude.has(e.quote)
      ).sort((a, b) => b.level - a.level); // Sort by highest level first
  
      // 1. Prioritize a unique, high-level, positive quote.
      if (candidates.length > 0) {
          return candidates[0].quote;
      }
      
      // 2. Fallback: If no unique quotes are left, find any MET positive quote, even if it's a repeat.
      const anyMetPositive = all.find(e => e.polarity === 'positive' && e.met === true && e.quote);
      if (anyMetPositive) return anyMetPositive.quote;
  
      // 3. Last resort fallback: Find any quote from a limitation.
      const anyLimitation = all.find(e => e.polarity === 'limitation' && e.quote);
      if (anyLimitation) return anyLimitation.quote;
  
      return ""; // Return empty if no suitable quotes are found at all.
  }

  function backfillImprovementQuotes(improvements, levelChecks) {
    // 1. Find all available "gap" quotes from positive skills the seller actually MET.
    //    These are the best examples of what the seller did "instead of" the mastery-level skill.
    let metPositiveChecks = flattenAllEvidence(levelChecks)
        .filter(e => e.polarity === 'positive' && e.met === true && e.quote)
        .sort((a, b) => b.level - a.level); // Sort descending to prioritize higher-level skills.

    // If there are no met positives (e.g., rating is 1), use all evidence objects from level 1 (any polarity, any met status)
    if (metPositiveChecks.length === 0) {
        metPositiveChecks = flattenAllEvidence(levelChecks)
            .filter(e => e.level === 1 && e.quote);
    }

    // 2. Extract just the unique quotes into a list to prevent duplicates.
    const availableQuotes = [...new Set(metPositiveChecks.map(e => e.quote))];
    let quoteIndex = 0;

    // 3. Map over the improvements and fill in the blank 'instead_of' fields sequentially.
  return (improvements || []).map(impr => {
    if (impr && impr.example && !impr.example.instead_of) {
      if (quoteIndex < availableQuotes.length) {
        impr.example.instead_of = availableQuotes[quoteIndex];
        quoteIndex++;
      } else if (availableQuotes.length > 0) {
        impr.example.instead_of = availableQuotes[availableQuotes.length - 1];
      } else {
        // No available quote, so remove the property
        delete impr.example.instead_of;
      }
    }
    return impr;
  });
  }


    // ===== Gemini indexing only =====
    async function callGeminiIndex(apiKey, transcriptPart, sellerId = null) {
      let prompt;
      const hasAgentUserLabels = transcriptPart.includes("Agent:") && transcriptPart.includes("User:");
      if (sellerId) {
        prompt = buildDirectedIndexPrompt(transcriptPart, sellerId);
      } else if (hasAgentUserLabels) {
        prompt = buildDirectedIndexPrompt(transcriptPart, 'User');
      } else {
        prompt = buildIndexPrompt(transcriptPart);
      }
      const requestBody = {
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        tools: [indexingTool],
        toolConfig: { functionCallingConfig: { mode: "ANY"} },
        generationConfig: {
          temperature: 0,
          topK: 1,
          topP: 0,
          candidateCount: 1
        },
        safetySettings: [
          { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
        ],
      };
      const result = await withRetry(
        () => fetchJSON(googleURL(INDEX_MODEL), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestBody)
        }),
        { retries: num(env.INDEX_RETRY_MAX, 3), baseMs: num(env.INDEX_RETRY_BASE_MS, 800) }
      );
      const call = extractFnCall(result);
      if (!(call && call.args)) {
        const finishReason = result?.candidates?.[0]?.finishReason || "No reason provided.";
        throw new Error("Transcript indexing failed. Reason: " + finishReason);
      }
      return call.args;
    }

    function mergeIndexes(list, maxSeller, maxCues) {
      const hasUser = list.some(idx => idx?.seller_label === 'User');
      const sellerLabel = hasUser ? 'User' : (list.find(idx => idx?.seller_label)?.seller_label || 'Seller');
      const allSellerQuotes = new Set();
      const allCustomerCues = new Set();
      const allBucketedEvidence = {};
      BUCKET_ORDER.forEach(k => allBucketedEvidence[k] = new Set());
      for (const idx of list) {
        if (!idx || !idx.seller_label) continue;
        const quotesToAdd = {
          seller: idx.seller_label === sellerLabel ? idx.seller_quotes : idx.customer_cues,
          customer: idx.seller_label === sellerLabel ? idx.customer_cues : idx.seller_quotes,
        };
        (quotesToAdd.seller || []).forEach(q => allSellerQuotes.add(q));
        (quotesToAdd.customer || []).forEach(c => allCustomerCues.add(c));
        if (idx.evidence_buckets) {
          for (const k in idx.evidence_buckets) {
            if (allBucketedEvidence[k]) {
              (idx.evidence_buckets[k] || []).forEach(q => allBucketedEvidence[k].add(q));
            }
          }
        }
      }
      const out = {
        seller_label: sellerLabel,
        seller_quotes: sortQuotesDeterministic([...allSellerQuotes]).slice(0, maxSeller),
        customer_cues: sortQuotesDeterministic([...allCustomerCues]).slice(0, maxCues),
        evidence_buckets: {}
      };
      const finalSellerQuotesSet = new Set(out.seller_quotes);
      const order = new Map(out.seller_quotes.map((q,i)=>[q,i]));
      for (const k of BUCKET_ORDER) {
        const validQuotesInBucket = [...allBucketedEvidence[k]].map(q => String(q).trim()).filter(q => finalSellerQuotesSet.has(q));
        out.evidence_buckets[k] = validQuotesInBucket.sort((a, b) => order.get(a) - order.get(b)).slice(0, maxSeller);
      }
      return out;
    }

    async function adaptiveIndexSingle(apiKey, part, sellerId, depth = 0) {
      try {
        return await callGeminiIndex(apiKey, part, sellerId);
      } catch (e) {
        const msg = String(e?.message || e);
        const transient = /timeout|timed out|429|5\d\d|unavailable|quota|exhausted/i.test(msg);
        if (!transient || depth >= INDEX_SPLIT_MAX_DEPTH) throw e;
        if (depth < INDEX_SPLIT_MAX_DEPTH) {
          const mid = Math.floor(part.length / 2);
          const a = part.slice(0, mid).trim();
          const b = part.slice(mid).trim();
          if (a && b) {
            const [idxA, idxB] = await Promise.all([
              adaptiveIndexSingle(apiKey, a, sellerId, depth + 1),
              adaptiveIndexSingle(apiKey, b, sellerId, depth + 1),
            ]);
            return mergeIndexes([idxA, idxB], MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);
          }
        }
        throw e;
      }
    }

    async function indexTranscriptSmart(apiKey, transcriptFull, sellerId = null) {
      const t = normalizeTranscript(transcriptFull);
      const parts = splitOnSpeakerBoundaries(t, INDEX_SEGMENT_CHARS, INDEX_SEGMENT_MAX);
      timing.index_segments = parts.length;
      const tS = Date.now();
      if (parts.length === 1) {
        const res = await adaptiveIndexSingle(apiKey, parts[0], sellerId, 0);
        timing.index_ms = Date.now() - tS;
        return res;
      }
      const tasks = parts.map((p) => () => adaptiveIndexSingle(apiKey, p, sellerId, 0));
      const results = await runWithPool(tasks, Math.min(MAX_CONCURRENCY, 3));
      const valid = results.filter(Boolean);
      timing.index_ms = Date.now() - tS;
      if (!valid.length) throw new Error("Indexing failed for all segments");
      return mergeIndexes(valid, MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);
    }

    function splitOnSpeakerBoundaries(t, target = INDEX_SEGMENT_CHARS, maxParts = INDEX_SEGMENT_MAX) {
      if (t.length <= target) return [t];
      const turnRegex = /^([A-Za-z0-9_ ]+):\s*([\s\S]*?)(?=\n[A-Za-z0-9_ ]+:|$)/gm;
      const turns = [];
      let match;
      while ((match = turnRegex.exec(t)) !== null) {
        turns.push({ speaker: match[1].trim(), text: match[2].trim() });
      }
      if (turns.length === 0) {
        const chunks = [];
        for (let i = 0; i < t.length; i += target) {
          chunks.push(t.substring(i, i + target));
        }
        return chunks.slice(0, maxParts);
      } 
      function splitLongTurn(speaker, text, targetSize) {
        const subTurns = [];
        const sentences = text.match(/[^.!?]+[.!?]*\s*/g) || [text];
        let currentSubTurnText = "";
        for (const sentence of sentences) {
          if (currentSubTurnText.length + sentence.length > targetSize) {
            if (currentSubTurnText) subTurns.push({ speaker, text: currentSubTurnText.trim() });
            currentSubTurnText = sentence;
          } else {
            currentSubTurnText += sentence;
          }
        }
        if (currentSubTurnText) subTurns.push({ speaker, text: currentSubTurnText.trim() });
        return subTurns;
      }
      const chunks = [];
      let currentChunk = "";
      for (const turn of turns) {
        const turnString = `${turn.speaker}: ${turn.text}\n`;
        if (turnString.length > target) {
          if (currentChunk.length > 0) {
            chunks.push(currentChunk.trim());
            currentChunk = "";
          }
          const subTurns = splitLongTurn(turn.speaker, turn.text, target - (turn.speaker.length + 5));
          for (const subTurn of subTurns) {
            chunks.push(`${subTurn.speaker}: ${subTurn.text}`);
          }
          continue;
        }
        if (currentChunk.length + turnString.length > target && currentChunk.length > 0) {
          chunks.push(currentChunk.trim());
          currentChunk = "";
        }
        currentChunk += turnString;
      }
      if (currentChunk.length > 0) chunks.push(currentChunk.trim());
      return chunks.slice(0, maxParts);
    }

    async function runWithPool(tasks, limit = MAX_CONCURRENCY) {
      const results = [];
      let i = 0;
      const workers = new Array(Math.min(limit, tasks.length)).fill(0).map(async () => {

        while (i < tasks.length) {
          const idx = i++;
          try { results[idx] = await tasks[idx](); }
          catch (err) { results[idx] = { __error: true, error: String(err) }; }
        }
      });
      await Promise.all(workers);
      return results;
    }

    function trimIndex(idx, maxSeller = MAX_SELLER_QUOTES, maxCues = MAX_CUSTOMER_CUES) {
      if (!idx || typeof idx !== "object") return idx;
      const out = JSON.parse(JSON.stringify(idx || {}));
      out.seller_quotes = sortQuotesDeterministic(out.seller_quotes).slice(0, maxSeller);
      out.customer_cues = sortQuotesDeterministic(out.customer_cues).slice(0, maxCues);
      const order = new Map(out.seller_quotes.map((q,i)=>[q,i]));
      const eb = out.evidence_buckets || {};
      for (const k in eb) {
        const arr = (eb[k] || []).map(q => String(q).trim()).filter(q => order.has(q));
        const uniq = [...new Set(arr)];
        eb[k] = uniq.sort((a, b) => order.get(a) - order.get(b)).slice(0, maxSeller);
      }
      out.evidence_buckets = eb;
      return out;
    }

    // ===== PIPELINE =====
    const suppliedSkillCount = (() => {
      let n = 0;
      for (const comp in rubrics || {}) {
        const skillsObj = rubrics[comp]?.skills;
        if (skillsObj) n += Object.keys(skillsObj).length;
      }
      return n;
    })();
    if (suppliedSkillCount > MAX_SKILLS_CAP) {
      return new Response(JSON.stringify({ error: `Too many skills (${suppliedSkillCount}) > cap (${MAX_SKILLS_CAP})` }), { status: 400, headers });
    }
    if (Array.isArray(skills) && skills.length && suppliedSkillCount > skills.length) {
      const setRaw = new Set(skills.map((s) => String(s)));
      const filtered = {};
      for (const comp in rubrics || {}) {
        const compSkills = rubrics[comp]?.skills;
        if (!compSkills) continue;
        for (const skill in compSkills) {
          const keyA = skill, keyB = `${comp}|${skill}`;
          if (setRaw.has(keyA) || setRaw.has(keyB)) {
            if (!filtered[comp]) filtered[comp] = { skills: {} };
            filtered[comp].skills[skill] = compSkills[skill];
          }
        }
      }
      rubrics = filtered;
    }

    transcript = normalizeTranscript(transcript);

    // Determine which skills to assess (default = all in rubrics)
    let requestedSkills = Array.isArray(skills) && skills.length
    ? skills.map(String)
    : (() => {
       const all = [];
       for (const comp in rubrics || {}) {
         const s = rubrics[comp]?.skills || {};
          for (const k in s) all.push(k);
        }
        return all;
    })();

    const presentSkills = [];
    const missingSkills = [];
    const resolvedSkills = []; // [{ skillName, rubricData }]

    for (const s of requestedSkills) {
      const hit = resolveSkill(rubrics, s);
      if (hit && hit.rubricData && Array.isArray(hit.rubricData.levels) && hit.rubricData.levels.length) {
        presentSkills.push(hit.skillName);
        resolvedSkills.push({ skillName: hit.skillName, rubricData: hit.rubricData });
      } else {
        missingSkills.push(s);
      }
    }

    // Compute ONCE; reuse later for per-skill cache keys
    const indexKeyInput = stable({
      v: CACHE_VERSION,
      INDEX_MODEL,
      MAX_SELLER_QUOTES,
      MAX_CUSTOMER_CUES,
      MAX_QUOTE_WORDS,
      INDEX_SEGMENT_CHARS,
      INDEX_SEGMENT_MAX,
      INDEX_SPLIT_MAX_DEPTH,
      transcript,
      sellerId
    });
    const indexKeyHash = await sha256Hex(indexKeyInput);
    const indexKVKey  = `v${CACHE_VERSION}:index:${indexKeyHash}`;

    let rawIndex = null;
    let index_kv_hit = false;

    if (env.ASSESS_CACHE) {
      rawIndex = await kvGetJSON(env.ASSESS_CACHE, indexKVKey);
      if (rawIndex) index_kv_hit = true;
    }

    if (!rawIndex) {
      rawIndex = await indexTranscriptSmart(GEMINI_API_KEY, transcript, sellerId);
      if (env.ASSESS_CACHE) await kvPutJSON(env.ASSESS_CACHE, indexKVKey, rawIndex, KV_TTL_SECS, CACHE_VERSION);
      await edgePutJSON(edgeKey("index", indexKeyHash), rawIndex);
    }

    const index = trimIndex(rawIndex, MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);

    // === assessment engine (OpenRouter judge + coach) ======================
    function buildGatingSummary(levels) {
      const normalized = normalizeChecks(JSON.parse(JSON.stringify(levels || [])));
      const sorted = [...normalized].sort((a,b)=> (a.level||0)-(b.level||0));
      const highest = computeHighestDemonstrated(sorted);
      const out = [];
      for (const lvl of sorted) {
        const rq = levelRequiredQuotes(lvl.level || 0);
        const positives = (lvl.checks || []).filter(c => (c.polarity || "positive") === "positive" && (c?.observable ?? true) === true);
        const metDirect = positives.filter(c => c.met && (c.evidence||[]).length >= rq).map(c => c.characteristic);
        let attainedViaHigher = [];
        let unmet = [];
        if ((lvl.level || 0) < highest) {
          attainedViaHigher = positives.filter(c => !(c.met && (c.evidence||[]).length >= rq)).map(c => c.characteristic);
        } else {
          unmet = positives.filter(c => !(c.met && (c.evidence||[]).length >= rq)).map(c => c.characteristic);
        }
        out.push({ level: lvl.level, name: lvl.name, positives_met: metDirect, positives_unmet: unmet, positives_attained_via_higher: attainedViaHigher });
      }
      return out;
    }

    async function getAssessmentForSkill(apiKey_UNUSED, transcript, skillName, rubricData, index, wl, DEBUG_PROMPT_FLAG) {
      const MAX_QUOTE_WORDS = num(env.MAX_QUOTE_WORDS, 50);
      const ENFORCE_MAX = bool(env.ENFORCE_MAX_WORDS_IN_EVIDENCE, true);
      const normalizeQ = makeNormalizeQuote(MAX_QUOTE_WORDS, ENFORCE_MAX);

      const allowedQuotes = Array.isArray(wl) && wl.length
        ? wl.map(normalizeQ).filter(Boolean)
        : (index?.seller_quotes || []).map(normalizeQ).filter(Boolean);

      const tA0 = Date.now();
      let promptBytes = 0;

      function attachDebug(assessment, ctx = {}) {
        if (!DEBUG_PROMPT_FLAG) return assessment;
      
        const { judgeResp, coachResp } = ctx; // may be undefined on early returns
        try {
          const rawJudge = judgeResp
            ? (typeof judgeResp.content === "string" && judgeResp.content) || judgeResp.raw || ""
            : "";
          const rawCoach = coachResp
            ? (typeof coachResp.content === "string" && coachResp.content) || coachResp.raw || ""
            : "";
      
          const SLICE = 8000;
          assessment._debug = assessment._debug || {};
          if (rawJudge) assessment._debug.rawJudgeOutput = String(rawJudge).slice(0, SLICE);
          if (rawCoach) assessment._debug.rawCoachOutput = String(rawCoach).slice(0, SLICE);
        } catch (e) {
          assessment._debug = assessment._debug || {};
          assessment._debug.debugAttachError = String(e?.message || e);
        }
        return assessment;
      }

      if (!rubricData || !Array.isArray(rubricData.levels) || rubricData.levels.length === 0) {
        return attachDebug({
          skill: skillName, rating: 1, strengths: [], improvements: [], coaching_tips: [],
          seller_identity: index?.seller_label || "Seller",
          level_checks: [], gating_summary: [],
          _debug: { missing_rubric: true },
          _raw_model_output: [],
          _served_by: { judge: env.JUDGE_MODEL || "", coach: env.WRITER_MODEL || "" }
        });
      }

      const lvlCount = Array.isArray(rubricData?.levels) ? rubricData.levels.length : 0;
      let totalChecks = 0;
      for (const lvl of (rubricData?.levels || [])) {
        totalChecks += Array.isArray(lvl?.checks) ? lvl.checks.length : 0;
      }
      if (lvlCount === 0 || totalChecks === 0) {
        return attachDebug({
          skill: skillName,
          rating: 1,
          strengths: [],
          improvements: [],
          coaching_tips: [],
          seller_identity: index?.seller_label || "Seller",
          level_checks: [],
          gating_summary: [],
          _debug: { malformed_rubric: true, lvlCount, totalChecks },
          _raw_model_output: [],
          _served_by: { judge: env.JUDGE_MODEL || "", coach: env.WRITER_MODEL || "" }
        });
      }


      // ---- Build judge prompt (exceptions allowed for customer cues if needed)
      const customerEvidenceChecks = new Set();
      for (const level of rubricData?.levels || []) {
        for (const check of level?.checks || []) {
          if (isCustomerEvidenceRequired(check.characteristic)) {
            customerEvidenceChecks.add(String(check.characteristic || '').trim());
          }
        }
      }
      const exceptionRuleText = customerEvidenceChecks.size > 0
        ? `For characteristics requiring prompting/guidance/feedback/objections, you MAY use customer cues as evidence: ${stable(Array.from(customerEvidenceChecks))}`
        : `Use ONLY seller quotes for evidence; customer cues are for context only.`;

      const sortedRubric = sortRubricDeterministically(rubricData);

      if (DEBUG_PROMPT_FLAG) {
        dlog(`[judge:${skillName}] whitelist size=${allowedQuotes.length} first3=`, allowedQuotes.slice(0,3));
        dlog(`[judge:${skillName}] customer_cues size=${(index?.customer_cues || []).length}`);
      }
      
      const judgeUser = buildAnalysisPrompt(
        skillName,
        rubricData,
        index,
        allowedQuotes
      );

      // --- DEBUG: prompt preview & rubric metrics ---
      if (DEBUG_PROMPT_FLAG) {
          const head = judgeUser.slice(0, 800);
          const tail = judgeUser.slice(-800);
          let checkCount = 0;
          for (const lvl of (rubricData?.levels || [])) {
            checkCount += Array.isArray(lvl?.checks) ? lvl.checks.length : 0;
          }
          console.log(`[judge:${skillName}] HEAD:\n${head}\n---\nTAIL:\n${tail}\n---`);
          console.log(`rubric_levels=${Array.isArray(rubricData?.levels)?rubricData.levels.length:0} rubric_checks=${checkCount} rubric_bytes=${bytes(JSON.stringify(rubricData))} quotes_allowed=${allowedQuotes.length} customer_cues=${(index?.customer_cues||[]).length}`);
        }
      // ----------------------------------------------

      // ---- 1) JUDGE ----------------------
      const judgeResp = await withRetry(() => chatOpenRouter(env, {
        model: env.JUDGE_MODEL,
        temperature: 0.1,
        max_tokens: 8000,
        tools: [{
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
                            reason: { type: "string" }
                          },
                          required: ["characteristic","polarity","met","evidence","reason"]
                        }
                      }
                    },
                    required: ["level","name","checks"]
                  }
                }
              },
              required: ["level_checks"]
            }
          }
        }],
        tool_choice: { type: "function", function: { name: "extract_rubric_analysis" }}, // <-- FORCE THE MODEL TO USE THE TOOL
        messages: [
          { role: "system", content: OR_SYSTEM_JUDGE },
          { role: "user", content: judgeUser }
        ],
        provider: providerPrefs(env)
      }, { hint: "judge" }), { retries: 1, baseMs: 350, factor: 1.6 });

      
      promptBytes += bytes(judgeUser);

      if (DEBUG_PROMPT_FLAG) {
        const blob = (judgeResp.content || judgeResp.raw || "");
        dlog(`[judge:${skillName}] served_by=${judgeResp.servedBy}`);
        dlog(`[judge:${skillName}] model content head:\n${blob.slice(0, 800)}\n---`);
        console.log(`[judge:${skillName}] model content head:\n${String(blob).slice(0,600)}\n---`);
        const raw = String(judgeResp.content || judgeResp.raw || "");
        const served = judgeResp.servedBy || "unknown";
        const chunkSize = 1000; // avoid truncation in dashboard
        console.log(`[judge:${skillName}] full JSON from model (served_by=${served}, length=${raw.length}):`);
        for (let i = 0; i < raw.length; i += chunkSize) {
          console.log(raw.slice(i, i + chunkSize));
        }
        console.log("--- END FULL JUDGE JSON ---");
      }
      

      function tryParse(obj) { try { return JSON.parse(obj); } catch { return null; } }

console.log(`[judge:${skillName}] typeof content=${typeof judgeResp?.content}`);
console.log(`[judge:${skillName}] raw content preview=`, JSON.stringify(judgeResp?.content)?.slice(0, 400));
console.log(`[judge:${skillName}] judgeResp.content length=${(judgeResp?.content || '').length}`);


// --- parse & normalize judge output ---
let parsedJudge = null;

try {
  if (typeof judgeResp?.content === "object" && judgeResp.content?.level_checks) {
    // Case 1: OpenRouter or model already returned a structured JSON object
    parsedJudge = judgeResp.content;

  } else if (judgeResp?.json?.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments) {
    // Case 2: Handle Tool Use response
    const toolArgs = judgeResp.json.choices[0].message.tool_calls[0].function.arguments;
    parsedJudge = JSON.parse(toolArgs);

  } else if (typeof judgeResp?.content === "string" && judgeResp.content.trim()) {
    // Case 3: Plain JSON string
    parsedJudge = JSON.parse(judgeResp.content);

  } else if (judgeResp?.json?.choices?.[0]?.message?.content) {
    // Case 4: Nested inside OpenAI-style response
    parsedJudge = JSON.parse(judgeResp.json.choices[0].message.content);

  } else if (judgeResp?.raw) {
    // Case 5: Fallback to raw text — extract first {...} block
    const match = String(judgeResp.raw).match(/\{[\s\S]*\}/);
    if (match) parsedJudge = JSON.parse(match[0]);
  }
} catch (e) {
  console.log(`[judge:${skillName}] parse fail`, e);
}

// --- Fallback and key normalization ---
if (!parsedJudge || typeof parsedJudge !== "object") parsedJudge = { level_checks: [] };

const lc = Array.isArray(parsedJudge.level_checks)
  ? parsedJudge.level_checks
  : Array.isArray(parsedJudge.levelChecks)
    ? parsedJudge.levelChecks
    : [];

parsedJudge = { level_checks: lc };
// --- end robust parse block ---


      // ---- Post-process -----------------------------------------------------
      const rawLevelChecks = JSON.parse(JSON.stringify(parsedJudge.level_checks));
      const checksWithObservableFlags = applyObservableFlags(parsedJudge.level_checks, rubricData);
      const rawNormalized = normalizePolarity(checksWithObservableFlags);

      const sellerQuotesSet = new Set((index?.seller_quotes || []).map(normalizeQ));
      let levelChecks = sanitizeEvidenceAgainstIndex(
        JSON.parse(JSON.stringify(rawNormalized)),
        sellerQuotesSet,
        transcript,
        new Set(allowedQuotes)
      );
      levelChecks = enforceNegativeGuard(levelChecks);

      // --- Limitation post-processing: set met=true if evidence matches limitation exactly ---
      function limitationPostProcess(levelChecks) {
        for (const lvl of levelChecks || []) {
          for (const check of (lvl.checks || [])) {
            if (check.polarity === 'limitation' && check.met === false && Array.isArray(check.evidence) && check.evidence.length > 0) {
              // If the evidence is not worse than the limitation, set met=true
              // Heuristic: if the evidence is present and matches the limitation description, set met=true
              // (This is a best-effort, as 'worse than' is subjective)
              const charNorm = String(check.characteristic || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
              const evNorm = check.evidence.map(e => String(e).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim());
              // If any evidence is a substring or equal to the characteristic, treat as 'same as'
              if (evNorm.some(e => charNorm && (e === charNorm || charNorm.includes(e) || e.includes(charNorm)))) {
                check.met = true;
                check.reason = `[AUTO-CORRECTED] Evidence matches limitation exactly; set met: true. Original reason: ${check.reason}`;
              }
            }
          }
        }
        return levelChecks;
      }
      levelChecks = limitationPostProcess(levelChecks);

      const ratingRaw = computeHighestDemonstrated(rawNormalized);
      const ratingSanitized = computeHighestDemonstrated(levelChecks);

      // Optional soft-floor logic retained
      const countMet = (checks) => checks.flatMap(l => l.checks || []).filter(c => c?.polarity !== "limitation" && c?.met === true).length;
      const metRaw = countMet(rawNormalized);
      const metAfter = countMet(levelChecks);
      const evidenceLossRatio = metRaw > 0 ? (metRaw - metAfter) / metRaw : 1;

      const LOSS_THRESHOLD = 0.6;
      const RAW_MIN_FOR_FLOOR = 3;
      const MAX_SOFT_FLOOR = 3;
      let rating = ratingSanitized;
      if (ratingSanitized <= 1 && ratingRaw >= RAW_MIN_FOR_FLOOR && evidenceLossRatio >= LOSS_THRESHOLD) {
        rating = Math.min(MAX_SOFT_FLOOR, Math.max(2, ratingRaw - 1));
      }

      const gating_summary = buildGatingSummary(levelChecks);

      // ---- 2) COACH (Enforcing the schema - CORRECTED) ------------------------
      const coachUser = buildCoachingPrompt(skillName, rating, levelChecks, gating_summary);
      promptBytes += bytes(coachUser);
   
      const coachResp = await withRetry(() => chatOpenRouter(env, {
        model: env.WRITER_MODEL || "o4-mini",
        temperature: 0.2,
        max_tokens: 4096,
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "coaching_feedback_schema",
            schema: {
              type: "object",
              additionalProperties: false, // <-- FIX: Added this line
              properties: {
                strengths: {
                  type: "array",
                  items: { type: "string" },
                },
                improvements: {
                  type: "array",
                  items: {
                    type: "object",
                    additionalProperties: false, // <-- FIX: Added this line
                    properties: {
                      point: { type: "string", description: "High-level area for improvement." },
                      example: {
                        type: "object",
                        additionalProperties: false, // <-- FIX: Added this line
                        properties: {
                          instead_of: { type: "string", description: "The seller's actual quote demonstrating the gap." },
                          try_this: { type: "string", description: "A better, alternative phrase the seller could have used." }
                        },
                        required: ["instead_of", "try_this"]
                      }
                    },
                    required: ["point", "example"]
                  }
                },
                coaching_tips: {
                  type: "array",
                  items: { type: "string" },
                }
              },
              required: ["strengths", "improvements", "coaching_tips"]
            }
          }
        },
        messages: [
          { role: "system", content: OR_SYSTEM_COACH },
          { role: "user", content: coachUser }
        ],
      }, { hint: "coach" }), { retries: 1 });

promptBytes += bytes(coachUser);


let strengths = [], improvements = [], coaching_tips = [];
try {
    // Robustly find and parse the JSON from the coach's response
    let coachObj = null;
    if (typeof coachResp.content === 'string' && coachResp.content.trim()) {
        coachObj = JSON.parse(coachResp.content);
    } else if (coachResp.json?.choices?.[0]?.message?.content) {
        coachObj = JSON.parse(coachResp.json.choices[0].message.content);
    } else if (coachResp.json?.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments) {
        // Handle cases where coach might use tool calls
        const toolArgs = coachResp.json.choices[0].message.tool_calls[0].function.arguments;
        coachObj = JSON.parse(toolArgs);
    }

    if (coachObj) {
        strengths = coachObj.strengths || [];
        // Directly assign the full improvements array with the nested 'example' objects
        improvements = coachObj.improvements || []; 
        coaching_tips = coachObj.coaching_tips || [];
    }
} catch (e) {
    console.log(`[coach:${skillName}] parse fail`, e);
    // Gracefully fail, leaving coaching fields empty if parsing fails
}

// populate the 'instead_of' quotes 👇
improvements = backfillImprovementQuotes(improvements, levelChecks);

      const ms = Date.now() - tA0;
      timing.assess_calls.push({ mode: "single_decoupled_or", skills: 1, ms, prompt_bytes: promptBytes, skill: skillName });
      timing.assess_ms_total += ms;
      timing.prompt_bytes_total += promptBytes;

      return attachDebug({
        skill: skillName, rating,
        strengths, improvements, coaching_tips,
        seller_identity: index?.seller_label || "Seller",
        level_checks: levelChecks, gating_summary,
        _debug: { ratingRaw, ratingSanitized, metRaw, metAfter, evidenceLossRatio },
        _raw_model_output: rawLevelChecks,
        _served_by: { judge: "meta-llama/llama-3.1-70b-instruct", coach: "openai/o4-mini" }
      }, { judgeResp, coachResp });
    }

    async function getAssessmentsBatched(apiKey, transcript, rubricsSubset, index) {
      const taskFns = [];
      for (const competency in rubricsSubset) {
        const comp = rubricsSubset[competency];
        if (!comp || !comp.skills) continue;
        for (const skillName in comp.skills) {
          const rubricData = comp.skills[skillName];
          const wl = selectWhitelistForSkill(
            index,
            skillName,
            WHITELIST_MAX,
            transcript,
            { maxQuoteWords: MAX_QUOTE_WORDS, enforce: ENFORCE_MAX_WORDS_IN_EVIDENCE }
          );
          taskFns.push(() => getAssessmentForSkill(apiKey, transcript, skillName, rubricData, index, wl, DEBUG_PROMPT_FLAG));
        }
      }
      const pooledResults = await runWithPool(taskFns, Math.min(MAX_CONCURRENCY, 3));
      return pooledResults.filter((r) => r && !r.__error);
    }

    // ===== ASSESSMENT EXECUTION =====
    let assessments = [];
    let assess_kv_hit = false;

    if ((env.ASSESS_MODE || "parallel").toLowerCase() === "batched") {
      // Build a tiny rubric subset from the skills we actually resolved
      const rubricsFiltered = { filtered: { skills: {} } };
      for (const { skillName, rubricData } of resolvedSkills) {
        rubricsFiltered.filtered.skills[skillName] = rubricData;
      }
    
      // Make a compact signature so cache invalidates if any rubric snippet changes
      const rubricSignature = await sha256Hex(stable(
        resolvedSkills.map(({ skillName, rubricData }) => ({ skillName, rubricData }))
      ));
    
      // Prefer stable keys: include indexKeyHash (ties to transcript) + skills list + rubricSignature
      const assessKeyInput = stable({
        v: CACHE_VERSION,
        ASSESS_MODEL: "openrouter",
        limits: {
          MIN_QUOTES_PER_POSITIVE_PASS,
          REQUIRE_DISTINCT_EVIDENCE,
          MAX_EVIDENCE_REUSE,
          ENFORCE_MAX_WORDS_IN_EVIDENCE,
          WHITELIST_MAX,
          BUCKETS_IN_PROMPT,
          BUCKET_SAMPLE_N,
        },
        indexKeyHash,               // already computed earlier for the index cache
        skills: presentSkills,      // only the skills we’ll assess
        rubricSignature             // hashes the rubrics so cache busts on rubric edits
      });
    
      const assessKeyHash = await sha256Hex(assessKeyInput);
      const assessKVKey = `v${CACHE_VERSION}:assess:${assessKeyHash}`;
    
      if (env.ASSESS_CACHE) {
        const cached = await kvGetJSON(env.ASSESS_CACHE, assessKVKey);
        if (cached && Array.isArray(cached.assessments)) {
          assessments = cached.assessments;
          assess_kv_hit = true;
        }
      }
    
      if (!assessments.length) {
        assessments = await getAssessmentsBatched(
          GEMINI_API_KEY,
          transcript,
          rubricsFiltered,   // <— only resolved skills
          index
        );
    
        if (assessments.length && env.ASSESS_CACHE) {
          await kvPutJSON(env.ASSESS_CACHE, assessKVKey, { assessments }, KV_TTL_SECS, CACHE_VERSION);
          await edgePutJSON(edgeKey("assess", assessKeyHash), { assessments });
        }
      }    
    } else {
      assessments = [];
    
      for (const { skillName, rubricData } of resolvedSkills) {
        const wl = selectWhitelistForSkill(
          index,
          skillName,
          WHITELIST_MAX,
          transcript,
          { maxQuoteWords: MAX_QUOTE_WORDS, enforce: ENFORCE_MAX_WORDS_IN_EVIDENCE }
        );
    
        const skillKeyHash = await sha256Hex(stable({
          v: CACHE_VERSION,
          assessModel: "openrouter",
          limits: { MIN_QUOTES_PER_POSITIVE_PASS, REQUIRE_DISTINCT_EVIDENCE, MAX_EVIDENCE_REUSE, ENFORCE_MAX_WORDS_IN_EVIDENCE },
          skillName,
          rubric: rubricData,
          whitelist: wl,
          indexKeyHash
        }));
    
        const kvKey = `v${CACHE_VERSION}:assess_skill:${skillKeyHash}`;
    
        let cached = null;
        if (env.ASSESS_CACHE) cached = await kvGetJSON(env.ASSESS_CACHE, kvKey);
    
        if (cached && cached.assessment && !cached.assessment.__error) {
          assessments.push(cached.assessment);
          assess_kv_hit = true;
        } else {
          const assessment = await getAssessmentForSkill(
            GEMINI_API_KEY,
            transcript,
            skillName,
            rubricData,
            index,
            wl,
            DEBUG_PROMPT_FLAG
          );
          assessments.push(assessment);
          if (env.ASSESS_CACHE) {
            await kvPutJSON(env.ASSESS_CACHE, kvKey, { assessment }, KV_TTL_SECS, CACHE_VERSION);
            await edgePutJSON(edgeKey("assess_skill", skillKeyHash), { assessment });
          }
        }
      }
    }
    
    // ===== Assemble Response =================================================
    const duration_ms = Date.now() - t0;

    const meta = {
      run_id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      duration_ms,
      assess_mode: ASSESS_MODE,
      assess_model: "openrouter",
      index_model: INDEX_MODEL,
      writer_model: env.WRITER_MODEL || "openai/o4-mini",
      judge_model: env.JUDGE_MODEL || "meta-llama/llama-3.1-70b-instruct",
      provider_order: (env.PROVIDER_ORDER || "fireworks,together,groq,google,openai"),
      allow_fallbacks: providerPrefs(env).allow_fallbacks,
      kv_enabled: !!env.ASSESS_CACHE,
      kv_index_hit: !!index_kv_hit,
      kv_assess_hit: !!assess_kv_hit,
      edge_warmed: !!WARM_EDGE_CACHE,
      timing,
      rubric_source,
      assessed_skills: presentSkills,
      missing_skills: missingSkills,
      limits: {
        MAX_SELLER_QUOTES,
        MAX_CUSTOMER_CUES,
        MAX_QUOTE_WORDS,
        MIN_QUOTES_PER_POSITIVE_PASS,
        REQUIRE_DISTINCT_EVIDENCE,
        MAX_EVIDENCE_REUSE,
        WHITELIST_MAX,
        BUCKETS_IN_PROMPT,
        BUCKET_SAMPLE_N
      }
    };
    
    return new Response(JSON.stringify({
      assessments,
      meta,
      seller_identity: index?.seller_label || "Seller"
    }), { headers });

  } catch (error) {
    console.error("handleFullAssessment error:", error);
    return new Response(JSON.stringify({ error: String(error?.message || error) }), { status: 500, headers });
  }
}
