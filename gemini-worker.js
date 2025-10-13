// sales-coach-worker.js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // -------- CORS ----------
    const allowOrigin = (env.ALLOW_ORIGIN && String(env.ALLOW_ORIGIN)) || "*";
    const headers = new Headers({
      "Access-Control-Allow-Origin": allowOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Content-Type": "application/json",
    });
    if (request.method === "OPTIONS") return new Response(null, { headers });

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

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers });
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
      const ASSESS_MODEL = (env.ASSESS_MODEL || "gemini-2.5-pro").trim();
      const ASSESS_MODE  = (env.ASSESS_MODE  || "parallel").toLowerCase();

      const MAX_CONCURRENCY   = num(env.MAX_CONCURRENCY, 4);
      const MAX_RUBRICS_BYTES = num(env.MAX_RUBRICS_BYTES, 1_000_000);
      const MAX_SKILLS_CAP    = num(env.MAX_SKILLS_CAP, 50);

      const ASSESS_RETRY_MAX       = num(env.ASSESS_RETRY_MAX, 1);
      const ASSESS_RETRY_BASE_MS   = num(env.ASSESS_RETRY_BASE_MS, 700);

      const MIN_QUOTES_PER_POSITIVE_PASS  = num(env.MIN_QUOTES_PER_POSITIVE_PASS, 1);
      const MIN_QUOTES_PER_HIGH_LEVEL_PASS = num(env.MIN_QUOTES_PER_HIGH_LEVEL_PASS, 1);
      const HIGH_LEVEL_START               = num(env.HIGH_LEVEL_START, 4);

      // Fuzzy matching knobs (only used if present; otherwise fallback defaults)
      const EVIDENCE_FUZZ      = num(env.EVIDENCE_FUZZ, 0.78);
      const NGRAM_N            = num(env.NGRAM_N, 3);
      const NGRAM_THRESHOLD    = num(env.NGRAM_THRESHOLD, 0.6);
      const SOFT_CONTAINS_MIN  = num(env.SOFT_CONTAINS_MIN, 10);
    
      
      const REQUIRE_DISTINCT_EVIDENCE     = bool(env.REQUIRE_DISTINCT_EVIDENCE, false);
      const MAX_EVIDENCE_REUSE            = num(env.MAX_EVIDENCE_REUSE, 5);
      const ENFORCE_MAX_WORDS_IN_EVIDENCE = bool(env.ENFORCE_MAX_WORDS_IN_EVIDENCE, true);

      const MAX_SELLER_QUOTES = num(env.MAX_SELLER_QUOTES, 40);
      const MAX_CUSTOMER_CUES = num(env.MAX_CUSTOMER_CUES, 20);
      const MAX_QUOTE_WORDS   = num(env.MAX_QUOTE_WORDS, 50);

      const INDEX_SEGMENT_CHARS      = num(env.INDEX_SEGMENT_CHARS, 3000);
      const INDEX_SEGMENT_MAX        = num(env.INDEX_SEGMENT_MAX, 10);
      const INDEX_SPLIT_MAX_DEPTH    = num(env.INDEX_SPLIT_MAX_DEPTH, 3);
      
      const WHITELIST_MAX     = num(env.WHITELIST_MAX, 24);
      const BUCKETS_IN_PROMPT = String(env.BUCKETS_IN_PROMPT || "none").toLowerCase();
      const BUCKET_SAMPLE_N   = num(env.BUCKET_SAMPLE_N, 3);

      const GEMINI_TIMEOUT_MS   = num(env.GEMINI_TIMEOUT_MS, 120000);
      const INDEX_RETRY_MAX     = num(env.INDEX_RETRY_MAX, 3);
      const INDEX_RETRY_BASE_MS = num(env.INDEX_RETRY_BASE_MS, 800);

      const CACHE_VERSION   = String(env.CACHE_VERSION || "1");
      const KV_TTL_SECS     = num(env.KV_TTL_SECS,    60 * 60 * 24 * 14);
      const EDGE_TTL_SECS   = num(env.EDGE_TTL_SECS,  60 * 60 * 24 * 7);
      const WARM_EDGE_CACHE = bool(env.WARM_EDGE_CACHE, true);

      // ===== Parse body =====
      const body = await request.json();
      let { transcript, rubrics, rubrics_url, skills, include_presentation, rubric_version } = body || {};
      if (!transcript && typeof body?.transcript === "string") transcript = body.transcript;
      
      if (!rubrics && rubrics_url) {
        if (!/^https:\/\/.+/i.test(rubrics_url)) { return new Response(JSON.stringify({ error: "rubrics_url must be HTTPS" }), { status: 400, headers }); }
        const rubricsRes = await fetch(rubrics_url, { method: "GET" });
        const ct = (rubricsRes.headers.get("content-type") || "").toLowerCase();
        if (!ct.includes("application/json")) { return new Response(JSON.stringify({ error: "rubrics_url did not return JSON" }), { status: 400, headers }); }
        const rubricsText = await rubricsRes.text();
        if (rubricsText.length > MAX_RUBRICS_BYTES) { return new Response(JSON.stringify({ error: `rubrics JSON too large (>${MAX_RUBRICS_BYTES} bytes)` }), { status: 400, headers }); }
        try { rubrics = JSON.parse(rubricsText); }
        catch { return new Response(JSON.stringify({ error: "Invalid JSON from rubrics_url" }), { status: 400, headers }); }
      }

      const rubricSetParam = url.searchParams.get("rubric_set");
      const skillsParamQS  = url.searchParams.get("skills");
      const competencyQS   = url.searchParams.get("competency");

      if (!Array.isArray(skills) && typeof skillsParamQS === "string") {
        skills = skillsParamQS.split(",").map((s) => s.trim()).filter(Boolean);
      }

      if (!rubrics && rubricSetParam) {
        if (!env.RUBRICS) return new Response(JSON.stringify({ error: "KV binding RUBRICS missing" }), { status: 500, headers });
        let kvVal = await env.RUBRICS.get(rubricSetParam, "text");
        if (!kvVal) return new Response(JSON.stringify({ error: `rubric_set not found in KV: ${rubricSetParam}` }), { status: 404, headers });
        if (/^rubrics:/.test(kvVal.trim())) {
          const aliasVal = await env.RUBRICS.get(kvVal.trim(), "text");
          if (aliasVal) kvVal = aliasVal;
        }
        if (kvVal.length > MAX_RUBRICS_BYTES) { return new Response(JSON.stringify({ error: `KV rubrics too large (>${MAX_RUBRICS_BYTES} bytes)` }), { status: 400, headers }); }
        try { rubrics = JSON.parse(kvVal); }
        catch { return new Response(JSON.stringify({ error: "Invalid JSON in KV rubric_set" }), { status: 400, headers }); }
      }

      if (rubrics && competencyQS) {
        const comp = rubrics[competencyQS];
        if (!comp?.skills) { return new Response(JSON.stringify({ error: `Unknown competency: ${competencyQS}` }), { status: 400, headers }); }
        rubrics = { [competencyQS]: { skills: comp.skills } };
      }

      if (!transcript || !rubrics) {
        return new Response(JSON.stringify({ error: "Missing 'transcript' or 'rubrics' in request body." }), { status: 400, headers });
      }

      // ===== Helpers =====
      const googleURL = (model) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
      function num(v, d) { const n = Number(v); return Number.isFinite(n) ? n : d; }
      function bool(v, d) { if (v === undefined || v === null) return d; const s = String(v).toLowerCase().trim(); return s === "true" || s === "1" || s === "yes"; }
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
        const { hint = "upstream", timeoutMs = GEMINI_TIMEOUT_MS } = options;
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
        const s = await ns.get(key);
        if (!s) return null;
        try { return JSON.parse(s); } catch { return null; }
      }
      async function kvPutJSON(ns, key, obj, ttlSecs) {
        await ns.put(key, JSON.stringify(obj), {
          expirationTtl: ttlSecs,
          metadata: { createdAt: Date.now(), version: CACHE_VERSION },
        });
      }
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
      const BUCKET_ORDER = [ "ask_probe", "clarify_validate", "summarize_synthesize", "empathize_label", "quantify_measure", "connect_link", "document_commit", "explain_teach", "position_value", "other" ];
      function getQuotePosMap(transcript, quotes) {
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
      async function buildAssessSkillKeyHash({ cacheVersion, assessModel, minQuotesPerPositivePass, requireDistinctEvidence, maxEvidenceReuse, enforceMaxWords, bucketsInPrompt, bucketSampleN, skillName, rubricData, whitelist, indexKeyHash }) {
        const input = {
          v: String(cacheVersion || "1"),
          assessModel: String(assessModel || ""),
          limits: { minQuotesPerPositivePass: Number(minQuotesPerPositivePass || 0), requireDistinctEvidence: !!requireDistinctEvidence, maxEvidenceReuse: Number(maxEvidenceReuse || 0), enforceMaxWords: !!enforceMaxWords, bucketsInPrompt: String(bucketsInPrompt || "none"), bucketSampleN: Number(bucketSampleN || 0) },
          skillName: String(skillName || ""),
          rubric: rubricData || {},
          whitelist: (whitelist || []).map(String),
          indexKeyHash: String(indexKeyHash || "")
        };
        const stableStr = stable(input);
        return await sha256Hex(stableStr);
      }
      function normalizeQuote(q) {
        const t = String(q || "").replace(/\s+/g, " ").trim();
        if (!t) return "";
        const MAX_QW = Number(env.MAX_QUOTE_WORDS || 50);
        const ENFORCE = bool(env.ENFORCE_MAX_WORDS_IN_EVIDENCE, true);
        if (!ENFORCE) return t;
        const words = t.split(" ");
        if (words.length <= MAX_QW) return t;
        return words.slice(0, MAX_QW).join(" ");
      }
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

      function sortQuotesDeterministic(arr) {
        const uniq = [...new Set((arr || []).map(normalizeQuote).filter(Boolean))];
        return uniq.sort((a, b) => {
          const lc = a.toLowerCase().localeCompare(b.toLowerCase());
          return lc !== 0 ? lc : (a.length - b.length);
        });
      }

      function isCustomerEvidenceRequired(characteristicText) {
        const lowerText = String(characteristicText || '').toLowerCase();
        if (!lowerText) return false;
      
        // Keywords that indicate the seller's performance is a reaction to the customer
        const keywords = [
          'prompting', 'prompted', 
          'guidance', 
          'support', 
          'feedback', 
          'objections', 
          'cues', 
          'led by'
        ];
      
        return keywords.some(keyword => lowerText.includes(keyword));
      }

      function isCharacteristicObservable(characteristicText) {
        // Keywords indicating actions not observable in a transcript.
        // Using word boundaries (\b) to prevent matching substrings (e.g., 'send' in 'sending').
          const NON_OBSERVABLE_KEYWORDS = [
            'document', 'documents', 'documented', 'documentation',
            'write', 'writes', 'written',
            'update', 'updates', 'updated',
            'schedule', 'schedules', 'scheduled',
            'send', 'sends', 'sent',
            'log', 'logs', 'logged',
            'report', 'reports', 'reported',
            'crm', 'email', 'calendar', 'invite',
            'follow-up', 'follow up'
        ];
        const lowerText = String(characteristicText || '').toLowerCase();
        if (!lowerText) return true; // Default to observable if empty.

        // Return true if the text is observable (i.e., does NOT contain any non-observable keywords).
        return !NON_OBSERVABLE_KEYWORDS.some(keyword => {
            const regex = new RegExp(`\\b${keyword}\\b`);
            return regex.test(lowerText);
        });
      }

      function applyObservableFlags(modelChecks, originalRubric) {
        const characteristicMap = new Map();
        // 1. Build a map of characteristics to their observability status from the original rubric.
        for (const level of originalRubric?.levels || []) {
            for (const check of level?.checks || []) {
                const characteristic = String(check.characteristic || '').trim();
                if (!characteristic) continue;

                // Determine observability with a clear priority:
                // Priority 1: An explicit `observable` boolean set in the rubric JSON.
                // Priority 2: Our keyword-based detection for common non-observable actions.
                // Priority 3: Default to true (observable).
                let isObservable;
                if (typeof check.observable === 'boolean') {
                    isObservable = check.observable;
                } else {
                    isObservable = isCharacteristicObservable(characteristic);
                }
                characteristicMap.set(characteristic, isObservable);
            }
        }

        // 2. Iterate over the model's output and apply the mapped observability flag.
        const processedChecks = JSON.parse(JSON.stringify(modelChecks));
        for (const level of processedChecks || []) {
            for (const check of level?.checks || []) {
                const characteristic = String(check.characteristic || '').trim();
                // Look up the flag from our map. Default to `true` if it was somehow missing from the original rubric.
                check.observable = characteristicMap.get(characteristic) ?? true;
            }
        }
        return processedChecks;
      }

      function orderIndexMap(quotes) {
        const m = new Map();
        (quotes || []).forEach((q, i) => m.set(q, i));
        return m;
      }
      
      function normalizeChecks(levels) {
        for (const lvl of levels || []) {
          for (const c of (lvl.checks || [])) {
            if (typeof c.observable !== "boolean") c.observable = true;
          }
        }
        return levels;
      }

      function sanitizeEvidenceAgainstIndex(skillLevels, sellerQuotesSet, transcriptText, allowlist) {
        const rawTranscript  = transcriptText || "";
        const normTranscript = normalize(rawTranscript);
      
        const sellerQuotes = new Set(
          Array.from(sellerQuotesSet || new Set())
            .map(normalize)
            .filter(Boolean)
        );
      
        // normalize allowlist (SOFT allow)
        const allowSet = (() => {
          if (!allowlist) return null;
          const arr = allowlist instanceof Set ? Array.from(allowlist)
                   : Array.isArray(allowlist) ? allowlist : [];
          const s = new Set(arr.map(normalize).filter(Boolean));
          return s.size ? s : null;
        })();
      
        const getMinForLevel = (level) =>
          (Number(level) >= HIGH_LEVEL_START
            ? MIN_QUOTES_PER_HIGH_LEVEL_PASS
            : MIN_QUOTES_PER_POSITIVE_PASS);
      
        let totalBefore = 0, totalAfter = 0;
      
        // --- IMPORTANT: make allowlist soft, not a hard gate
        const hasQuote = (q) => {
          if (!q || typeof q !== "string") return false;
          const n = normalize(q);
          if (!n) return false;
      
          // If on allowlist, accept immediately
          if (allowSet && allowSet.has(n)) return true;
      
          // 1) exact vs transcript
          if (normTranscript.includes(n)) return true;
      
          // 2) exact vs indexed seller quotes
          if (sellerQuotes.has(n)) return true;
      
          // 3) fuzzy vs seller quotes
          for (const s of sellerQuotes) {
            if (
              tokenSim(n, s) >= EVIDENCE_FUZZ ||
              softContains(s, n, SOFT_CONTAINS_MIN) ||
              softContains(n, s, SOFT_CONTAINS_MIN)
            ) return true;
          }
      
          // 4) n-gram containment vs transcript for longer quotes
          if (n.length > 40 && ngramContainment(n, normTranscript, NGRAM_N) >= NGRAM_THRESHOLD) return true;
      
          return false;
        };
      
        for (const lvl of (skillLevels || [])) {
          const L   = Number(lvl.level) || 0;
          const MIN = getMinForLevel(L);
      
          // --- IMPORTANT: throttle evidence reuse **within a level** only
          const reuseCounter = new Map();
      
          for (const check of (lvl.checks || [])) {
            const ev = Array.isArray(check.evidence) ? check.evidence : [];
            totalBefore += ev.length;
      
            const kept = ev.map(normalize).filter(hasQuote);
      
            // cap reuse across checks (but only within this level)
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
      
        // ------------ helpers ------------
        function normalize(s) {
          return String(s || "")
            .toLowerCase()
            .replace(/[\u2018\u2019]/g, "'")
            .replace(/[\u201c\u201d]/g, '"')
            .replace(/[^a-z0-9\s\?]/g, " ")
            .replace(/\s+/g, " ")
            .trim();
        }
      
        function tokenSim(a, b) {
          const A = new Set(a.split(" ").filter(Boolean));
          const B = new Set(b.split(" ").filter(Boolean));
          const inter = [...A].filter(x => B.has(x)).length;
          const denom = Math.max(A.size, B.size) || 1;
          return inter / denom; // Jaccard-ish token overlap
          }
      
        function softContains(longer, shorter, minLen) {
          if (!longer || !shorter) return false;
          if (shorter.length < (minLen || 10)) return longer.includes(shorter);
          const lw = longer.split(" ").filter(Boolean);
          const sw = shorter.split(" ").filter(Boolean);
          let i = 0;
          for (const w of sw) {
            while (i < lw.length && lw[i] !== w) i++;
            if (i === lw.length) return false;
            i++;
          }
          return true;
        }
      
        function ngramContainment(q, corpus, n) {
          const toksQ = q.split(" ").filter(Boolean);
          if (toksQ.length < n) return 0;
          const grams = new Set();
          for (let i = 0; i <= toksQ.length - n; i++) grams.add(toksQ.slice(i, i + n).join(" "));
          let hit = 0;
          for (const g of grams) if (corpus.includes(g)) hit++;
          return grams.size ? hit / grams.size : 0;
        }
      }      
      
      function computeStrictRating(levels) {
        if (!Array.isArray(levels) || levels.length === 0) return 1;
        const normalized = normalizeChecks(levels);
        let highest = 0;
        for (const lvl of normalized) {
          const positives = (lvl.checks || []).filter(
            c => (c.polarity || "positive") === "positive" && (c?.observable ?? true) === true
          );
          if (positives.length === 0) { highest = Math.max(highest, lvl.level || 0); continue; }
          const requiredQuotes =
            (lvl.level >= HIGH_LEVEL_START) ? MIN_QUOTES_PER_HIGH_LEVEL_PASS : MIN_QUOTES_PER_POSITIVE_PASS;
          const allMet = positives.every(c => c.met === true && Array.isArray(c.evidence) && c.evidence.length >= requiredQuotes);
          if (allMet) {
            highest = Math.max(highest, lvl.level || 0);
          } else {
            break;
          }
        }
        return highest > 0 ? highest : 1;
      }
  
      function buildGatingSummary(levels) {
        const normalized = normalizeChecks(JSON.parse(JSON.stringify(levels || [])));
        const sorted = [...normalized].sort((a,b)=> (a.level||0)-(b.level||0));
        const highest = computeHighestDemonstrated(sorted);
        const out = [];
        for (const lvl of sorted) {
          const rq = levelRequiredQuotes(lvl.level || 0);
          const positives = (lvl.checks || []).filter(
            c => (c.polarity || "positive") === "positive" && (c?.observable ?? true) === true
          );
          const metDirect = positives.filter(c => c.met && (c.evidence||[]).length >= rq)
                                     .map(c => c.characteristic);
          const attainedViaHigher = (lvl.level <= highest)
            ? positives.filter(c => !(c.met && (c.evidence||[]).length >= rq))
                       .map(c => c.characteristic)
            : [];
          const unmet = (lvl.level > highest)
            ? positives.filter(c => !(c.met && (c.evidence||[]).length >= rq))
                       .map(c => c.characteristic)
            : [];
          out.push({
            level: lvl.level,
            name:  lvl.name,
            positives_met: metDirect,
            positives_unmet: unmet,
            positives_attained_via_higher: attainedViaHigher
          });
        }
        return out;
      }      

      function countSkills(r) {
        let n = 0;
        for (const comp in r || {}) {
          const skills = r[comp]?.skills;
          if (skills) n += Object.keys(skills).length;
        }
        return n;
      }

      function pickSelectedRubrics(r, skillsParam) {
        if (!Array.isArray(skillsParam) || !skillsParam.length) return r;
        const setRaw = new Set(skillsParam.map((s) => String(s)));
        const out = {};
        for (const comp in r || {}) {
          const compSkills = r[comp]?.skills;
          if (!compSkills) continue;
          for (const skill in compSkills) {
            const keyA = skill, keyB = `${comp}|${skill}`;
            if (setRaw.has(keyA) || setRaw.has(keyB)) {
              if (!out[comp]) out[comp] = { skills: {} };
              out[comp].skills[skill] = compSkills[skill];
            }
          }
        }
        return out;
      }

      function correctInconsistentMetStatus(levels) {
        const corrected = JSON.parse(JSON.stringify(levels));
        for (const level of corrected) {
            if (!level.checks) continue;
            for (const check of level.checks) {
                const hasEvidence = check.evidence && check.evidence.length > 0;
                if (check.met === true && !hasEvidence) {
                    check.met = false;
                    check.reason = `[AUTO-CORRECTED] 'met' was true but no evidence was found. Original reason: ${check.reason}`;
                }
            }
        }
        return corrected;
      }

      function extractFnCall(resp) {
        const cands = resp?.candidates || [];
        for (const c of cands) {
          const parts = c?.content?.parts || [];
          for (const p of parts) {
            if (p?.functionCall?.name && p?.functionCall?.args) return p.functionCall;
          }
        }
        return null;
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

      function selectWhitelistForSkill(index, skillName, maxN = WHITELIST_MAX, transcript = "") {
        const all = (index?.seller_quotes || []).map(normalizeQuote).filter(Boolean);
        if (!all.length) return [];
        const posMap = getQuotePosMap(transcript, all);
        const eb = index?.evidence_buckets || {};
        const picked = [];
        const seen = new Set();
        for (const b of BUCKET_ORDER) {
          const inBucket = (eb[b] || []).map(normalizeQuote).filter(q => q && all.includes(q)).sort((a, bq) => (posMap.get(a) || 1e15) - (posMap.get(bq) || 1e15));
          for (const q of inBucket) {
            if (!seen.has(q)) {
              picked.push(q);
              seen.add(q);
              if (picked.length >= maxN) return picked;
            }
          }
        }
        const remaining = all.filter(q => !seen.has(q)).sort((a, bq) => (posMap.get(a) || 1e15) - (posMap.get(bq) || 1e15));
        for (const q of remaining) {
          picked.push(q);
          if (picked.length >= maxN) break;
        }
        return picked;
      }

      function levelRequiredQuotes(lvlNum) {
        return (lvlNum >= HIGH_LEVEL_START)
          ? MIN_QUOTES_PER_HIGH_LEVEL_PASS
          : MIN_QUOTES_PER_POSITIVE_PASS;
      }
      
      function didPassLevelPositives(lvl) {
        if (!lvl || !Array.isArray(lvl.checks)) return true; // Gracefully handle empty levels
      
        const rq = levelRequiredQuotes(lvl.level || 0);
      
        // Condition 1: All observable 'positive' characteristics must be met.
        const positives = lvl.checks.filter(
          c => (c.polarity || "positive") === "positive" && (c?.observable ?? true) === true
        );
        const allPositivesMet = positives.length === 0 || positives.every(c => c.met === true && Array.isArray(c.evidence) && c.evidence.length >= rq);
      
        // Condition 2: All observable 'limitation' characteristics must also be met.
        const limitations = lvl.checks.filter(
          c => c.polarity === "limitation" && (c?.observable ?? true) === true
        );
        const allLimitationsMet = limitations.every(c => c.met === true);
      
        // A level is only passed if BOTH conditions are true.
        return allPositivesMet && allLimitationsMet;
      }
      
      // highest demonstrated level (attainment)
      function computeHighestDemonstrated(levels) {
        if (!Array.isArray(levels) || levels.length === 0) return 1;
        const normalized = normalizeChecks(levels);
        const sorted = [...normalized].sort((a,b) => (a.level||0)-(b.level||0));
        let highest = 0;
        for (const lvl of sorted) {
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
          const qs = selectWhitelistForSkill(index, name, maxN, transcript);
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
        const customerLabel = sellerLabel === 'User' ? 'Agent' : 'User';
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

      // ===== NEW TWO-STEP ASSESSMENT PROMPTS AND TOOLS =====

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
      You are an expert AI Sales Coach. You have been provided with a pre-computed, strict analysis of a seller's performance on the skill "${skillName}". Their final rating was ${rating}/5.
      
      The detailed, check-by-check analysis is as follows:
      ${stable({ level_checks: levelChecks, gating_summary: gatingSummary })}
      
      YOUR TASK:
      Based ONLY on the analysis provided above, generate the qualitative feedback. Do not re-evaluate the transcript.
      - Return ONLY a function call to 'extract_coaching_feedback'.
      - Write 2-4 clear "Strengths Exhibited" that demonstrate proficiency, especially focusing on the characteristics that were met at the highest achieved levels. If the score is low, find at least one foundational attempt to highlight.
      - Write 3-5 specific "Areas for Improvement". These should be based on the positive characteristics that were NOT met at the next level up. For each point, select the MOST RELEVANT seller quote from the provided evidence in the checks to use as an example.
      - Write 3-6 actionable "Coaching Tips" that directly relate to the areas for improvement.
      
      The output should be concise, constructive, and directly reflect the provided data.`;
      }

      const analysisTool = {
        functionDeclarations: [{
            name: "extract_analysis",
            description: "Return STRICT per-characteristic checks with seller-only evidence.",
            parameters: {
                type: "OBJECT",
                properties: {
                    level_checks: {
                        type: "ARRAY",
                        items: {
                            type: "OBJECT",
                            properties: {
                                level: { type: "NUMBER" },
                                name: { type: "STRING" },
                                checks: {
                                    type: "ARRAY",
                                    items: {
                                        type: "OBJECT",
                                        properties: {
                                            characteristic: { type: "STRING" },
                                            polarity: { type: "STRING" },
                                            met: { type: "BOOLEAN" },
                                            evidence: { type: "ARRAY", items: { type: "STRING" } },
                                            reason: { type: "STRING" },
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
        }],
      };
      
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
        functionDeclarations: [ { name: "index_transcript", description: "Identify the seller and extract seller-only quotes (no paraphrase). Also bucket quotes by generic behavior types. KEEP OUTPUT SMALL.", parameters: { type: "OBJECT", properties: { seller_label: { type: "STRING" }, seller_quotes: { type: "ARRAY", items: { type: "STRING" } }, customer_cues: { type: "ARRAY", items: { type: "STRING" } }, evidence_buckets: { type: "OBJECT", properties: { ask_probe: { type: "ARRAY", items: { type: "STRING" } }, clarify_validate: { type: "ARRAY", items: { type: "STRING" } }, summarize_synthesize: { type: "ARRAY", items: { type: "STRING" } }, empathize_label: { type: "ARRAY", items: { type: "STRING" } }, quantify_measure: { type: "ARRAY", items: { type: "STRING" } }, connect_link: { type: "ARRAY", items: { type: "STRING" } }, document_commit: { type: "ARRAY", items: { type: "STRING" } }, explain_teach: { type: "ARRAY", items: { type: "STRING" } }, position_value: { type: "ARRAY", items: { type: "STRING" } }, other: { type: "ARRAY", items: { type: "STRING" } }, }, }, }, required: ["seller_label", "seller_quotes", "customer_cues", "evidence_buckets"], }, }, ],
      };

      // ===== Gemini calls =====
      async function callGeminiIndex(apiKey, transcriptPart) {
        const hasAgentUserLabels = transcriptPart.includes("Agent:") && transcriptPart.includes("User:");
        let prompt;
    
        if (hasAgentUserLabels) {
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
          safetySettings: [ { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" }, { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" }, { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" }, { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" }, ],
        };
        const result = await withRetry( () => fetchJSON(googleURL(INDEX_MODEL), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(requestBody) }), { retries: INDEX_RETRY_MAX, baseMs: INDEX_RETRY_BASE_MS } );
        const call = extractFnCall(result);
        if (!(call && call.args)) {
          const finishReason = result?.candidates?.[0]?.finishReason || "No reason provided.";
          throw new Error("Transcript indexing failed. Reason: " + finishReason);
        }
        return call.args;
      }

      // ===== NEW TWO-STEP ASSESSMENT LOGIC =====
async function getAssessmentForSkill(apiKey, transcript, skillName, rubricData, index, wl) {
  const allowedQuotes = Array.isArray(wl) && wl.length
    ? wl.map(normalizeQuote).filter(Boolean)
    : (index?.seller_quotes || []).map(normalizeQuote).filter(Boolean);

  const tA0 = Date.now();
  let promptBytes = 0;

  const analysisPrompt = buildAnalysisPrompt(skillName, rubricData, index, allowedQuotes);
  promptBytes += bytes(analysisPrompt);

  const analysisResult = await withRetry(() => fetchJSON(googleURL(ASSESS_MODEL), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: analysisPrompt }] }],
      tools: [analysisTool],
      toolConfig: { functionCallingConfig: { mode: "ANY" } },
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
    }),
  }), { retries: ASSESS_RETRY_MAX, baseMs: ASSESS_RETRY_BASE_MS });

  const analysisCall = analysisResult?.candidates?.[0]?.content?.parts?.[0]?.functionCall;
  if (!analysisCall?.args?.level_checks) {
    throw new Error(`Analysis step failed for skill "${skillName}". Reason: ${analysisResult?.candidates?.[0]?.finishReason || "No function call."}`);
  }

  const rawLevelChecks = JSON.parse(JSON.stringify(analysisCall.args.level_checks));

  // --- Apply observability flags before any processing or rating calculation ---
  const checksWithObservableFlags = applyObservableFlags(analysisCall.args.level_checks, rubricData);

  // --- normalize once, keep both RAW and SANITIZED branches
  const rawNormalized = normalizePolarity(checksWithObservableFlags); // Use the processed checks
  const sellerQuotesSet = new Set((index?.seller_quotes || []).map(normalizeQuote));
  
  // Strict sanitization (enforce allowlist)
  let levelChecks = sanitizeEvidenceAgainstIndex(
    JSON.parse(JSON.stringify(rawNormalized)),
    sellerQuotesSet,
    transcript,
    new Set(allowedQuotes)
  );
  levelChecks = enforceNegativeGuard(levelChecks);

  // --- Consistency guard: compare pre/post-sanitization
  const ratingRaw = computeHighestDemonstrated(rawNormalized);
  const ratingSanitized = computeHighestDemonstrated(levelChecks);

  const countMet = (checks) =>
    checks.flatMap(l => l.checks || []).filter(c => c?.polarity !== "limitation" && c?.met === true).length;

  const metRaw = countMet(rawNormalized);
  const metAfter = countMet(levelChecks);

  const evidenceLossRatio = metRaw > 0 ? (metRaw - metAfter) / metRaw : 1;

  // If sanitization wiped most positives and cratered the score,
  // apply a soft floor so we don't report absurd 1/5s on clearly decent calls.
  // Tunables:
  const LOSS_THRESHOLD = 0.6; // >60% positives disappeared
  const RAW_MIN_FOR_FLOOR = 3; // model thought at least "Progressing"
  const MAX_SOFT_FLOOR = 3;    // don't overcorrect past 3/5

  let rating = ratingSanitized;
  if (ratingSanitized <= 1 && ratingRaw >= RAW_MIN_FOR_FLOOR && evidenceLossRatio >= LOSS_THRESHOLD) {
    rating = Math.min(MAX_SOFT_FLOOR, Math.max(2, ratingRaw - 1));
  }

  const gating_summary = buildGatingSummary(levelChecks);

  const coachingPrompt = buildCoachingPrompt(skillName, rating, levelChecks, gating_summary);
  promptBytes += bytes(coachingPrompt);

  const coachingResult = await withRetry(() => fetchJSON(googleURL(ASSESS_MODEL), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ role: "user", parts: [{ text: coachingPrompt }] }],
      tools: [coachingTool],
      toolConfig: { functionCallingConfig: { mode: "ANY" } },
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
    }),
  }), { retries: ASSESS_RETRY_MAX, baseMs: ASSESS_RETRY_BASE_MS });

  const ms = Date.now() - tA0;
  timing.assess_calls.push({ mode: "single_decoupled", skills: 1, ms, prompt_bytes: promptBytes, skill: skillName });
  timing.assess_ms_total += ms;
  timing.prompt_bytes_total += promptBytes;

  const coachingCall = coachingResult?.candidates?.[0]?.content?.parts?.[0]?.functionCall;
  if (!coachingCall?.args) {
    console.error(`Coaching step failed for skill "${skillName}". Reason: ${coachingResult?.candidates?.[0]?.finishReason || "No function call."}`);
    return {
      skill: skillName,
      rating,
      level_checks: levelChecks,
      gating_summary,
      strengths: [],
      improvements: [],
      coaching_tips: [],
      seller_identity: index?.seller_label || "Seller",
      // Helpful debug for your logs:
      _debug: { ratingRaw, ratingSanitized, metRaw, metAfter, evidenceLossRatio },
      _raw_model_output: rawLevelChecks,
    };
  }

  const { strengths, improvements, coaching_tips } = coachingCall.args;

  return {
    skill: skillName,
    rating,
    strengths: strengths || [],
    improvements: improvements || [],
    coaching_tips: coaching_tips || [],
    seller_identity: index?.seller_label || "Seller",
    level_checks: levelChecks,
    gating_summary,
    // Helpful debug for your logs:
    _debug: { ratingRaw, ratingSanitized, metRaw, metAfter, evidenceLossRatio },
    _raw_model_output: rawLevelChecks,
  };
}



      // ===== CORRECTED BATCHED ASSESSMENT LOGIC =====
      async function getAssessmentsBatched(apiKey, transcript, rubricsSubset, index) {
        const taskFns = [];
        for (const competency in rubricsSubset) {
          const comp = rubricsSubset[competency];
          if (!comp || !comp.skills) continue;
          for (const skillName in comp.skills) {
            const rubricData = comp.skills[skillName];
            const wl = selectWhitelistForSkill(index, skillName, WHITELIST_MAX, transcript);
            taskFns.push(() => getAssessmentForSkill(apiKey, transcript, skillName, rubricData, index, wl));
          }
        }
        const pooledResults = await runWithPool(taskFns, Math.min(MAX_CONCURRENCY, 3));
        return pooledResults.filter((r) => r && !r.__error);
      }

      // ===== Concurrency =====
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

      // ===== Index segmentation =====
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
                      if (currentSubTurnText) {
                          subTurns.push({ speaker, text: currentSubTurnText.trim() });
                      }
                      currentSubTurnText = sentence;
                  } else {
                      currentSubTurnText += sentence;
                  }
              }
              if (currentSubTurnText) {
                  subTurns.push({ speaker, text: currentSubTurnText.trim() });
              }
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
      
          if (currentChunk.length > 0) {
              chunks.push(currentChunk.trim());
          }
      
          return chunks.slice(0, maxParts);
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
        const order = orderIndexMap(out.seller_quotes);

        for (const k of BUCKET_ORDER) {
          const validQuotesInBucket = [...allBucketedEvidence[k]].map(normalizeQuote).filter(q => finalSellerQuotesSet.has(q));
          out.evidence_buckets[k] = validQuotesInBucket.sort((a, b) => order.get(a) - order.get(b)).slice(0, maxSeller);
        }
        
        return out;
      }

      async function adaptiveIndexSingle(apiKey, part, depth = 0) {
          try {
              return await callGeminiIndex(apiKey, part);
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
                          adaptiveIndexSingle(apiKey, a, depth + 1),
                          adaptiveIndexSingle(apiKey, b, depth + 1),
                      ]);
                      return mergeIndexes([idxA, idxB], MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);
                  }
              }
              throw e;
          }
      }

      async function indexTranscriptSmart(apiKey, transcriptFull) {
        const t = normalizeTranscript(transcriptFull);
        const parts = splitOnSpeakerBoundaries(t, INDEX_SEGMENT_CHARS, INDEX_SEGMENT_MAX);
        timing.index_segments = parts.length;
        const tS = Date.now();
        if (parts.length === 1) {
          const res = await adaptiveIndexSingle(apiKey, parts[0], 0);
          timing.index_ms = Date.now() - tS;
          return res;
        }
        const tasks = parts.map((p) => () => adaptiveIndexSingle(apiKey, p, 0));
        const results = await runWithPool(tasks, Math.min(MAX_CONCURRENCY, 3));
        const valid = results.filter(Boolean);
        timing.index_ms = Date.now() - tS;
        if (!valid.length) throw new Error("Indexing failed for all segments");
        return mergeIndexes(valid, MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);
      }
      
      // ===== PIPELINE =====
      const suppliedSkillCount = countSkills(rubrics);
      if (suppliedSkillCount > MAX_SKILLS_CAP) {
        return new Response(JSON.stringify({ error: `Too many skills (${suppliedSkillCount}) > cap (${MAX_SKILLS_CAP})` }), { status: 400, headers });
      }
      if (Array.isArray(skills) && skills.length && suppliedSkillCount > skills.length) {
        rubrics = pickSelectedRubrics(rubrics, skills);
      }
      transcript = normalizeTranscript(transcript);
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
        rawIndex = await indexTranscriptSmart(GEMINI_API_KEY, transcript);
        if (env.ASSESS_CACHE) await kvPutJSON(env.ASSESS_CACHE, indexKVKey, rawIndex, KV_TTL_SECS);
        await edgePutJSON(edgeKey("index", indexKeyHash), rawIndex);
      }
      function trimIndex(idx, maxSeller = MAX_SELLER_QUOTES, maxCues = MAX_CUSTOMER_CUES) {
        if (!idx || typeof idx !== "object") return idx;
        const out = JSON.parse(JSON.stringify(idx || {}));
        out.seller_quotes = sortQuotesDeterministic(out.seller_quotes).slice(0, maxSeller);
        out.customer_cues = sortQuotesDeterministic(out.customer_cues).slice(0, maxCues);
        const order = orderIndexMap(out.seller_quotes);
        const eb = out.evidence_buckets || {};
        for (const k in eb) {
          const arr = (eb[k] || []).map(normalizeQuote).filter(q => order.has(q));
          const uniq = [...new Set(arr)];
          eb[k] = uniq.sort((a, b) => order.get(a) - order.get(b)).slice(0, maxSeller);
        }
        out.evidence_buckets = eb;
        return out;
      }
      const index = trimIndex(rawIndex, MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES);
      let assessments = [];
      let assess_kv_hit = false;

      if (ASSESS_MODE === "batched") {
        const assessKeyInput = stable({
          v: CACHE_VERSION,
          ASSESS_MODEL,
          MIN_QUOTES_PER_POSITIVE_PASS, REQUIRE_DISTINCT_EVIDENCE, MAX_EVIDENCE_REUSE, ENFORCE_MAX_WORDS_IN_EVIDENCE,
          WHITELIST_MAX, BUCKETS_IN_PROMPT, BUCKET_SAMPLE_N,
          transcript, rubrics, index,
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
          assessments = await getAssessmentsBatched(GEMINI_API_KEY, transcript, rubrics, index);
          if (assessments.length && env.ASSESS_CACHE) {
            await kvPutJSON(env.ASSESS_CACHE, assessKVKey, { assessments }, KV_TTL_SECS);
            await edgePutJSON(edgeKey("assess", assessKeyHash), { assessments });
          }
        }
      } else {
        const pendingTasks = [];
        assessments = [];
        for (const competency in rubrics) {
          const comp = rubrics[competency];
          if (!comp || !comp.skills) continue;
          for (const skillName in comp.skills) {
            const rubricData = comp.skills[skillName];
            const wl = selectWhitelistForSkill(index, skillName, WHITELIST_MAX, transcript);
            const skillKeyHash = await buildAssessSkillKeyHash({
              cacheVersion: CACHE_VERSION,
              assessModel: ASSESS_MODEL,
              minQuotesPerPositivePass: MIN_QUOTES_PER_POSITIVE_PASS,
              requireDistinctEvidence: REQUIRE_DISTINCT_EVIDENCE,
              maxEvidenceReuse: MAX_EVIDENCE_REUSE,
              enforceMaxWords: ENFORCE_MAX_WORDS_IN_EVIDENCE,
              bucketsInPrompt: BUCKETS_IN_PROMPT,
              bucketSampleN: BUCKET_SAMPLE_N,
              skillName, rubricData, whitelist: wl, indexKeyHash
            });
            const kvKey = `v${CACHE_VERSION}:assess_skill:${skillKeyHash}`;
            if (env.ASSESS_CACHE) {
              const cached = await kvGetJSON(env.ASSESS_CACHE, kvKey);
              if (cached && cached.assessment && !cached.assessment.__error) {
                assessments.push(cached.assessment);
                assess_kv_hit = true;
                continue;
              }
            }
            pendingTasks.push(async () => {
              const res = await getAssessmentForSkill(GEMINI_API_KEY, transcript, skillName, rubricData, index, wl);
              if (res && env.ASSESS_CACHE) {
                await kvPutJSON(env.ASSESS_CACHE, kvKey, { assessment: res }, KV_TTL_SECS);
                await edgePutJSON(edgeKey("assess_skill", skillKeyHash), { assessment: res });
              }
              return res;
            });
          }
        }
        if (!pendingTasks.length && !assessments.length) {
          return new Response(JSON.stringify({ error: "No skills found in provided rubrics." }), { status: 400, headers });
        }
        if (pendingTasks.length) {
          const pooled = await runWithPool(pendingTasks, Math.min(MAX_CONCURRENCY, 3));
          const fresh = pooled.filter((r) => r && !r.__error);
          assessments = assessments.concat(fresh);
        }
      }      

      // 3) Presentation
      function buildPresentation(assessments) {
        try {
          const headline = assessments.map((a) => `${a.skill}: ${a.rating}/5`).join(" • ");
          const bullets = [];
          for (const a of assessments.slice(0, 3)) {
            if (a.strengths?.length) bullets.push(`Strength (${a.skill}): ${a.strengths[0]}`);
            if (a.improvements?.length) bullets.push(`Gap (${a.skill}): ${a.improvements[0].point}`);
          }
          return { headline, summary_bullets: bullets.slice(0, 5) };
        } catch { return undefined; }
      }

      timing.assess = timing.assess_calls;

      if (assessments.length > 0) {
        const meta = {
          index_model: INDEX_MODEL,
          assess_model: ASSESS_MODEL,
          assess_mode: ASSESS_MODE,
          kv_index_hit: index_kv_hit,
          kv_assess_hit: assess_kv_hit,
          kv_enabled: !!env.ASSESS_CACHE,
          edge_warmed: WARM_EDGE_CACHE,
          run_id: crypto && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
          duration_ms: Date.now() - t0,
          rubric_version: rubric_version || undefined,
          limits: { MAX_SELLER_QUOTES, MAX_CUSTOMER_CUES, MAX_QUOTE_WORDS, MIN_QUOTES_PER_POSITIVE_PASS, REQUIRE_DISTINCT_EVIDENCE, MAX_EVIDENCE_REUSE, WHITELIST_MAX, BUCKETS_IN_PROMPT, BUCKET_SAMPLE_N, },
          timing,
        };
        const payload = {
          seller_identity: index?.seller_label || "Seller",
          assessments,
          meta,
        };
        if (include_presentation) {
          const presentation = buildPresentation(assessments);
          if (presentation) payload.presentation = presentation;
        }
        return new Response(JSON.stringify(payload), { status: 200, headers });
      }

      return new Response(JSON.stringify({ error: "All skill assessments failed to process." }), { status: 500, headers });

    } catch (error) {
      const msg = (error && error.message) ? String(error.message) : "Unknown error";
      console.error("Error in Cloudflare Worker:", msg);
      const status = /Timeout/i.test(msg) || /(^|[^0-9])524([^0-9]|$)/.test(msg) ? 504 : 500;
      return new Response(JSON.stringify({ error: msg }), { status, headers });
    }
  },
};