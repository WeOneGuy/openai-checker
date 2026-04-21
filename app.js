/* ═══════════════════════════════════════════════════════════
   OpenAI Key Checker — Application Logic
   ═══════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── Constants ────────────────────────────────────────────
  const API_URL = 'https://api.openai.com/v1/chat/completions';
  const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/key';
  const OPENROUTER_CREDITS_URL = 'https://openrouter.ai/api/v1/credits';
  const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta';
  const REQUEST_TIMEOUT = 15000;
  const MAX_CONCURRENCY = 5;
  const STORAGE_KEY = 'oai-checker-keys';
  const CRYPTO_PASS = 'oai-kc-2026-x9f';

  // gpt-5.4-nano specific TPM thresholds
  const TIER_MAP = {
    40000: { tier: 'Free', rpm: 3 },
    200000: { tier: 'Tier 1', rpm: 500 },
    2000000: { tier: 'Tier 2', rpm: 5000 },
    4000000: { tier: 'Tier 3', rpm: 5000 },
    10000000: { tier: 'Tier 4', rpm: 10000 },
    180000000: { tier: 'Tier 5', rpm: 30000 },
  };

  const TIER_ORDER = ['Free', 'Tier 1', 'Tier 2', 'Tier 3', 'Tier 4', 'Tier 5'];

  // Regex patterns for key extraction
  const KEY_PATTERNS = [
    /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    /sk-proj-[A-Za-z0-9\-_]{40,}/g,
    /sk-or-[a-zA-Z0-9\-_]{20,}/g,
    /AIzaSy[A-Za-z0-9_-]{33}/g,
  ];

  // ── Key Type Detection ──────────────────────────────────
  function detectKeyType(key) {
    if (key.startsWith('sk-or-')) return 'openrouter';
    if (key.startsWith('sk-proj-') || /^sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}$/.test(key)) return 'openai';
    if (key.startsWith('sk-')) return 'openai'; // default assumption
    if (key.startsWith('AIzaSy')) return 'gemini';
    return 'openai';
  }

  // ── State ────────────────────────────────────────────────
  const state = {
    keys: [],
    corsOk: null,
    checking: false,
    checkedCount: 0,
    totalCount: 0,
    sortBy: 'smart', // smart = valid first, then by tier/balance
    filterBy: 'all',
  };

  // ── DOM References ───────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  let els = {};

  function cacheEls() {
    els = {
      bulkInput: $('#bulk-input'),
      checkBtn: $('#check-btn'),
      corsBanner: $('#cors-banner'),
      extractBanner: $('#extract-banner'),
      extractCount: $('#extract-count'),
      extractNew: $('#extract-new'),
      progressFill: $('#progress-fill'),
      progressSection: $('#progress-section'),
      resultsList: $('#results-list'),
      emptyState: $('#empty-state'),
      statsBar: $('#stats-bar'),
      controlsSection: $('#controls-section'),
      sortBtns: $$('[data-sort]'),
      filterBtns: $$('[data-filter]'),
      copyAllBtn: $('#copy-all-btn'),
      totalStat: $('#stat-total'),
      validStat: $('#stat-valid'),
      invalidStat: $('#stat-invalid'),
      tierDistribution: $('#tier-distribution'),
    };
  }

  // ── Encryption (AES-like XOR + base64 for localStorage) ──
  function encrypt(text) {
    const pass = CRYPTO_PASS;
    let result = '';
    for (let i = 0; i < text.length; i++) {
      result += String.fromCharCode(text.charCodeAt(i) ^ pass.charCodeAt(i % pass.length));
    }
    return btoa(unescape(encodeURIComponent(result)));
  }

  function decrypt(encoded) {
    try {
      const decoded = decodeURIComponent(escape(atob(encoded)));
      const pass = CRYPTO_PASS;
      let result = '';
      for (let i = 0; i < decoded.length; i++) {
        result += String.fromCharCode(decoded.charCodeAt(i) ^ pass.charCodeAt(i % pass.length));
      }
      return result;
    } catch {
      return '';
    }
  }

  // ── LocalStorage (encrypted) ─────────────────────────────
  function saveKeys() {
    const data = state.keys.map((k) => ({
      key: k.key,
      status: k.status,
      type: k.type,
      tier: k.tier,
      rpm: k.rpm,
      tpm: k.tpm,
      rpmRemaining: k.rpmRemaining,
      tpmRemaining: k.tpmRemaining,
      balance: k.balance,
      balanceLimit: k.balanceLimit,
      isFreeTier: k.isFreeTier,
      usage: k.usage,
      responseTime: k.responseTime,
      orTotalCredits: k.orTotalCredits,
      orTotalUsage: k.orTotalUsage,
      orKeyLimit: k.orKeyLimit,
      orKeyLimitRemaining: k.orKeyLimitRemaining,
      orKeyUsageDaily: k.orKeyUsageDaily,
      addedAt: k.addedAt,
    }));
    localStorage.setItem(STORAGE_KEY, encrypt(JSON.stringify(data)));
  }

  function loadKeys() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const decrypted = decrypt(raw);
    if (!decrypted) return [];
    try {
      const data = JSON.parse(decrypted);
      if (!Array.isArray(data)) return [];
      return data.map((k) => ({
        key: k.key || '',
        status: k.status || 'pending',
        type: k.type || detectKeyType(k.key || ''),
        tier: k.tier || 'Unknown',
        rpm: k.rpm || 0,
        tpm: k.tpm || 0,
        rpmRemaining: k.rpmRemaining || 0,
        tpmRemaining: k.tpmRemaining || 0,
        balance: k.balance !== undefined ? k.balance : null,
        balanceLimit: k.balanceLimit !== undefined ? k.balanceLimit : null,
        isFreeTier: k.isFreeTier || false,
        usage: k.usage || 0,
        responseTime: k.responseTime || 0,
        orTotalCredits: k.orTotalCredits !== undefined ? k.orTotalCredits : null,
        orTotalUsage: k.orTotalUsage !== undefined ? k.orTotalUsage : null,
        orKeyLimit: k.orKeyLimit !== undefined ? k.orKeyLimit : null,
        orKeyLimitRemaining: k.orKeyLimitRemaining !== undefined ? k.orKeyLimitRemaining : null,
        orKeyUsageDaily: k.orKeyUsageDaily !== undefined ? k.orKeyUsageDaily : null,
        addedAt: k.addedAt || 0,
        headers: null,
        error: null,
        errorFull: null,
        expanded: false,
        revealed: false,
      }));
    } catch {
      return [];
    }
  }

  function clearStorage() {
    localStorage.removeItem(STORAGE_KEY);
  }

  // ── Key Extraction ───────────────────────────────────────
  function extractKeys(text) {
    const found = new Set();
    KEY_PATTERNS.forEach((pattern) => {
      pattern.lastIndex = 0;
      const matches = text.matchAll(pattern);
      for (const m of matches) {
        found.add(m[0]);
      }
    });
    return [...found];
  }

  // ── Mask / Reveal Key ────────────────────────────────────
  function maskKey(key) {
    if (key.length <= 12) return key;
    return key.slice(0, 8) + '...' + key.slice(-4);
  }

  // ── Tier Inference ───────────────────────────────────────
  function inferTier(tpm) {
    if (!tpm || tpm <= 0) return { tier: 'Unknown', rpm: 0, level: -1 };

    if (TIER_MAP[tpm]) {
      const t = TIER_MAP[tpm];
      return { ...t, level: TIER_ORDER.indexOf(t.tier) };
    }

    const thresholds = Object.keys(TIER_MAP).map(Number).sort((a, b) => a - b);
    let best = null;
    for (const t of thresholds) {
      if (t <= tpm) best = t;
      else break;
    }

    if (best !== null) {
      const t = TIER_MAP[best];
      return { ...t, level: TIER_ORDER.indexOf(t.tier) };
    }

    return { tier: 'Unknown', rpm: 0, level: -1 };
  }

  // ── Tier Badge CSS Class ─────────────────────────────────
  function tierBadgeClass(tierName) {
    const map = {
      'Free': 'tier-free',
      'Tier 1': 'tier-1',
      'Tier 2': 'tier-2',
      'Tier 3': 'tier-3',
      'Tier 4': 'tier-4',
      'Tier 5': 'tier-5',
      'Paid': 'tier-paid',
    };
    return map[tierName] || 'tier-unknown';
  }

  // ── API Validation ───────────────────────────────────────
  async function validateKey(key) {
    const entry = state.keys.find((k) => k.key === key);
    if (!entry) return;

    entry.type = detectKeyType(key);
    entry.status = 'checking';
    renderKeyCard(entry);

    if (entry.type === 'openrouter') {
      await validateOpenRouterKey(key, entry);
    } else if (entry.type === 'gemini') {
      await validateGeminiKey(key, entry);
    } else {
      await validateOpenAIKey(key, entry);
    }

    state.checkedCount++;
    updateProgress();
    renderKeyCard(entry);
    updateStats();
    saveKeys();
  }

  // ── OpenAI Key Validation ────────────────────────────────
  async function validateOpenAIKey(key, entry) {
    const startTime = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-5.4-nano',
          messages: [{ role: 'user', content: 'Hi' }],
          max_completion_tokens: 16,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;

      // Parse rate limit headers
      const headers = {};
      const headerNames = [
        'x-ratelimit-limit-requests',
        'x-ratelimit-limit-tokens',
        'x-ratelimit-remaining-requests',
        'x-ratelimit-remaining-tokens',
        'x-ratelimit-reset-requests',
        'x-ratelimit-reset-tokens',
        'x-ratelimit-limit-requests-1h',
        'x-ratelimit-limit-tokens-1h',
        'x-ratelimit-remaining-requests-1h',
        'x-ratelimit-remaining-tokens-1h',
        'x-ratelimit-reset-requests-1h',
        'x-ratelimit-reset-tokens-1h',
      ];
      headerNames.forEach((h) => {
        const val = response.headers.get(h);
        if (val) headers[h] = val;
      });

      const rpm = parseInt(headers['x-ratelimit-limit-requests'], 10) || 0;
      const tpm = parseInt(headers['x-ratelimit-limit-tokens'], 10) || 0;
      const rpmRemaining = parseInt(headers['x-ratelimit-remaining-requests'], 10) || 0;
      const tpmRemaining = parseInt(headers['x-ratelimit-remaining-tokens'], 10) || 0;

      const tierInfo = inferTier(tpm);

      if (response.status === 200) {
        entry.status = 'valid';
        entry.tier = tierInfo.tier;
        entry.rpm = rpm;
        entry.tpm = tpm;
        entry.rpmRemaining = rpmRemaining;
        entry.tpmRemaining = tpmRemaining;
        entry.headers = headers;
        entry.responseTime = responseTime;
        entry.error = null;
        entry.errorFull = null;
      } else if (response.status === 429) {
        entry.status = 'rate-limited';
        entry.tier = tierInfo.tier;
        entry.rpm = rpm;
        entry.tpm = tpm;
        entry.rpmRemaining = rpmRemaining;
        entry.tpmRemaining = tpmRemaining;
        entry.headers = headers;
        entry.responseTime = responseTime;
        // If headers didn't come, still show useful info
        if (!rpm && !tpm) {
          entry.error = 'Rate limited — key is valid but too many requests. Tier info unavailable from headers.';
          entry.errorFull = 'HTTP 429 Too Many Requests. The key works but rate limit headers were not returned in this response. Try again later to get tier data.';
        }
      } else if (response.status === 401 || response.status === 403) {
        entry.status = 'invalid';
        entry.tier = 'Unknown';
        entry.rpm = 0;
        entry.tpm = 0;
        entry.rpmRemaining = 0;
        entry.tpmRemaining = 0;
        entry.headers = headers;
        entry.responseTime = responseTime;

        try {
          const body = await response.json();
          const errMsg = body?.error?.message || `HTTP ${response.status}`;
          const errFull = JSON.stringify(body, null, 2);
          entry.error = errMsg;
          entry.errorFull = errFull;
        } catch {
          entry.error = `HTTP ${response.status}`;
          entry.errorFull = `HTTP ${response.status}`;
        }
      } else {
        entry.status = 'error';
        entry.responseTime = responseTime;
        entry.headers = headers;

        try {
          const body = await response.json();
          const errMsg = body?.error?.message || `Unexpected HTTP ${response.status}`;
          const errFull = JSON.stringify(body, null, 2);
          entry.error = errMsg;
          entry.errorFull = errFull;
        } catch {
          entry.error = `Unexpected HTTP ${response.status}`;
          entry.errorFull = `Unexpected HTTP ${response.status}`;
        }
      }
    } catch (err) {
      entry.responseTime = Date.now() - startTime;
      if (err.name === 'AbortError') {
        entry.status = 'error';
        entry.error = 'Request timed out (15s)';
        entry.errorFull = 'Request timed out (15s)';
      } else if (err.message && err.message.includes('CORS')) {
        entry.status = 'error';
        entry.error = 'CORS blocked — browser cannot reach OpenAI API directly';
        entry.errorFull = 'CORS blocked — browser cannot reach OpenAI API directly';
      } else {
        entry.status = 'error';
        entry.error = err.message || 'Network error';
        entry.errorFull = err.stack || err.message || 'Network error';
      }
    }
  }

  // ── OpenRouter Key Validation ────────────────────────────
  async function validateOpenRouterKey(key, entry) {
    const startTime = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

      const response = await fetch(OPENROUTER_API_URL, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${key}`,
          'HTTP-Referer': 'https://weoneguy.github.io/openai-checker',
          'X-Title': 'AI Key Checker',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      const responseTime = Date.now() - startTime;

      // Parse response headers
      const headers = {};
      const headerNames = [
        'x-ratelimit-limit',
        'x-ratelimit-remaining',
        'x-ratelimit-reset',
      ];
      headerNames.forEach((h) => {
        const val = response.headers.get(h);
        if (val) headers[h] = val;
      });

      if (response.status === 200) {
        const body = await response.json();
        const data = body?.data || {};

        entry.status = 'valid';
        entry.type = 'openrouter';
        entry.isFreeTier = data.is_free_tier || false;
        entry.tier = data.is_free_tier ? 'Free' : 'Paid';
        entry.rpm = parseInt(headers['x-ratelimit-limit'], 10) || 0;
        entry.rpmRemaining = parseInt(headers['x-ratelimit-remaining'], 10) || 0;
        entry.tpm = 0;
        entry.tpmRemaining = 0;
        entry.headers = headers;
        entry.responseTime = responseTime;
        entry.error = null;
        entry.errorFull = null;

        // Store /key endpoint data separately
        entry.orKeyLimit = data.limit !== null && data.limit !== undefined ? data.limit : null;
        entry.orKeyLimitRemaining = data.limit_remaining !== null && data.limit_remaining !== undefined ? data.limit_remaining : null;
        entry.orKeyUsageDaily = data.usage_daily !== null && data.usage_daily !== undefined ? data.usage_daily : null;
        entry.usage = data.usage || 0;

        // Store key info in headers for expandable details
        if (data.label) headers['label'] = data.label;
        if (data.limit !== null && data.limit !== undefined) headers['key_limit'] = String(data.limit);
        if (data.limit_remaining !== null && data.limit_remaining !== undefined) headers['key_limit_remaining'] = String(data.limit_remaining);
        if (data.usage !== null && data.usage !== undefined) headers['key_usage'] = String(data.usage);
        if (data.usage_daily !== null && data.usage_daily !== undefined) headers['usage_daily'] = String(data.usage_daily);
        if (data.usage_weekly !== null && data.usage_weekly !== undefined) headers['usage_weekly'] = String(data.usage_weekly);
        if (data.usage_monthly !== null && data.usage_monthly !== undefined) headers['usage_monthly'] = String(data.usage_monthly);
        if (data.is_free_tier !== undefined) headers['is_free_tier'] = String(data.is_free_tier);
        if (data.rate_limit) {
          if (data.rate_limit.requests) headers['rate_limit_requests'] = String(data.rate_limit.requests);
          if (data.rate_limit.tokens) headers['rate_limit_tokens'] = String(data.rate_limit.tokens);
        }

        // Now fetch credits endpoint for account-wide balance
        try {
          const creditsResponse = await fetch(OPENROUTER_CREDITS_URL, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${key}`,
              'HTTP-Referer': 'https://weoneguy.github.io/openai-checker',
              'X-Title': 'AI Key Checker',
            },
          });

          if (creditsResponse.status === 200) {
            const creditsBody = await creditsResponse.json();
            const creditsData = creditsBody?.data || {};

            const totalCredits = creditsData.total_credits || 0;
            const totalUsage = creditsData.total_usage || 0;
            const remaining = totalCredits - totalUsage;

            entry.orTotalCredits = totalCredits;
            entry.orTotalUsage = totalUsage;
            entry.balance = remaining;
            entry.balanceLimit = totalCredits;
            entry.usage = totalUsage;

            // Store in headers for expandable details
            headers['total_credits'] = String(totalCredits);
            headers['total_usage'] = String(totalUsage);
            headers['balance_remaining'] = String(remaining);
          } else {
            // Credits endpoint failed, fall back to /key endpoint data
            entry.orTotalCredits = null;
            entry.orTotalUsage = null;
            entry.balance = entry.orKeyLimitRemaining;
            entry.balanceLimit = entry.orKeyLimit;
          }
        } catch {
          // Credits fetch failed (network/CORS), fall back to /key endpoint data
          entry.orTotalCredits = null;
          entry.orTotalUsage = null;
          entry.balance = entry.orKeyLimitRemaining;
          entry.balanceLimit = entry.orKeyLimit;
        }
      } else if (response.status === 401 || response.status === 403) {
        entry.status = 'invalid';
        entry.tier = 'Unknown';
        entry.rpm = 0;
        entry.tpm = 0;
        entry.rpmRemaining = 0;
        entry.tpmRemaining = 0;
        entry.headers = headers;
        entry.responseTime = responseTime;

        try {
          const body = await response.json();
          const errMsg = body?.error?.message || body?.message || `HTTP ${response.status}`;
          const errFull = JSON.stringify(body, null, 2);
          entry.error = errMsg;
          entry.errorFull = errFull;
        } catch {
          entry.error = `HTTP ${response.status}`;
          entry.errorFull = `HTTP ${response.status}`;
        }
      } else {
        entry.status = 'error';
        entry.responseTime = responseTime;
        entry.headers = headers;

        try {
          const body = await response.json();
          const errMsg = body?.error?.message || body?.message || `Unexpected HTTP ${response.status}`;
          const errFull = JSON.stringify(body, null, 2);
          entry.error = errMsg;
          entry.errorFull = errFull;
        } catch {
          entry.error = `Unexpected HTTP ${response.status}`;
          entry.errorFull = `Unexpected HTTP ${response.status}`;
        }
      }
    } catch (err) {
      entry.responseTime = Date.now() - startTime;
      if (err.name === 'AbortError') {
        entry.status = 'error';
        entry.error = 'Request timed out (15s)';
        entry.errorFull = 'Request timed out (15s)';
      } else if (err.message && err.message.includes('CORS')) {
        entry.status = 'error';
        entry.error = 'CORS blocked — browser cannot reach OpenRouter API directly';
        entry.errorFull = 'CORS blocked — browser cannot reach OpenRouter API directly';
      } else {
        entry.status = 'error';
        entry.error = err.message || 'Network error';
        entry.errorFull = err.stack || err.message || 'Network error';
      }
    }
  }

  // ── Gemini Key Validation ────────────────────────────────
  async function validateGeminiKey(key, entry) {
    const startTime = Date.now();
    const headers = {};

    // Strategy:
    // 1. Call GET /v1/models?key={key} — validates key + gets available model list
    // 2. Find a "pro" model in the list → test it for paid tier
    // 3. Find a "flash" model → test it for free tier
    // 4. If key invalid (400/401) → invalid
    // 5. If key valid but no models accessible → invalid

    // Step 1: List models to validate key and discover available models
    try {
      const listController = new AbortController();
      const listTimeout = setTimeout(() => listController.abort(), REQUEST_TIMEOUT);

      const listResponse = await fetch(
        `${GEMINI_BASE_URL}/models?key=${encodeURIComponent(key)}`,
        {
          method: 'GET',
          signal: listController.signal,
        }
      );

      clearTimeout(listTimeout);

      // Invalid key — 400, 401
      if (listResponse.status === 400 || listResponse.status === 401 || listResponse.status === 403) {
        entry.responseTime = Date.now() - startTime;
        entry.status = 'invalid';
        entry.type = 'gemini';
        entry.tier = 'Unknown';

        try {
          const errBody = await listResponse.json();
          const errMsg = errBody?.error?.message || `HTTP ${listResponse.status}`;
          const errFull = JSON.stringify(errBody, null, 2);
          entry.error = errMsg;
          entry.errorFull = errFull;
          entry.headers = { 'list_status': String(listResponse.status) };
        } catch {
          entry.error = `Invalid API key (HTTP ${listResponse.status})`;
          entry.errorFull = `HTTP ${listResponse.status}`;
          entry.headers = { 'list_status': String(listResponse.status) };
        }
        return;
      }

      if (listResponse.status !== 200) {
        entry.responseTime = Date.now() - startTime;
        entry.status = 'error';
        entry.type = 'gemini';
        entry.error = `Unexpected response from models list: HTTP ${listResponse.status}`;
        entry.errorFull = `HTTP ${listResponse.status}`;
        entry.headers = { 'list_status': String(listResponse.status) };
        return;
      }

      // Key is valid! Parse available models
      const listBody = await listResponse.json();
      const models = listBody?.models || [];

      // Extract model names (format: "models/gemini-2.5-flash")
      const modelNames = models.map((m) => m.name?.replace('models/', '') || '');

      // Store model list in headers for expandable details
      headers['available_models'] = modelNames.join(', ');
      headers['models_count'] = String(modelNames.length);

      // Find models with supportedMethods that include "generateContent"
      const genModels = models.filter((m) =>
        m.supportedGenerationMethods?.includes('generateContent')
      );
      const genModelNames = genModels.map((m) => m.name?.replace('models/', '') || '');

      // Find best Pro model to test (paid tier indicator)
      // Priority: gemini-2.5-pro (most common paid indicator)
      const proCandidates = genModelNames.filter((n) =>
        n.includes('pro') && !n.includes('flash')
      );
      const proModel = proCandidates.sort((a, b) => b.localeCompare(a))[0] || null;

      // Find best Flash model to test (free tier indicator)
      const flashCandidates = genModelNames.filter((n) =>
        n.includes('flash') || n.includes('lite')
      );
      const flashModel = flashCandidates.sort((a, b) => {
        // Prefer flash-lite (cheapest) over flash
        const aHasLite = a.includes('lite');
        const bHasLite = b.includes('lite');
        if (aHasLite && !bHasLite) return -1;
        if (!aHasLite && bHasLite) return 1;
        return b.localeCompare(a);
      })[0] || null;

      // Step 2: If Pro model exists, test it for paid tier
      if (proModel) {
        try {
          const proController = new AbortController();
          const proTimeout = setTimeout(() => proController.abort(), REQUEST_TIMEOUT);

          const proResponse = await fetch(
            `${GEMINI_BASE_URL}/models/${proModel}:generateContent?key=${encodeURIComponent(key)}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                contents: [{ parts: [{ text: 'Hi' }] }],
                generationConfig: { maxOutputTokens: 5 },
              }),
              signal: proController.signal,
            }
          );

          clearTimeout(proTimeout);

          if (proResponse.status === 200) {
            entry.responseTime = Date.now() - startTime;
            entry.status = 'valid';
            entry.type = 'gemini';
            entry.tier = 'Paid';
            entry.isFreeTier = false;
            entry.rpm = 0;
            entry.rpmRemaining = 0;
            entry.tpm = 0;
            entry.tpmRemaining = 0;
            entry.headers = { ...headers, 'pro_access': 'true', 'pro_model': proModel };
            entry.error = null;
            entry.errorFull = null;
            return;
          }

          // Pro failed with 429 or quota exceeded — paid tier but rate limited or no quota
          if (proResponse.status === 429 || proResponse.status === 403) {
            entry.responseTime = Date.now() - startTime;
            entry.status = 'valid';
            entry.type = 'gemini';
            entry.tier = 'Paid';
            entry.isFreeTier = false;
            entry.rpm = 0;
            entry.rpmRemaining = 0;
            entry.tpm = 0;
            entry.tpmRemaining = 0;

            try {
              const proBody = await proResponse.json();
              const errMsg = proBody?.error?.message || 'Rate limited';
              // Check for quota exceeded - means valid key but no quota, still Paid tier
              if (errMsg && errMsg.toLowerCase().includes('quota')) {
                entry.error = errMsg;
                entry.errorFull = JSON.stringify(proBody, null, 2);
                entry.headers = { ...headers, 'pro_access': 'quota-exceeded', 'pro_model': proModel };
              } else {
                entry.error = errMsg;
                entry.errorFull = JSON.stringify(proBody, null, 2);
                entry.headers = { ...headers, 'pro_access': 'rate-limited', 'pro_model': proModel };
              }
            } catch {
              entry.error = 'Pro model error';
              entry.errorFull = String(proResponse.status);
              entry.headers = { ...headers, 'pro_access': String(proResponse.status), 'pro_model': proModel };
            }
            return;
          }

          // Pro failed with other error — likely free tier (insufficient access)
          headers['pro_error'] = `HTTP ${proResponse.status}`;
          headers['pro_status'] = String(proResponse.status);
        } catch {
          // Pro test timed out or network error — skip, try Flash
          headers['pro_error'] = 'timeout';
        }
      }

      // Step 3: Test Flash model (free tier indicator)
      if (flashModel) {
        try {
          const flashController = new AbortController();
          const flashTimeout = setTimeout(() => flashController.abort(), REQUEST_TIMEOUT);

          const flashResponse = await fetch(
            `${GEMINI_BASE_URL}/models/${flashModel}:generateContent?key=${encodeURIComponent(key)}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                contents: [{ parts: [{ text: 'Hi' }] }],
                generationConfig: { maxOutputTokens: 5 },
              }),
              signal: flashController.signal,
            }
          );

          clearTimeout(flashTimeout);
          entry.responseTime = Date.now() - startTime;

          if (flashResponse.status === 200) {
            entry.status = 'valid';
            entry.type = 'gemini';
            entry.tier = 'Free';
            entry.isFreeTier = true;
            entry.rpm = 0;
            entry.rpmRemaining = 0;
            entry.tpm = 0;
            entry.tpmRemaining = 0;
            entry.headers = { ...headers, 'flash_access': 'true', 'flash_model': flashModel };
            entry.error = null;
            entry.errorFull = null;
            return;
          }

          if (flashResponse.status === 429 || flashResponse.status === 403) {
            entry.responseTime = Date.now() - startTime;
            entry.status = 'valid';
            entry.type = 'gemini';
            entry.tier = 'Free';
            entry.isFreeTier = true;
            entry.rpm = 0;
            entry.rpmRemaining = 0;
            entry.tpm = 0;
            entry.tpmRemaining = 0;

            try {
              const flashBody = await flashResponse.json();
              const errMsg = flashBody?.error?.message || 'Rate limited';
              // Check for quota exceeded - key is valid Free tier but no quota
              if (errMsg && errMsg.toLowerCase().includes('quota')) {
                entry.status = 'valid';
                entry.error = errMsg;
                entry.errorFull = JSON.stringify(flashBody, null, 2);
                entry.headers = { ...headers, 'flash_error': errMsg, 'flash_status': String(flashResponse.status), 'flash_model': flashModel };
              } else {
                entry.status = 'rate-limited';
                entry.error = errMsg;
                entry.errorFull = JSON.stringify(flashBody, null, 2);
                entry.headers = { ...headers, 'flash_error': errMsg, 'flash_status': String(flashResponse.status), 'flash_model': flashModel };
              }
            } catch {
              entry.status = 'rate-limited';
              entry.error = flashResponse.status === 429 ? 'Model is temporarily overloaded' : 'Access denied';
              entry.errorFull = String(flashResponse.status);
              entry.headers = { ...headers, 'flash_error': String(flashResponse.status), 'flash_status': String(flashResponse.status), 'flash_model': flashModel };
            }
            return;
          }

          // Flash also failed
          if (flashResponse.status === 400 || flashResponse.status === 401 || flashResponse.status === 403) {
            entry.status = 'invalid';
            entry.type = 'gemini';
            entry.tier = 'Unknown';

            try {
              const flashBody = await flashResponse.json();
              const errMsg = flashBody?.error?.message || `HTTP ${flashResponse.status}`;
              const errFull = JSON.stringify(flashBody, null, 2);
              entry.error = errMsg;
              entry.errorFull = errFull;
              entry.headers = { ...headers, 'flash_error': errMsg, 'flash_status': String(flashResponse.status) };
            } catch {
              entry.error = `HTTP ${flashResponse.status}`;
              entry.errorFull = `HTTP ${flashResponse.status}`;
            }
            return;
          }

          // Other error on Flash
          entry.status = 'error';
          entry.type = 'gemini';
          try {
            const flashBody = await flashResponse.json();
            const errMsg = flashBody?.error?.message || `Unexpected HTTP ${flashResponse.status}`;
            const errFull = JSON.stringify(flashBody, null, 2);
            entry.error = errMsg;
            entry.errorFull = errFull;
            entry.headers = { ...headers, 'flash_error': errMsg, 'flash_status': String(flashResponse.status) };
          } catch {
            entry.error = `Unexpected HTTP ${flashResponse.status}`;
            entry.errorFull = `Unexpected HTTP ${flashResponse.status}`;
          }
          return;
        } catch (err) {
          entry.responseTime = Date.now() - startTime;
          entry.status = 'error';
          entry.error = err.name === 'AbortError' ? 'Request timed out (15s)' : (err.message || 'Network error');
          entry.errorFull = err.stack || err.message || 'Network error';
          entry.headers = headers;
          return;
        }
      }

      // No pro or flash models found — key might be valid but has no generateContent models
      entry.responseTime = Date.now() - startTime;
      entry.status = 'valid';
      entry.type = 'gemini';
      entry.tier = 'Unknown';
      entry.rpm = 0;
      entry.rpmRemaining = 0;
      entry.tpm = 0;
      entry.tpmRemaining = 0;
      entry.headers = headers;
      entry.error = 'Key is valid but no generateContent models available';
      entry.errorFull = `Available models: ${modelNames.join(', ')}`;
    } catch (err) {
      entry.responseTime = Date.now() - startTime;
      if (err.name === 'AbortError') {
        entry.status = 'error';
        entry.error = 'Request timed out (15s)';
        entry.errorFull = 'Request timed out (15s)';
      } else {
        entry.status = 'error';
        entry.error = err.message || 'Network error';
        entry.errorFull = err.stack || err.message || 'Network error';
      }
      entry.headers = headers;
    }
  }

  // ── Batch Validation with Concurrency ────────────────────
  async function batchValidate(keys) {
    state.checking = true;
    state.checkedCount = 0;
    state.totalCount = keys.length;
    updateProgress();
    setCheckBtnLoading(true);

    for (let i = 0; i < keys.length; i += MAX_CONCURRENCY) {
      const chunk = keys.slice(i, i + MAX_CONCURRENCY);
      await Promise.all(chunk.map((k) => validateKey(k)));
    }

    state.checking = false;
    setCheckBtnLoading(false);
    saveKeys();
  }

  // ── CORS Probe ───────────────────────────────────────────
  async function probeCORS() {
    let openaiOk = false;
    let openrouterOk = false;
    let geminiOk = false;

    // Probe OpenAI API
    try {
      await fetch(API_URL, {
        method: 'OPTIONS',
        headers: { 'Content-Type': 'application/json' },
      });
      openaiOk = true;
    } catch {}

    // Probe OpenRouter API
    try {
      await fetch(OPENROUTER_API_URL, {
        method: 'OPTIONS',
        headers: {
          'HTTP-Referer': 'https://weoneguy.github.io/openai-checker',
          'X-Title': 'AI Key Checker',
        },
      });
      openrouterOk = true;
    } catch {}

    // Probe Gemini API
    try {
      await fetch(`${GEMINI_BASE_URL}/models?key=test`, {
        method: 'GET',
      });
      geminiOk = true;
    } catch {}

    state.corsOk = openaiOk || openrouterOk || geminiOk;

    const anyBlocked = !openaiOk || !openrouterOk || !geminiOk;
    const allBlocked = !openaiOk && !openrouterOk && !geminiOk;

    if (allBlocked) {
      els.corsBanner.classList.remove('hidden');
      els.corsBanner.querySelector('.text').innerHTML = '<strong>CORS Blocked</strong> — Your browser cannot reach any API. Key validation will fail. Try a different browser or proxy extension.';
    } else if (anyBlocked) {
      els.corsBanner.classList.remove('hidden');
      const blocked = [];
      if (!openaiOk) blocked.push('OpenAI');
      if (!openrouterOk) blocked.push('OpenRouter');
      if (!geminiOk) blocked.push('Gemini');
      const accessible = [];
      if (openaiOk) accessible.push('OpenAI');
      if (openrouterOk) accessible.push('OpenRouter');
      if (geminiOk) accessible.push('Gemini');
      els.corsBanner.querySelector('.text').innerHTML = `<strong>CORS Partially Blocked</strong> — ${blocked.join(', ')} API is blocked. ${accessible.join(', ')} keys can still be checked.`;
    } else {
      els.corsBanner.classList.add('hidden');
    }
  }

  // ── UI: Check Button ─────────────────────────────────────
  function setCheckBtnLoading(loading) {
    if (loading) {
      els.checkBtn.classList.add('loading');
      els.checkBtn.disabled = true;
    } else {
      els.checkBtn.classList.remove('loading');
      els.checkBtn.disabled = false;
    }
  }

  // ── UI: Progress ─────────────────────────────────────────
  function updateProgress() {
    if (state.totalCount === 0) {
      els.progressSection.classList.add('hidden');
      return;
    }
    els.progressSection.classList.remove('hidden');
    const pct = Math.round((state.checkedCount / state.totalCount) * 100);
    els.progressFill.style.width = pct + '%';
  }

  // ── UI: Stats ────────────────────────────────────────────
  function updateStats() {
    const total = state.keys.length;
    if (total === 0) {
      els.statsBar.classList.add('hidden');
      els.controlsSection.style.display = 'none';
      return;
    }
    els.statsBar.classList.remove('hidden');
    els.controlsSection.style.display = '';

    const valid = state.keys.filter((k) => k.status === 'valid' || k.status === 'rate-limited').length;
    const invalid = state.keys.filter((k) => k.status === 'invalid' || k.status === 'error').length;

    els.totalStat.textContent = total;
    els.validStat.textContent = valid;
    els.invalidStat.textContent = invalid;

    const tiers = {};
    state.keys.forEach((k) => {
      if (k.tier && k.tier !== 'Unknown') {
        tiers[k.tier] = (tiers[k.tier] || 0) + 1;
      }
    });

    let html = '';
    TIER_ORDER.forEach((t) => {
      if (tiers[t]) {
        const dotClass = t === 'Free' ? 'free' : t.replace('Tier ', 't');
        html += `<span class="tier-count"><span class="dot ${dotClass}"></span>${t}: ${tiers[t]}</span>`;
      }
    });
    // Add Paid tier for OpenRouter
    if (tiers['Paid']) {
      html += `<span class="tier-count"><span class="dot paid"></span>Paid: ${tiers['Paid']}</span>`;
    }
    els.tierDistribution.innerHTML = html;
  }

  // ── UI: Render Key Card ──────────────────────────────────
  function renderKeyCard(entry) {
    const cardId = `key-${entry.key.slice(0, 12)}`;
    const existing = document.getElementById(cardId);
    const card = existing || document.createElement('div');

    card.id = cardId;
    card.className = `key-card ${entry.status}${existing ? ' rendered' : ''}`;
    card.setAttribute('data-tier', entry.tier || '');
    card.setAttribute('data-status', entry.status);
    card.setAttribute('data-type', entry.type || 'openai');
    card.setAttribute('data-rpm', entry.rpm || 0);
    card.setAttribute('data-tpm', entry.tpm || 0);

    if (!existing) {
      const idx = state.keys.indexOf(entry);
      card.style.animationDelay = `${idx * 60}ms`;
    } else {
      // Already rendered — update without re-triggering animation
      card.style.animationDelay = '';
    }

    renderKeyCardContent(card, entry);

    if (!existing) {
      attachCardEvents(card, entry);
      els.resultsList.appendChild(card);
    }
  }

  // ── UI: Render All Cards ─────────────────────────────────
  function renderAllCards() {
    els.resultsList.innerHTML = '';
    const filtered = getFilteredKeys();
    const sorted = getSortedKeys(filtered);

    if (sorted.length === 0) {
      els.emptyState.classList.remove('hidden');
      return;
    }
    els.emptyState.classList.add('hidden');

    sorted.forEach((entry, idx) => {
      const card = document.createElement('div');
      card.id = `key-${entry.key.slice(0, 12)}`;
      card.className = `key-card ${entry.status}`;
      card.setAttribute('data-tier', entry.tier || '');
      card.setAttribute('data-status', entry.status);
      card.setAttribute('data-type', entry.type || 'openai');
      card.setAttribute('data-rpm', entry.rpm || 0);
      card.setAttribute('data-tpm', entry.tpm || 0);
      card.style.animationDelay = `${idx * 60}ms`;

      renderKeyCardContent(card, entry);
      attachCardEvents(card, entry);
      els.resultsList.appendChild(card);
    });
  }

  function renderKeyCardContent(card, entry) {
    const statusIcons = {
      'checking': '⏳',
      'valid': '✓',
      'invalid': '✗',
      'rate-limited': '⚠',
      'error': '✗',
      'pending': '·',
    };

    const masked = entry.revealed ? entry.key : maskKey(entry.key);

    // Type badge
    const typeBadgeHtml = entry.type
      ? `<span class="type-badge ${entry.type}">${entry.type === 'openrouter' ? 'OpenRouter' : entry.type === 'gemini' ? 'Gemini' : 'OpenAI'}</span>`
      : '';

    const tierBadge = entry.tier && entry.tier !== 'Unknown'
      ? `<span class="tier-badge ${tierBadgeClass(entry.tier)}">${entry.tier}</span>`
      : '';

    // Status label for non-valid keys
    const statusLabels = {
      'rate-limited': '<span class="status-label rate-limited-label">Rate Limited</span>',
      'invalid': '<span class="status-label invalid-label">Invalid</span>',
      'error': '<span class="status-label error-label">Error</span>',
      'checking': '<span class="status-label checking-label">Checking...</span>',
    };
    const statusLabelHtml = statusLabels[entry.status] || '';

    const timeHtml = entry.responseTime
      ? `<div class="limit-item"><span class="limit-value">${entry.responseTime}ms</span><span class="limit-label">Time</span></div>`
      : '';

    // Balance display for OpenRouter keys — account credits from /credits and key limit from /key
    let creditsHtml = '';
    let keyLimitHtml = '';
    let keyDailyHtml = '';

    if (entry.type === 'openrouter') {
      // Account-wide credits (/api/v1/credits): total_credits - total_usage = remaining
      if (entry.orTotalCredits !== null && entry.orTotalCredits !== undefined) {
        const remaining = entry.orTotalCredits - (entry.orTotalUsage || 0);
        const remStr = formatBalance(remaining);
        const totalStr = formatBalance(entry.orTotalCredits);
        creditsHtml = `<div class="limit-item balance-item"><span class="limit-value">$${remStr} / $${totalStr}</span><span class="limit-label">Credits</span></div>`;
      }

      // Key limit (/api/v1/key): limit_remaining out of limit
      if (entry.orKeyLimitRemaining !== null && entry.orKeyLimitRemaining !== undefined) {
        const remStr = formatBalance(entry.orKeyLimitRemaining);
        const limitStr = entry.orKeyLimit !== null && entry.orKeyLimit !== undefined
          ? formatBalance(entry.orKeyLimit)
          : null;
        let display = `$${remStr}`;
        if (limitStr) display += ` / $${limitStr}`;
        keyLimitHtml = `<div class="limit-item"><span class="limit-value">${display}</span><span class="limit-label">Key Limit</span></div>`;
      } else if (entry.orKeyLimit === null && entry.status === 'valid') {
        // No key limit set = unlimited
        keyLimitHtml = `<div class="limit-item"><span class="limit-value">∞</span><span class="limit-label">Key Limit</span></div>`;
      }

      // Daily usage from /key
      if (entry.orKeyUsageDaily !== null && entry.orKeyUsageDaily !== undefined) {
        keyDailyHtml = `<div class="limit-item"><span class="limit-value">$${formatBalance(entry.orKeyUsageDaily)}</span><span class="limit-label">Today Used</span></div>`;
      }
    }

    // Limits: for OpenRouter show balance + RPM, for Gemini show tier info, for OpenAI show RPM/TPM/Rem
    let limitsHtml = '';
    if (entry.type === 'openrouter') {
      const rpmHtml = entry.rpm
        ? `<div class="limit-item"><span class="limit-value">${formatNum(entry.rpm)}</span><span class="limit-label">RPM</span></div>`
        : '';
      const rpmRemHtml = entry.rpmRemaining
        ? `<div class="limit-item"><span class="limit-value">${formatNum(entry.rpmRemaining)}</span><span class="limit-label">Rem Req</span></div>`
        : '';
      const limitItems = [creditsHtml, keyLimitHtml, keyDailyHtml, rpmHtml, rpmRemHtml, timeHtml].filter(Boolean);
      if (limitItems.length) {
        limitsHtml = `<div class="limits">${limitItems.join('')}</div>`;
      }
    } else if (entry.type === 'gemini') {
      // Gemini: no RPM/TPM/balance — just show time
      if (timeHtml) {
        limitsHtml = `<div class="limits">${timeHtml}</div>`;
      }
    } else {
      limitsHtml = (entry.rpm || entry.tpm)
        ? `<div class="limits">
            <div class="limit-item">
              <span class="limit-value">${formatNum(entry.rpm)}</span>
              <span class="limit-label">RPM</span>
            </div>
            <div class="limit-item">
              <span class="limit-value">${formatNum(entry.tpm)}</span>
              <span class="limit-label">TPM</span>
            </div>
            <div class="limit-item">
              <span class="limit-value">${formatNum(entry.rpmRemaining)}</span>
              <span class="limit-label">Rem Req</span>
            </div>
            <div class="limit-item">
              <span class="limit-value">${formatNum(entry.tpmRemaining)}</span>
              <span class="limit-label">Rem Tok</span>
            </div>
            ${timeHtml}
          </div>`
        : timeHtml ? `<div class="limits">${timeHtml}</div>` : '';
    }

    const errorTooltip = entry.errorFull ? ` title="${entry.errorFull.replace(/"/g, '&quot;')}"` : '';
    const errorHtml = entry.error
      ? `<div class="error-message"${errorTooltip}>${entry.error}${entry.errorFull ? '<span class="error-expand-hint">hover for details</span>' : ''}</div>`
      : '';

    const detailsHtml = (entry.headers || entry.error)
      ? `<div class="card-details">
          ${errorHtml}
          ${entry.headers ? `<div class="detail-grid">${Object.entries(entry.headers).map(([k, v]) =>
            `<div class="detail-item"><span class="detail-label">${k}</span><span class="detail-value">${v}</span></div>`
          ).join('')}</div>` : ''}
        </div>`
      : '';

    card.innerHTML = `
      <div class="status-icon">${statusIcons[entry.status] || '·'}</div>
      <span class="key-text ${entry.revealed ? 'revealed' : ''}">${masked}</span>
      ${statusLabelHtml}
      ${typeBadgeHtml}
      ${tierBadge}
      ${limitsHtml}
      <div class="card-actions">
        <button class="btn-icon" data-action="reveal" title="Toggle key visibility" aria-label="Toggle key visibility">👁</button>
        <button class="btn-icon" data-action="copy" title="Copy key" aria-label="Copy key">📋</button>
        <button class="btn-icon" data-action="delete" title="Remove key" aria-label="Remove key">🗑</button>
      </div>
      ${detailsHtml}
    `;

    if (entry.expanded) {
      card.classList.add('expanded');
    }
  }

  function attachCardEvents(card, entry) {
    card.addEventListener('click', (e) => {
      if (e.target.closest('[data-action]')) return;
      entry.expanded = !entry.expanded;
      card.classList.toggle('expanded', entry.expanded);
    });

    card.querySelectorAll('[data-action]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;
        if (action === 'reveal') {
          entry.revealed = !entry.revealed;
          renderAllCards();
        } else if (action === 'copy') {
          copyToClipboard(entry.key);
          btn.textContent = '✓';
          setTimeout(() => { btn.textContent = '📋'; }, 1500);
        } else if (action === 'delete') {
          state.keys = state.keys.filter((k) => k.key !== entry.key);
          card.remove();
          updateStats();
          saveKeys();
          if (state.keys.length === 0) {
            els.emptyState.classList.remove('hidden');
            els.emptyState.querySelector('p').textContent = 'No API keys found. Paste text containing keys above.';
          }
        }
      });
    });
  }

  // ── Sort & Filter ────────────────────────────────────────
  function getFilteredKeys() {
    if (state.filterBy === 'all') return [...state.keys];
    if (state.filterBy === 'valid') return state.keys.filter((k) => k.status === 'valid' || k.status === 'rate-limited');
    if (state.filterBy === 'invalid') return state.keys.filter((k) => k.status === 'invalid' || k.status === 'error');
    if (state.filterBy === 'openai') return state.keys.filter((k) => k.type === 'openai');
    if (state.filterBy === 'openrouter') return state.keys.filter((k) => k.type === 'openrouter');
    if (state.filterBy === 'gemini') return state.keys.filter((k) => k.type === 'gemini');
    if (state.filterBy.startsWith('tier-')) {
      const tierName = state.filterBy === 'tier-Free' ? 'Free' : `Tier ${state.filterBy.replace('tier-', '')}`;
      return state.keys.filter((k) => k.tier === tierName);
    }
    return [...state.keys];
  }

  function getSortedKeys(keys) {
    const sorted = [...keys];
    switch (state.sortBy) {
      case 'smart':
        // First: keys with addedAt (just scanned) sorted by addedAt descending (newest first)
        // Then: old keys from storage sorted by status (valid first, then invalid/error)
        sorted.sort((a, b) => {
          const aRecent = a.addedAt && a.addedAt > 0;
          const bRecent = b.addedAt && b.addedAt > 0;

          // Both recent: sort by addedAt descending (most recent first)
          if (aRecent && bRecent) {
            return b.addedAt - a.addedAt;
          }

          // One recent, one old: recent goes first
          if (aRecent && !bRecent) return -1;
          if (!aRecent && bRecent) return 1;

          // Both old (from storage): sort by status (valid first)
          const statusPriority = { valid: 0, 'rate-limited': 0, pending: 1, checking: 2, invalid: 3, error: 4 };
          const aP = statusPriority[a.status] || 9;
          const bP = statusPriority[b.status] || 9;
          if (aP !== bP) return aP - bP;

          // Same status: sort by balance (OpenRouter) or tier level (OpenAI)
          if (a.status === 'valid' || a.status === 'rate-limited') {
            if (a.type === 'openrouter' && b.type === 'openrouter') {
              const aBal = a.balance || 0;
              const bBal = b.balance || 0;
              return bBal - aBal;
            }
            if (a.type === 'openai' && b.type === 'openai') {
              const aL = TIER_ORDER.indexOf(a.tier);
              const bL = TIER_ORDER.indexOf(b.tier);
              const aIdx = aL === -1 ? 999 : aL;
              const bIdx = bL === -1 ? 999 : bL;
              return aIdx - bIdx;
            }
            const typePriority = { openrouter: 0, gemini: 1, openai: 2 };
            return (typePriority[a.type] || 9) - (typePriority[b.type] || 9);
          }

          return 0;
        });
        break;
      case 'tier':
        sorted.sort((a, b) => {
          const aL = TIER_ORDER.indexOf(a.tier);
          const bL = TIER_ORDER.indexOf(b.tier);
          const aIdx = aL === -1 ? 999 : aL;
          const bIdx = bL === -1 ? 999 : bL;
          return aIdx - bIdx;
        });
        break;
      case 'status':
        const statusOrder = { valid: 0, 'rate-limited': 1, invalid: 2, error: 3, checking: 4, pending: 5 };
        sorted.sort((a, b) => (statusOrder[a.status] || 9) - (statusOrder[b.status] || 9));
        break;
      case 'rpm':
        sorted.sort((a, b) => (b.rpm || 0) - (a.rpm || 0));
        break;
      case 'tpm':
        sorted.sort((a, b) => (b.tpm || 0) - (a.tpm || 0));
        break;
      case 'type':
        sorted.sort((a, b) => {
          const typeOrder = { openrouter: 0, openai: 1, gemini: 2 };
          return (typeOrder[a.type] || 9) - (typeOrder[b.type] || 9);
        });
        break;
    }
    return sorted;
  }

  // ── Clipboard ────────────────────────────────────────────
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
  }

  // ── Format Numbers ───────────────────────────────────────
  function formatNum(n) {
    if (!n || n === 0) return '—';
    if (n >= 1000000) {
      const m = n / 1000000;
      const formatted = m % 1 === 0 ? m.toString() : m.toFixed(1);
      return formatted + 'M';
    }
    if (n >= 1000) {
      const k = n / 1000;
      const formatted = k % 1 === 0 ? k.toString() : k.toFixed(1);
      return formatted + 'K';
    }
    return n.toString();
  }

  // ── Format Balance (USD) ─────────────────────────────────
  function formatBalance(n) {
    if (n === null || n === undefined) return '—';
    if (n === 0) return '0.00';
    // Show up to 2 decimal places, strip trailing zeros after 2
    const fixed = n.toFixed(2);
    return fixed;
  }

  // ── Handle Check ─────────────────────────────────────────
  async function handleCheck() {
    const bulkText = els.bulkInput.value.trim();

    let keys = [];
    if (bulkText) {
      keys = extractKeys(bulkText);
    }

    keys = [...new Set(keys)];

    if (keys.length === 0) {
      els.emptyState.classList.remove('hidden');
      els.emptyState.querySelector('p').textContent = 'No API keys found. Paste text containing keys above.';
      els.resultsList.innerHTML = '';
      els.extractBanner.classList.add('hidden');
      return;
    }

    // Show extraction count
    const existingKeys = new Set(state.keys.map((k) => k.key));
    const newKeys = keys.filter((k) => !existingKeys.has(k));
    const duplicateKeys = keys.filter((k) => existingKeys.has(k));
    const skipped = keys.length - newKeys.length;

    const now = Date.now();

    // Handle duplicates: find existing entries and move them to top with new timestamp
    if (duplicateKeys.length > 0) {
      duplicateKeys.forEach((dupKey) => {
        const idx = state.keys.findIndex((k) => k.key === dupKey);
        if (idx !== -1) {
          const [entry] = state.keys.splice(idx, 1);
          entry.addedAt = now;
          entry.status = 'pending';
          state.keys.unshift(entry);
        }
      });
    }

    // Add new keys at the beginning
    if (newKeys.length > 0) {
      const newEntries = newKeys.map((k) => ({
        key: k,
        status: 'pending',
        type: detectKeyType(k),
        tier: 'Unknown',
        rpm: 0,
        tpm: 0,
        rpmRemaining: 0,
        tpmRemaining: 0,
        balance: null,
        balanceLimit: null,
        isFreeTier: false,
        usage: 0,
        responseTime: 0,
        orTotalCredits: null,
        orTotalUsage: null,
        orKeyLimit: null,
        orKeyLimitRemaining: null,
        orKeyUsageDaily: null,
        addedAt: now,
        headers: null,
        error: null,
        errorFull: null,
        expanded: false,
        revealed: false,
      }));
      // Add at beginning (after duplicates which are already at beginning)
      state.keys = [...newEntries, ...state.keys];
    }

    els.extractCount.textContent = keys.length;
    els.extractNew.textContent = newKeys.length;
    els.extractBanner.classList.remove('hidden');

    // Update banner text for duplicates
    if (skipped > 0) {
      els.extractBanner.innerHTML = `<span class="extract-count">${keys.length}</span> keys found · <span class="extract-new">${newKeys.length}</span> new · ${skipped} rechecked`;
    }

    els.emptyState.classList.add('hidden');

    // Render all cards
    renderAllCards();
    updateStats();

    // Validate all keys (new + duplicates)
    await batchValidate([...newKeys, ...duplicateKeys]);

    renderAllCards();
    updateStats();
  }

  // ── Copy All Valid Keys ──────────────────────────────────
  async function copyAllValid() {
    const validKeys = state.keys
      .filter((k) => k.status === 'valid' || k.status === 'rate-limited')
      .map((k) => k.key);

    if (validKeys.length === 0) return;

    await copyToClipboard(validKeys.join('\n'));
    els.copyAllBtn.textContent = '✓ Copied!';
    setTimeout(() => { els.copyAllBtn.textContent = 'Copy All Valid Keys'; }, 2000);
  }

  // ── Sort/Filter Controls ─────────────────────────────────
  function setupControls() {
    els.sortBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        els.sortBtns.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.sortBy = btn.dataset.sort;
        renderAllCards();
      });
    });

    els.filterBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        els.filterBtns.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.filterBy = btn.dataset.filter;
        renderAllCards();
      });
    });
  }

  // ── Init ─────────────────────────────────────────────────
  function init() {
    cacheEls();
    setupControls();

    // Load saved keys from localStorage (encrypted)
    const saved = loadKeys();
    if (saved.length > 0) {
      state.keys = saved;
      renderAllCards();
      updateStats();
    }

    els.checkBtn.addEventListener('click', handleCheck);
    els.copyAllBtn.addEventListener('click', copyAllValid);

    // Ctrl+Enter to check
    els.bulkInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) handleCheck();
    });

    // CORS probe on load
    probeCORS();
  }

  // Boot
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();