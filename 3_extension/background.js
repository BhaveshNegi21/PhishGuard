/**
 * @file background.js
 * @description PhishGuard — MV3 Service Worker
 *              URL interception, phishing detection, and tab redirect engine.
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  CRITICAL MV3 ARCHITECTURE NOTE — UNDERSTAND BEFORE EDITING
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  In Manifest V2, extensions used a PERSISTENT background page — a hidden
 *  HTML page that stayed alive for the entire browser session, holding state
 *  in memory and keeping listeners always-attached.
 *
 *  In Manifest V3, that model is GONE. Background pages are replaced by
 *  SERVICE WORKERS, which follow a fundamentally different lifecycle:
 *
 *    ┌─────────────────────────────────────────────────────────────────┐
 *    │  IDLE → [browser terminates worker] → TERMINATED               │
 *    │                    ↑                       ↓                   │
 *    │              (no events)          [event fires]                 │
 *    │                                       ↓                        │
 *    │                                   STARTING                     │
 *    │                                       ↓                        │
 *    │                               [script executes                 │
 *    │                                top-level code]                 │
 *    │                                       ↓                        │
 *    │                                   ACTIVE → handles event       │
 *    └─────────────────────────────────────────────────────────────────┘
 *
 *  KEY IMPLICATIONS:
 *
 *  1. THE WORKER CAN BE TERMINATED AT ANY TIME after ~30 seconds of idle.
 *     Any in-memory state (variables, Maps, Sets) is LOST on termination.
 *     For persistent state, use chrome.storage.session or chrome.storage.local.
 *
 *  2. THE WORKER IS REVIVED when a registered event fires. The browser
 *     re-executes this entire script from the top before dispatching the event.
 *
 *  3. THIS IS THE MOST COMMON MV3 FAILURE POINT:
 *     All chrome.* event listeners MUST be registered SYNCHRONOUSLY at the
 *     TOP LEVEL of this script. If a listener is registered inside an async
 *     function, a .then() callback, or any deferred context, it will NOT exist
 *     by the time the script finishes its synchronous setup pass — and the
 *     browser will consider the event "unhandled" and drop it silently.
 *
 *     ✅ CORRECT:
 *        chrome.webNavigation.onBeforeNavigate.addListener(async (details) => { … });
 *
 *     ❌ WRONG (listener is registered asynchronously — will miss events):
 *        chrome.storage.local.get('config', () => {
 *          chrome.webNavigation.onBeforeNavigate.addListener(…); // Never fires!
 *        });
 *
 *  4. The `async` keyword on the CALLBACK is fine — the REGISTRATION is sync.
 *     The event system captures a reference to the callback at registration time,
 *     which happens during the synchronous top-level execution.
 *
 * ════════════════════════════════════════════════════════════════════════════
 */

'use strict';

// ─── Configuration ────────────────────────────────────────────────────────────

/** Local FastAPI backend endpoint. Must match the server's address and port. */
const API_ENDPOINT = 'http://localhost:8000/scan';

/**
 * Maximum time (ms) to wait for the scan API before giving up.
 * If exceeded, we FAIL OPEN — the user is allowed through rather than
 * blocked indefinitely because the backend is slow or unreachable.
 * A fast local API should resolve well under 500ms.
 */
const API_TIMEOUT_MS = 3000;

/**
 * How long (ms) to cache a scan result for a given URL.
 * Prevents redundant API calls when a user navigates back and forth.
 *
 * ⚠️  This cache is in module scope (in-memory). It WILL be cleared if the
 *     service worker is terminated. For persistent caching, migrate to
 *     chrome.storage.session. In-memory is acceptable here because a cold
 *     cache only means one extra API round-trip, not a security failure.
 */
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ─── In-Memory Scan Cache ─────────────────────────────────────────────────────

/**
 * Cache map: URL string → { result: ApiResult, timestamp: number }
 * Keyed by exact URL. Eviction is TTL-based, checked on each read.
 *
 * @type {Map<string, { result: { is_phishing: boolean, confidence_score: number }, timestamp: number }>}
 */
const scanCache = new Map();

// ─── Utility Functions ────────────────────────────────────────────────────────

/**
 * Constructs the full chrome-extension:// URL for the warning page,
 * embedding the intercepted URL and confidence score as query parameters
 * so warning.js can read them without any back-channel messaging.
 *
 * @param {string} maliciousUrl    - The URL flagged as phishing.
 * @param {number} confidenceScore - Model confidence score in range [0.0, 1.0].
 * @returns {string}
 */
function buildWarningUrl(maliciousUrl, confidenceScore) {
  const base   = chrome.runtime.getURL('warning.html');
  const params = new URLSearchParams({
    url:        maliciousUrl,
    confidence: String(confidenceScore),
  });
  return `${base}?${params.toString()}`;
}

/**
 * Queries the FastAPI backend to determine whether a URL is a phishing site.
 * Implements a timeout via AbortController and caches successful responses.
 *
 * Returns null on any error (timeout, network failure, non-OK HTTP status),
 * which the caller interprets as "fail open" — do NOT block the navigation.
 *
 * @param {string} url - The URL to scan.
 * @returns {Promise<{ is_phishing: boolean, confidence_score: number } | null>}
 */
async function fetchScanResult(url) {
  // ── Cache check ────────────────────────────────────────────────────────────
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    console.debug(`[PhishGuard] Cache HIT → ${url}`);
    return cached.result;
  }

  // ── Timeout mechanism ──────────────────────────────────────────────────────
  // fetch() itself has no built-in timeout. We use AbortController to cancel
  // the request if it takes longer than API_TIMEOUT_MS.
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const response = await fetch(API_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
      signal:  controller.signal,
    });

    clearTimeout(timeoutHandle);

    if (!response.ok) {
      // HTTP error (4xx / 5xx). Log and fail open.
      console.warn(`[PhishGuard] API returned HTTP ${response.status} for: ${url}`);
      return null;
    }

    const result = await response.json();

    // Validate shape before caching to avoid acting on malformed responses
    if (typeof result.is_phishing !== 'boolean') {
      console.warn('[PhishGuard] API response missing `is_phishing` boolean field.');
      return null;
    }

    // Store in cache
    scanCache.set(url, { result, timestamp: Date.now() });
    return result;

  } catch (err) {
    clearTimeout(timeoutHandle);

    if (err.name === 'AbortError') {
      console.warn(`[PhishGuard] Scan timed out after ${API_TIMEOUT_MS}ms for: ${url}`);
    } else {
      // Network error (API server not running, CORS issue, etc.)
      console.error('[PhishGuard] Scan network error:', err.message);
    }

    // FAIL OPEN: allow navigation rather than blocking users when the
    // backend is unreachable. Security tools that fail closed on every
    // backend outage destroy user trust quickly.
    return null;
  }
}

// ─── Core Navigation Listener ─────────────────────────────────────────────────
//
// ⚠️  REGISTERED AT TOP LEVEL — THIS IS MANDATORY FOR MV3.
//     See the architecture note at the top of this file for the full rationale.
//
//     The `async` keyword on the callback is fine — it's the `.addListener()`
//     call itself that must happen synchronously, not the callback's body.
//     The browser captures a reference to the function at registration time.

chrome.webNavigation.onBeforeNavigate.addListener(

  async (details) => {
    // ── Guard 1: Main-frame only ───────────────────────────────────────────
    // frameId === 0 is always the top-level page. frameId > 0 are iframes,
    // embedded frames, etc. We only intercept top-level navigations to avoid
    // flooding the API with every ad pixel and analytics beacon.
    if (details.frameId !== 0) return;

    const { url, tabId } = details;

    // ── Guard 2: HTTP/HTTPS only ───────────────────────────────────────────
    // The URL filter on the listener (second argument below) already does this,
    // but we double-check in case of edge cases. We never scan chrome://, file://,
    // data:, blob:, or any other scheme.
    if (!url.startsWith('http://') && !url.startsWith('https://')) return;

    // ── Guard 3: Skip our own extension pages ─────────────────────────────
    // Without this guard, redirecting to warning.html would trigger this listener
    // again, creating an infinite redirect loop:
    //   phishing.com → warning.html → scan warning.html → redirect → warning.html → …
    const extensionOrigin = chrome.runtime.getURL('');
    if (url.startsWith(extensionOrigin)) return;

    // ── Guard 4: One-time user-approved bypass (proceed-anyway whitelist) ──
    // When the user clicks "Proceed anyway" on warning.html, background.js adds
    // the URL to chrome.storage.session under the 'allowedOnce' key. We check
    // that here, consume the entry (one-time only), and skip the scan so the
    // user reaches their intended destination without being re-blocked.
    try {
      const { allowedOnce = [] } = await chrome.storage.session.get('allowedOnce');

      if (allowedOnce.includes(url)) {
        console.info(`[PhishGuard] User-approved bypass → ${url}`);

        // Remove the URL from the whitelist immediately — single use only
        await chrome.storage.session.set({
          allowedOnce: allowedOnce.filter((u) => u !== url),
        });

        return; // Allow navigation to proceed uninterrupted
      }
    } catch (storageErr) {
      // chrome.storage.session is available in MV3 (Chrome 102+).
      // Log and continue rather than blocking navigation on a storage error.
      console.warn('[PhishGuard] Session storage read failed:', storageErr.message);
    }

    // ── Scan the URL ───────────────────────────────────────────────────────
    console.debug(`[PhishGuard] Scanning → ${url}`);
    const scanResult = await fetchScanResult(url);

    // Null result means API was unavailable — fail open, allow navigation
    if (!scanResult) return;

    // ── Redirect to warning page if phishing is detected ──────────────────
    if (scanResult.is_phishing === true) {
      const score = scanResult.confidence_score ?? 0;

      console.warn(
        `[PhishGuard] 🚨 PHISHING DETECTED\n` +
        `  URL:        ${url}\n` +
        `  Confidence: ${(score * 100).toFixed(1)}%`
      );

      try {
        // chrome.tabs.update() supersedes the current tab navigation.
        // Because this is called from onBeforeNavigate (before the phishing
        // page's network request has fully committed), the redirect is very
        // likely to win the race and prevent the malicious page from loading.
        //
        // ⚠️  RACE CONDITION NOTE (inherent MV3 limitation):
        //     This is NOT a synchronous block. Our async fetch means there is a
        //     window (typically 50–500ms) during which the browser may have
        //     started loading the phishing page's HTML. The tabs.update() call
        //     cancels that in-flight load. For a localhost API, this window is
        //     very small. True synchronous blocking would require the deprecated
        //     Manifest V2 `webRequest` API with the `blocking` option.
        await chrome.tabs.update(tabId, { url: buildWarningUrl(url, score) });

      } catch (tabErr) {
        // Tab was likely closed by the user during the async scan window. Safe to ignore.
        console.info('[PhishGuard] Tab no longer available for redirect:', tabErr.message);
      }
    }
  },

  // ── Event filter ────────────────────────────────────────────────────────────
  // Pre-filters events at the Chrome API level — more efficient than filtering
  // in JS. Only http:// and https:// navigations will invoke our callback.
  // This complements Guard 2 inside the callback body.
  { url: [{ schemes: ['http', 'https'] }] }

); // end chrome.webNavigation.onBeforeNavigate.addListener


// ─── Message Router ───────────────────────────────────────────────────────────
//
// warning.html communicates with this service worker via chrome.runtime.sendMessage.
// The two message types are:
//
//   NAVIGATE_BACK    → User clicked "Back to Safety"
//   PROCEED_ANYWAY   → User confirmed they want to visit the phishing site
//
// ⚠️  REGISTERED AT TOP LEVEL — same rationale as the navigation listener above.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Security: only accept messages from pages that belong to this extension.
  // This prevents a malicious website from sending us PROCEED_ANYWAY messages
  // if it somehow loaded our extension's message API.
  if (sender.id !== chrome.runtime.id) {
    console.warn('[PhishGuard] Message from unknown sender rejected:', sender.id);
    return false;
  }

  // We need a tab to act on — warning.html always has one.
  const tabId = sender.tab?.id;
  if (!tabId) return false;

  switch (message.type) {

    // ── "Back to Safety" button ──────────────────────────────────────────────
    case 'NAVIGATE_BACK': {
      // Navigate to the new-tab page — a clean, unambiguously safe destination.
      // We use the background script for this because chrome.tabs.update()
      // requires the `tabs` permission, which extension content/pages don't
      // have directly (only the service worker does via the manifest grant).
      chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
      sendResponse({ success: true });
      return false; // Synchronous response — no need to keep the channel open
    }

    // ── "Proceed anyway" link ────────────────────────────────────────────────
    case 'PROCEED_ANYWAY': {
      const targetUrl = message.url;

      if (!targetUrl) {
        sendResponse({ success: false, error: 'No URL provided in message.' });
        return false;
      }

      // Step 1: Write the URL to the one-time whitelist in session storage.
      //         The navigation listener will check this, consume it, and allow
      //         the navigation to pass through without triggering another scan.
      // Step 2: Update the tab to navigate to the original (phishing) URL.
      chrome.storage.session
        .get('allowedOnce')
        .then(({ allowedOnce = [] }) => {
          // Deduplicate in case of rapid double-clicks
          if (!allowedOnce.includes(targetUrl)) {
            allowedOnce.push(targetUrl);
          }
          return chrome.storage.session.set({ allowedOnce });
        })
        .then(() => chrome.tabs.update(tabId, { url: targetUrl }))
        .then(() => sendResponse({ success: true }))
        .catch((err) => {
          console.error('[PhishGuard] PROCEED_ANYWAY handler error:', err.message);
          sendResponse({ success: false, error: err.message });
        });

      // Return `true` to signal that sendResponse will be called asynchronously.
      // Without this, Chrome closes the message channel before the promise resolves
      // and the response is silently dropped — a very common MV3 debugging trap.
      return true;
    }

    default:
      return false;
  }
});


// ─── Lifecycle Hooks ──────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === chrome.runtime.OnInstalledReason.INSTALL) {
    console.info(
      '[PhishGuard] Extension installed.\n' +
      '  Backend expected at: ' + API_ENDPOINT + '\n' +
      '  Real-time phishing protection is now active.'
    );
    // Wipe any stale session state from a previous install/reload
    chrome.storage.session.clear();
  }

  if (reason === chrome.runtime.OnInstalledReason.UPDATE) {
    console.info('[PhishGuard] Extension updated. Clearing stale caches.');
    scanCache.clear();
    chrome.storage.session.clear();
  }
});
