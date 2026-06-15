/**
 * @file warning.js
 * @description PhishGuard Warning Page Controller
 *
 * This script runs exclusively on warning.html — a chrome-extension:// page,
 * not an injected content script. That distinction matters:
 *
 *   • It has access to the `chrome` extension API (same as background.js)
 *     because it runs in the extension's own origin.
 *   • It does NOT have access to the visited page's DOM — it is a full
 *     page replacement, not an overlay.
 *   • All data about the intercepted URL is passed via URL query parameters
 *     (set by background.js when it called chrome.tabs.update). This avoids
 *     any need for async storage reads just to render the initial UI.
 *
 * Flow:
 *   background.js detects phishing
 *     → calls chrome.tabs.update(tabId, { url: 'warning.html?url=…&confidence=…' })
 *     → browser navigates tab to warning.html
 *     → this script reads query params and renders the threat details
 *     → user clicks "Back to Safety" or "Proceed anyway"
 *     → this script sends a message to background.js to handle the navigation
 */

'use strict';

// ─── Query Parameter Utilities ────────────────────────────────────────────────

/**
 * Reads a single URL query parameter from the current page URL.
 * Returns a fallback value if the key is absent or parsing fails.
 *
 * @param {string} key      - Parameter name (e.g. 'url', 'confidence').
 * @param {string} fallback - Returned when the key is missing or invalid.
 * @returns {string}
 */
function getParam(key, fallback = '') {
  try {
    return new URLSearchParams(window.location.search).get(key) ?? fallback;
  } catch {
    return fallback;
  }
}

// ─── Risk Classification ──────────────────────────────────────────────────────

/**
 * Maps a confidence score (0.0–1.0) to a human-readable risk tier label
 * and a corresponding display color. Thresholds are intentionally conservative —
 * anything above 0.45 is treated as at least medium risk.
 *
 * @param {number} score - Clamped confidence score in [0, 1].
 * @returns {{ label: string, color: string }}
 */
function classifyRisk(score) {
  if (score >= 0.85) return { label: 'CRITICAL RISK', color: '#ff3040' };
  if (score >= 0.65) return { label: 'HIGH RISK',     color: '#ff5c30' };
  if (score >= 0.45) return { label: 'MEDIUM RISK',   color: '#ff8c00' };
  return                     { label: 'LOW RISK',      color: '#ffcc00' };
}

// ─── DOM Rendering ────────────────────────────────────────────────────────────

/**
 * Reads both URL parameters injected by background.js, validates them,
 * and populates the warning page's DOM with the threat details.
 *
 * SECURITY: All user-facing values are set via .textContent, NEVER .innerHTML.
 * A crafted URL like `https://evil.com/<script>alert(1)</script>` would be
 * rendered as literal text rather than parsed as markup, preventing XSS.
 *
 * @returns {{ maliciousUrl: string, confidence: number }} Parsed values,
 *   exposed so action handlers can reference them without re-parsing.
 */
function renderThreatDetails() {
  // ── Parse parameters ─────────────────────────────────────────────────────

  const maliciousUrl  = getParam('url', '[URL not available]');
  const rawConfidence = parseFloat(getParam('confidence', '0'));

  // Clamp to [0, 1] to guard against malformed or out-of-range values
  const confidence = Math.max(0, Math.min(1, isNaN(rawConfidence) ? 0 : rawConfidence));
  const pctStr     = (confidence * 100).toFixed(1) + '%';
  const risk       = classifyRisk(confidence);

  // ── Update document title ────────────────────────────────────────────────
  // Show the hostname in the tab title so the user can see at a glance which
  // site triggered the warning, even without reading the page body.
  try {
    const hostname    = new URL(maliciousUrl).hostname;
    document.title    = `⚠ PhishGuard — Threat at ${hostname}`;
  } catch {
    document.title    = '⚠ PhishGuard — Threat Detected';
  }

  // ── Malicious URL display ────────────────────────────────────────────────
  const urlEl = document.getElementById('js-url');
  if (urlEl) {
    // CRITICAL: .textContent, not .innerHTML
    urlEl.textContent = maliciousUrl;
  }

  // ── Confidence percentage ────────────────────────────────────────────────
  const pctEl = document.getElementById('js-pct');
  if (pctEl) {
    pctEl.textContent = pctStr;
    pctEl.style.color = risk.color;
  }

  // ── Risk label ───────────────────────────────────────────────────────────
  const riskEl = document.getElementById('js-risk-label');
  if (riskEl) {
    riskEl.textContent = risk.label;
    riskEl.style.color = risk.color;
  }

  // ── Confidence progress bar ──────────────────────────────────────────────
  // The bar fill width is controlled by the CSS variable --score.
  // Setting it inside requestAnimationFrame ensures the browser has painted
  // the initial state (--score: 0) first, so the CSS transition fires and
  // the bar visually "loads in" from zero to the actual value.
  const barFill  = document.getElementById('js-bar');
  const barTrack = barFill?.closest('[role="progressbar"]');

  if (barFill) {
    requestAnimationFrame(() => {
      barFill.style.setProperty('--score', String(confidence));
    });
  }

  if (barTrack) {
    barTrack.setAttribute('aria-valuenow', String(Math.round(confidence * 100)));
  }

  // Return parsed values so handlers can use them without re-reading the DOM
  return { maliciousUrl, confidence };
}

// ─── Action: Back to Safety ───────────────────────────────────────────────────

/**
 * Handles clicks on the "Back to Safety" button.
 *
 * Sends a NAVIGATE_BACK message to background.js, which has the `tabs`
 * permission needed to call chrome.tabs.update(). The background script
 * redirects the tab to chrome://newtab/ — a clean and unambiguously safe
 * starting point.
 *
 * A fallback path handles the edge case where the background service worker
 * is unavailable (e.g., being updated, crashed).
 */
function handleBackToSafety() {
  const btn = document.getElementById('js-btn-safe');

  // Disable immediately on first click to prevent double-triggering
  if (btn) {
    btn.disabled    = true;
    btn.textContent = 'Navigating to safety…';
  }

  // Send message to background service worker
  chrome.runtime.sendMessage({ type: 'NAVIGATE_BACK' }, (response) => {
    if (chrome.runtime.lastError) {
      /*
       * Background script is unavailable. This can happen briefly during
       * extension updates. Fall back to the history API.
       *
       * history.back() should return to the page before the phishing attempt.
       * Because onBeforeNavigate fires before the navigation commits, the
       * phishing site is usually NOT in history — one step back typically
       * lands on the last safe page.
       */
      console.warn('[PhishGuard] Background unavailable, falling back to history.back()');
      if (window.history.length > 1) {
        window.history.back();
      } else {
        // No history at all (e.g., the phishing link opened a new tab)
        window.close();
      }
    }
    // If response is successful, background.js has already updated the tab.
    // No further action needed here — the page will be replaced.
  });
}

// ─── Action: Proceed Anyway ───────────────────────────────────────────────────

/**
 * Handles clicks on the "Proceed anyway (Unsafe)" button.
 *
 * This is a two-phase operation:
 *
 *   Phase 1 — Confirm: Show a native browser dialog requiring the user to
 *             explicitly acknowledge the risk. This creates friction by design.
 *
 *   Phase 2 — Whitelist + Navigate: Send a PROCEED_ANYWAY message to background.js,
 *             which adds the URL to a one-time session whitelist BEFORE navigating.
 *             Without the whitelist step, the navigation listener in background.js
 *             would immediately intercept the URL again and redirect to THIS page,
 *             creating an infinite loop.
 *
 * @param {string} maliciousUrl - The original URL to navigate to.
 */
function handleProceedAnyway(maliciousUrl) {
  // ── Phase 1: Confirmation dialog ─────────────────────────────────────────
  // window.confirm() is a blocking call — execution pauses until the user
  // makes a choice. This intentionally breaks any "auto-click" flow.
  const confirmed = window.confirm(
    '⚠ WARNING — This site has been flagged as PHISHING.\n\n' +
    `URL: ${maliciousUrl}\n\n` +
    'Continuing may expose your passwords, financial information, and ' +
    'personal data to theft.\n\n' +
    'Do you accept full responsibility and wish to proceed?'
  );

  if (!confirmed) return; // User cancelled — do nothing

  // ── Phase 2: Whitelist URL and navigate ───────────────────────────────────
  // Disable the button while the async message completes to prevent
  // duplicate clicks during the round-trip to background.js.
  const btn = document.getElementById('js-link-proceed');
  if (btn) btn.disabled = true;

  chrome.runtime.sendMessage(
    { type: 'PROCEED_ANYWAY', url: maliciousUrl },
    (response) => {
      if (chrome.runtime.lastError || !response?.success) {
        /*
         * Background script was unavailable or returned an error.
         *
         * FALLBACK: Navigate directly without whitelisting.
         * The user will see the warning page again immediately (because
         * the background listener will re-intercept). This is degraded UX
         * but the correct safe behavior — better than silently ignoring
         * the failure.
         */
        console.warn(
          '[PhishGuard] Could not whitelist URL. User will see warning again.',
          chrome.runtime.lastError?.message
        );
        window.location.href = maliciousUrl;
      }
      /*
       * If the message succeeded, background.js has already:
       *   1. Added maliciousUrl to chrome.storage.session['allowedOnce']
       *   2. Called chrome.tabs.update(tabId, { url: maliciousUrl })
       * The tab navigation is now in progress — no further action here.
       */
    }
  );
}

// ─── Initialisation ───────────────────────────────────────────────────────────

/**
 * Entry point. Runs after the DOM is fully parsed.
 *
 * Rendering and event binding are deliberately separated so that each can be
 * tested or replaced independently without touching the other.
 */
document.addEventListener('DOMContentLoaded', () => {

  // Step 1: Parse query params and populate the DOM with threat data
  const { maliciousUrl } = renderThreatDetails();

  // Step 2: Wire up the "Back to Safety" button
  const btnSafe = document.getElementById('js-btn-safe');
  if (btnSafe) {
    btnSafe.addEventListener('click', handleBackToSafety);
  }

  // Step 3: Wire up the "Proceed anyway" link
  // Note: maliciousUrl is closed over from renderThreatDetails() to avoid
  // reading it from the DOM again (which could theoretically be tampered with
  // via a devtools injection in an edge case, whereas the parsed value is stable).
  const btnProceed = document.getElementById('js-link-proceed');
  if (btnProceed) {
    btnProceed.addEventListener('click', () => handleProceedAnyway(maliciousUrl));
  }

});
