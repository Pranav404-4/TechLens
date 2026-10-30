const api = typeof browser !== "undefined" ? browser : chrome;

// Store only the latest main-document response headers per tab.
const recentHeaders = new Map();

const ALLOWED_HEADERS = new Set([
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-vercel-id",
  "cf-ray",
  "x-amz-cf-id",
  "x-amz-request-id",
  "x-nf-request-id",
  "x-render-origin-server",
  "x-runtime",
  "x-application-context",
  "x-varnish",
  "via",
  "x-cache",
  "x-drupal-cache",
  "x-generator",
  // Browser security headers
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cross-origin-embedder-policy",
]);

// Clear old headers as soon as a new main-page request starts.
api.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0 || details.type !== "main_frame") return;
    recentHeaders.delete(details.tabId);
  },
  {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame"],
  },
);

// Capture headers from the main document only.
// Ignore subframes and API/XHR responses to reduce false positives.
api.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (
      details.tabId < 0 ||
      details.type !== "main_frame" ||
      details.frameId !== 0
    ) {
      return;
    }

    const safeHeaders = (details.responseHeaders || [])
      .filter(
        (header) =>
          header.name && ALLOWED_HEADERS.has(header.name.toLowerCase()),
      )
      .map((header) => ({
        name: header.name,
        value: String(header.value || ""),
      }));

    // Replace rather than merge, so old server clues cannot linger.
    recentHeaders.set(details.tabId, safeHeaders);
  },
  {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame"],
  },
  ["responseHeaders"],
);

// Remove cached data when a tab closes.
api.tabs.onRemoved.addListener((tabId) => {
  recentHeaders.delete(tabId);
});

// Keep the message format compatible with popup.js.
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "TECHLENS_GET_HEADERS") {
    const captured = recentHeaders.has(message.tabId);

    sendResponse({
      headers: recentHeaders.get(message.tabId) || [],
      captured,
    });
  }
});
