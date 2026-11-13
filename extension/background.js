const API_URL = "http://localhost:8000";
const REQUEST_TIMEOUT_MS = 8000;
const CACHE_TTL_MS = 30 * 60 * 1000;
const ICON_SIZES = [16, 32, 48, 128];
const ICON_BY_VERDICT = { safe: "green", suspicious: "yellow", phishing: "red" };
const BADGE_COLORS = { safe: "#16a34a", suspicious: "#ca8a04", phishing: "#dc2626", none: "#6b7280" };
const SKIPPED_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]);

const inflight = new Map();

function iconPath(color) {
  return Object.fromEntries(ICON_SIZES.map((size) => [size, `icons/${color}-${size}.png`]));
}

function isCheckable(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    const host = parsed.hostname.toLowerCase();
    return !SKIPPED_HOSTS.has(host) && !host.endsWith(".localhost");
  } catch {
    return false;
  }
}

function domainOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

async function sessionGet(key) {
  const data = await chrome.storage.session.get(key);
  return data[key];
}

function sessionSet(key, value) {
  return chrome.storage.session.set({ [key]: value });
}

function sessionRemove(key) {
  return chrome.storage.session.remove(key);
}

async function fetchCheck(url, page) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(page ? { url, page } : { url }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Сервер вернул ошибку ${response.status}`);
    return await response.json();
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Сервер PhishGuard не ответил вовремя");
    if (error instanceof TypeError) throw new Error("Сервер PhishGuard недоступен");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function checkDomain(url, page, force) {
  const domain = domainOf(url);
  const cacheKey = `cache:${domain}`;
  if (!force) {
    const cached = await sessionGet(cacheKey);
    const fresh = cached && Date.now() - cached.ts < CACHE_TTL_MS;
    if (fresh && (cached.withPage || !page)) return { ...cached.result, cached: true };
  }
  const flightKey = `${domain}|${page ? 1 : 0}`;
  if (inflight.has(flightKey)) return inflight.get(flightKey);
  const request = fetchCheck(url, page)
    .then(async (result) => {
      await sessionSet(cacheKey, { result, ts: Date.now(), withPage: Boolean(page) });
      return result;
    })
    .finally(() => inflight.delete(flightKey));
  inflight.set(flightKey, request);
  return request;
}

async function paintAction(tabId, state) {
  const verdict = state && state.status === "ok" ? state.result.verdict : "none";
  const color = ICON_BY_VERDICT[verdict] || "grey";
  const text = verdict === "suspicious" || verdict === "phishing" ? String(state.result.risk) : "";
  try {
    await chrome.action.setIcon({ tabId, path: iconPath(color) });
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[verdict] || BADGE_COLORS.none });
  } catch {
  }
}

async function tabStillOn(tabId, domain) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return domainOf(tab.url || "") === domain;
  } catch {
    return false;
  }
}

async function runCheck(tabId, url, page, force = false) {
  if (!isCheckable(url)) {
    const state = { status: "skipped", url, domain: domainOf(url) };
    await sessionSet(`tab:${tabId}`, state);
    await paintAction(tabId, state);
    return state;
  }
  const domain = domainOf(url);
  let state;
  try {
    const result = await checkDomain(url, page, force);
    state = { status: "ok", url, domain, result, page: page || null, ts: Date.now() };
  } catch (error) {
    state = { status: "error", url, domain, error: error.message, page: page || null, ts: Date.now() };
  }
  if (await tabStillOn(tabId, domain)) {
    await sessionSet(`tab:${tabId}`, state);
    await paintAction(tabId, state);
  }
  return state;
}

async function isAllowed(domain) {
  return Boolean(await sessionGet(`allow:${domain}`));
}

async function notifyTab(tabId, state) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "result", state, allowed: await isAllowed(state.domain) });
  } catch {
  }
}

async function handleMessage(message, sender) {
  switch (message && message.type) {
    case "check": {
      if (!sender.tab) return null;
      const state = await runCheck(sender.tab.id, sender.tab.url, message.page || null);
      return { state, allowed: await isAllowed(state.domain) };
    }
    case "getState": {
      const tab = await chrome.tabs.get(message.tabId);
      const stored = await sessionGet(`tab:${tab.id}`);
      if (stored && stored.domain === domainOf(tab.url || "") && stored.status !== "error") return stored;
      return runCheck(tab.id, tab.url || "", stored ? stored.page : null);
    }
    case "recheck": {
      const tab = await chrome.tabs.get(message.tabId);
      const domain = domainOf(tab.url || "");
      const stored = await sessionGet(`tab:${tab.id}`);
      await sessionRemove([`cache:${domain}`, `allow:${domain}`]);
      const page = stored && stored.domain === domain ? stored.page : null;
      const state = await runCheck(tab.id, tab.url || "", page, true);
      await notifyTab(tab.id, state);
      return state;
    }
    case "allow": {
      if (!sender.tab) return null;
      await sessionSet(`allow:${domainOf(sender.tab.url || "")}`, true);
      return { ok: true };
    }
    case "leave": {
      if (!sender.tab) return null;
      await chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" });
      return { ok: true };
    }
    default:
      return null;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ status: "error", error: error.message }));
  return true;
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;
  const domain = domainOf(tab.url);
  const stored = await sessionGet(`tab:${tabId}`);
  if (stored && stored.domain === domain && stored.url === tab.url) return;
  const cached = isCheckable(tab.url) ? await sessionGet(`cache:${domain}`) : null;
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    const state = { status: "ok", url: tab.url, domain, result: { ...cached.result, cached: true }, page: null, ts: Date.now() };
    await sessionSet(`tab:${tabId}`, state);
    await paintAction(tabId, state);
    return;
  }
  await sessionRemove(`tab:${tabId}`);
  await paintAction(tabId, null);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  sessionRemove(`tab:${tabId}`);
});
