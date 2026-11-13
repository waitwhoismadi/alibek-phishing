const VERDICT_LABELS = {
  safe: "Безопасно",
  suspicious: "Подозрительно",
  phishing: "Фишинг",
};

const $ = (id) => document.getElementById(id);

function show(sectionId) {
  for (const section of document.querySelectorAll(".state")) {
    section.hidden = section.id !== sectionId;
  }
}

function setMeter(key, value) {
  const bar = $(`m-${key}`);
  const label = $(`v-${key}`);
  if (value === null || value === undefined) {
    bar.style.width = "0";
    bar.className = "";
    label.textContent = "—";
    return;
  }
  const pct = Math.round(value * 100);
  bar.style.width = `${pct}%`;
  bar.className = pct >= 70 ? "lvl-high" : pct >= 40 ? "lvl-mid" : "lvl-low";
  label.textContent = String(pct);
}

function renderResult(state) {
  const result = state.result;
  const section = $("result");
  section.className = `state is-${result.verdict}`;
  $("domain").textContent = result.domain;
  $("risk").textContent = String(result.risk);
  $("verdict").textContent = VERDICT_LABELS[result.verdict] || result.verdict;

  const list = $("reasons");
  list.replaceChildren();
  const reasons = result.reasons || [];
  if (reasons.length) {
    for (const reason of reasons) {
      const li = document.createElement("li");
      li.textContent = reason;
      list.appendChild(li);
    }
  } else {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "Признаков фишинга не найдено";
    list.appendChild(li);
  }

  setMeter("ml", result.scores.ml);
  setMeter("rep", result.scores.reputation);
  setMeter("content", result.scores.content);

  const parts = [];
  if (result.scores.content === null) parts.push("данные страницы не учитывались");
  if (result.cached) parts.push("из кэша");
  else if (typeof result.elapsed_ms === "number") parts.push(`проверено за ${result.elapsed_ms} мс`);
  $("meta").textContent = parts.join(" · ");
  show("result");
}

function render(state) {
  const button = $("recheck");
  button.disabled = false;
  if (!state || state.status === "error") {
    $("error-text").textContent = (state && state.error) || "Не удалось связаться с сервером PhishGuard.";
    show("error");
    return;
  }
  if (state.status === "skipped") {
    button.disabled = true;
    show("skipped");
    return;
  }
  renderResult(state);
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function load(force) {
  $("recheck").disabled = true;
  show("loading");
  try {
    const tab = await activeTab();
    if (!tab) {
      render({ status: "skipped" });
      return;
    }
    const state = await chrome.runtime.sendMessage({ type: force ? "recheck" : "getState", tabId: tab.id });
    render(state);
  } catch (error) {
    render({ status: "error", error: error.message });
  }
}

$("recheck").addEventListener("click", () => load(true));
load(false);
