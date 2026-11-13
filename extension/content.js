(() => {
  if (window.top !== window || window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  const BRAND_PATTERNS = [
    "kaspi", "каспи",
    "halyk", "халык",
    "egov",
    "freedom bank", "freedombank", "фридом",
    "jusan", "жусан",
    "kazpost", "казпочта",
    "google", "paypal", "apple", "icloud", "microsoft",
    "facebook", "instagram", "telegram",
  ];

  const STYLE = `
    :host { all: initial; }
    .bar {
      box-sizing: border-box;
      width: 100%;
      padding: 14px 20px;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
      color: #fff;
      display: flex;
      gap: 16px;
      align-items: flex-start;
      box-shadow: 0 4px 18px rgba(0, 0, 0, 0.25);
    }
    .danger { background: #b91c1c; }
    .warn { background: #fde68a; color: #422006; }
    .icon {
      flex: none;
      width: 36px;
      height: 36px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      font-weight: 800;
      font-size: 22px;
      background: rgba(255, 255, 255, 0.2);
    }
    .warn .icon { background: rgba(66, 32, 6, 0.12); }
    .body { flex: 1; min-width: 0; }
    .title { font-size: 16px; font-weight: 700; margin: 0 0 2px; }
    .risk { font-weight: 600; opacity: 0.9; }
    ul { margin: 6px 0 0; padding-left: 18px; }
    li { margin: 2px 0; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    button {
      font: inherit;
      font-weight: 600;
      border-radius: 6px;
      padding: 7px 14px;
      cursor: pointer;
      border: 1px solid transparent;
    }
    .primary { background: #fff; color: #b91c1c; }
    .ghost { background: transparent; color: inherit; border-color: currentColor; opacity: 0.85; }
    .close {
      flex: none;
      background: transparent;
      color: inherit;
      font-size: 20px;
      line-height: 1;
      padding: 4px 8px;
    }
    button:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
  `;

  let bannerHost = null;

  function hostKey(hostname) {
    return hostname.toLowerCase().replace(/^www\./, "");
  }

  function sameSite(a, b) {
    return a === b || a.endsWith("." + b) || b.endsWith("." + a);
  }

  function collectPage() {
    const here = hostKey(location.hostname);
    const hasPassword = Boolean(document.querySelector('input[type="password"]'));
    let external = false;
    for (const form of document.forms) {
      if (!form.querySelector('input[type="password"], input[type="email"]')) continue;
      const action = form.getAttribute("action");
      if (!action || /^\s*javascript:/i.test(action)) continue;
      let target;
      try {
        target = new URL(action, location.href);
      } catch {
        continue;
      }
      if (target.protocol !== "http:" && target.protocol !== "https:") continue;
      if (!sameSite(hostKey(target.hostname), here)) {
        external = true;
        break;
      }
    }
    const title = (document.title || "").trim().slice(0, 300);
    const lower = title.toLowerCase();
    const brand = BRAND_PATTERNS.find((pattern) => lower.includes(pattern)) || null;
    return {
      has_password_field: hasPassword,
      form_action_external: external,
      brand_in_title: brand,
      title: title || null,
    };
  }

  function send(message) {
    try {
      return chrome.runtime.sendMessage(message);
    } catch {
      return Promise.resolve(null);
    }
  }

  function removeBanner() {
    if (bannerHost) bannerHost.remove();
    bannerHost = null;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function showBanner(result) {
    removeBanner();
    const danger = result.verdict === "phishing";

    bannerHost = document.createElement("div");
    bannerHost.style.cssText =
      "all: initial; position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;";
    const root = bannerHost.attachShadow({ mode: "closed" });
    root.appendChild(el("style", null, STYLE));

    const bar = el("div", `bar ${danger ? "danger" : "warn"}`);
    bar.setAttribute("role", "alert");
    bar.appendChild(el("div", "icon", "!"));

    const body = el("div", "body");
    const title = el(
      "p",
      "title",
      danger ? "PhishGuard: вероятно, это фишинговый сайт" : "PhishGuard: сайт выглядит подозрительно"
    );
    body.appendChild(title);
    body.appendChild(el("span", "risk", `Оценка риска: ${result.risk} из 100 · ${result.domain}`));

    const reasons = (result.reasons || []).slice(0, 3);
    if (reasons.length) {
      const list = el("ul");
      reasons.forEach((reason) => list.appendChild(el("li", null, reason)));
      body.appendChild(list);
    }

    if (danger) {
      const actions = el("div", "actions");
      const leave = el("button", "primary", "Уйти со страницы");
      leave.type = "button";
      leave.addEventListener("click", () => send({ type: "leave" }));
      const proceed = el("button", "ghost", "Всё равно продолжить");
      proceed.type = "button";
      proceed.addEventListener("click", () => {
        send({ type: "allow" });
        removeBanner();
      });
      actions.append(leave, proceed);
      body.appendChild(actions);
    }
    bar.appendChild(body);

    if (!danger) {
      const close = el("button", "close", "×");
      close.type = "button";
      close.setAttribute("aria-label", "Закрыть предупреждение");
      close.addEventListener("click", () => {
        send({ type: "allow" });
        removeBanner();
      });
      bar.appendChild(close);
    }

    root.appendChild(bar);
    document.documentElement.appendChild(bannerHost);
  }

  function handle(response) {
    if (!response || !response.state) return;
    const { state, allowed } = response;
    if (state.status !== "ok" || allowed) {
      removeBanner();
      return;
    }
    const verdict = state.result.verdict;
    if (verdict === "phishing" || verdict === "suspicious") {
      showBanner(state.result);
    } else {
      removeBanner();
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === "result") handle(message);
  });

  Promise.resolve(send({ type: "check", page: collectPage() }))
    .then(handle)
    .catch(() => {});
})();
