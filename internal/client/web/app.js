"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const els = {
  boot: $("#boot"),
  loginView: $("#loginView"),
  loginForm: $("#loginForm"),
  loginBtn: $("#loginBtn"),
  loginError: $("#loginError"),
  server: $("#server"),
  pin: $("#pin"),
  nick: $("#nick"),
  password: $("#password"),
  importInfoBtn: $("#importInfoBtn"),
  infoFile: $("#infoFile"),
  infoStatus: $("#infoStatus"),
  advancedInfo: $("#advancedInfo"),
  appView: $("#appView"),
  connPill: $("#connPill"),
  serverName: $("#serverName"),
  statSolved: $("#statSolved"),
  statTotal: $("#statTotal"),
  statSlots: $("#statSlots"),
  statOnline: $("#statOnline"),
  offlineBanner: $("#offlineBanner"),
  offlineText: $("#offlineText"),
  operatorList: $("#operatorList"),
  onlineCount: $("#onlineCount"),
  activityList: $("#activityList"),
  solverGrid: $("#solverGrid"),
  solverEmpty: $("#solverEmpty"),
  solverSearch: $("#solverSearch"),
  solverCount: $("#solverCount"),
  addSolverBtn: $("#addSolverBtn"),
  chatList: $("#chatList"),
  chatForm: $("#chatForm"),
  chatInput: $("#chatInput"),
  chatBadge: $("#chatBadge"),
  slotGrid: $("#slotGrid"),
  slotEmpty: $("#slotEmpty"),
  slotBadge: $("#slotBadge"),
  addSlotBtn: $("#addSlotBtn"),
  quotaProgress: $("#quotaProgress"),
  quotaText: $("#quotaText"),
  quota: $(".quota"),
  releasedCount: $("#releasedCount"),
  releasedList: $("#releasedList"),
  exportBtn: $("#exportBtn"),
  settingsBtn: $("#settingsBtn"),
  logoutBtn: $("#logoutBtn"),
  soundBtn: $("#soundBtn"),
  modalRoot: $("#modalRoot"),
  toastRoot: $("#toastRoot"),
};

function loadToken() {
  try {
    const fromHash = decodeURIComponent(location.hash.replace(/^#/, ""));
    const stored = sessionStorage.getItem("ctfbb-token") || "";
    const token = fromHash || stored;
    if (token) {
      sessionStorage.setItem("ctfbb-token", token);
      if (!fromHash) history.replaceState(null, "", "#" + encodeURIComponent(token));
    }
    return token;
  } catch (_) {
    return "";
  }
}

function loadSound() {
  try {
    return localStorage.getItem("ctfbb-sound") !== "off";
  } catch (_) {
    return true;
  }
}

const state = {
  token: loadToken(),
  snapshot: null,
  status: "offline",
  error: "",
  prefill: { url: "", pin: "", nick: "" },
  activeTab: "solvers",
  unread: 0,
  sound: loadSound(),
  sse: null,
  sseWarned: false,
  audio: null,
  search: "",
};

/* ---------- small helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(label, className, onClick) {
  const node = el("button", className, label);
  node.type = "button";
  if (onClick) node.addEventListener("click", onClick);
  return node;
}

function parseDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function timeAgo(value) {
  const d = parseDate(value);
  if (!d) return "";
  const diff = Date.now() - d.getTime();
  if (diff < 0) return "刚刚";
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  return d.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

function fmtDate(value) {
  const d = parseDate(value);
  if (!d) return "";
  return d.toLocaleString("zh-CN", { hour12: false });
}

function since(value) {
  const d = parseDate(value);
  if (!d) return "";
  const mins = Math.max(0, Math.floor((Date.now() - d.getTime()) / 60_000));
  if (mins < 60) return `${mins} 分钟`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} 小时 ${mins % 60} 分`;
  return `${Math.floor(hours / 24)} 天 ${hours % 24} 小时`;
}

function initial(nick) {
  const chars = Array.from(nick || "?");
  return (chars[0] || "?").toUpperCase();
}

function safeUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol === "http:" || u.protocol === "https:") return u.href;
  } catch (_) {}
  return "";
}

function toast(text, kind = "") {
  const node = el("div", "toast " + kind, text);
  els.toastRoot.append(node);
  setTimeout(() => node.remove(), 4500);
}

function hide(node) { node.classList.add("hidden"); }
function show(node) { node.classList.remove("hidden"); }

/* ---------- API ---------- */

async function api(path, options = {}) {
  const headers = Object.assign({ "X-CTFBB-Token": state.token }, options.headers || {});
  let body = options.body;
  if (body !== undefined && typeof body !== "string") {
    body = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(path, {
    method: options.method || (body !== undefined ? "POST" : "GET"),
    headers,
    body,
    cache: "no-store",
  });
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const err = new Error(data.error || `请求失败（HTTP ${res.status}）`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function cmd(command, args = {}) {
  const res = await api("/api/command", { method: "POST", body: { cmd: command, args } });
  if (!res.ok) throw new Error(res.error || "命令执行失败");
  return res.data;
}

/* ---------- sound ---------- */

function ensureAudio() {
  if (!state.sound) return null;
  try {
    if (!state.audio) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return null;
      state.audio = new Ctx();
    }
    if (state.audio.state === "suspended") state.audio.resume().catch(() => {});
    return state.audio;
  } catch (_) {
    return null;
  }
}

function playPing(kind = "chat") {
  if (!state.sound) return;
  const ctx = ensureAudio();
  if (!ctx) return;
  const notes = kind === "solve" ? [880, 1174] : [720];
  const start = ctx.currentTime + 0.01;
  notes.forEach((freq, index) => {
    const t = start + index * 0.13;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, t);
    gain.gain.setValueAtTime(0.0001, t);
    gain.gain.exponentialRampToValueAtTime(0.09, t + 0.012);
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.20);
    osc.connect(gain).connect(ctx.destination);
    osc.start(t);
    osc.stop(t + 0.22);
  });
}

function updateSoundButton() {
  els.soundBtn.textContent = state.sound ? "🔔" : "🔕";
  els.soundBtn.title = state.sound ? "提示音：开（点击静音）" : "提示音：关（点击开启）";
  els.soundBtn.setAttribute("aria-pressed", String(state.sound));
}

/* ---------- status / header ---------- */

function updateStatus() {
  const labels = {
    online: ["在线", "online"],
    connecting: ["连接中", "connecting"],
    reconnecting: ["重连中", "reconnecting"],
    kicked: ["被踢出", "kicked"],
    offline: ["离线", "offline"],
  };
  const [label, cls] = labels[state.status] || labels.offline;
  els.connPill.textContent = label;
  els.connPill.className = "pill " + cls;

  if (state.status === "online") {
    hide(els.offlineBanner);
  } else {
    show(els.offlineBanner);
    if (state.status === "reconnecting") {
      els.offlineText.textContent = "连接断开" + (state.error ? `：${state.error}` : "") + "，正在自动重连…";
    } else if (state.status === "kicked") {
      els.offlineText.textContent = "你被踢出" + (state.error ? `：${state.error}` : "") + "，冷却后会自动重连。";
    } else if (state.status === "connecting") {
      els.offlineText.textContent = "正在连接服务器…";
    } else {
      els.offlineText.textContent = state.error || "未连接。";
    }
  }
  setActionsEnabled(state.status === "online");
}

function setActionsEnabled(online) {
  for (const node of [els.addSolverBtn, els.settingsBtn, els.exportBtn, els.chatInput]) {
    node.disabled = !online;
  }
  const snap = state.snapshot;
  const active = (snap?.slots || []).filter((s) => s.status === "active").length;
  const limit = Number(snap?.settings?.slot_limit || 0);
  els.addSlotBtn.disabled = !online || active >= limit;
  const send = els.chatForm.querySelector("button");
  if (send) send.disabled = !online;
  if (!online) els.addSlotBtn.title = "连接断开，暂时不能占用容器位";
  els.chatInput.placeholder = online ? "说点什么，Enter 发送" : "连接断开，正在重连…";
}

function renderHeader() {
  const snap = state.snapshot;
  if (!snap) return;
  const settings = snap.settings || {};
  const board = snap.board || {};
  const solvers = snap.solvers || [];
  const slots = snap.slots || [];
  const active = slots.filter((s) => s.status === "active").length;
  const limit = Number(settings.slot_limit || 0);
  const total = Number(settings.total_challenges || 0);
  const online = (board.operators || []).length;
  const onlineSelf = state.status === "online";

  els.serverName.textContent = settings.server_name || board.server_name || "";
  els.statSolved.textContent = String(solvers.length);
  els.statTotal.textContent = String(total);
  els.statSlots.textContent = `${active}/${limit}`;
  els.statOnline.textContent = String(online);

  els.solverCount.textContent = String(solvers.length);
  els.slotBadge.textContent = `${active}/${limit}`;
  els.slotBadge.classList.toggle("hot", active >= limit && limit >= 0);

  els.quotaProgress.max = Math.max(active, limit, 1);
  els.quotaProgress.value = active;
  els.quotaText.textContent = `已用 ${active} / ${limit}`;
  els.quota.classList.toggle("over", active > limit);

  const full = active >= limit;
  els.addSlotBtn.disabled = !onlineSelf || full;
  els.addSlotBtn.title = full
    ? "容器位已满：先释放一个，避免把别人顶掉"
    : "占用一个容器位";
}

function renderOperators() {
  const snap = state.snapshot;
  if (!snap) return;
  const board = snap.board || {};
  const operators = (board.operators || []).slice().sort((a, b) => {
    return (parseDate(a.joined_at)?.getTime() || 0) - (parseDate(b.joined_at)?.getTime() || 0);
  });
  els.onlineCount.textContent = String(operators.length);
  els.operatorList.replaceChildren();
  if (!operators.length) {
    const li = el("li", "activity-item");
    li.append(el("strong", "", "暂无在线"));
    els.operatorList.append(li);
    return;
  }
  for (const op of operators) {
    const li = el("li", "operator-row");
    li.title = op.remote ? `来自 ${op.remote}` : "";

    const avatar = el("span", "avatar", initial(op.nick));
    const name = el("span", "operator-name", op.nick);
    li.append(avatar, name);

    if (op.nick === snap.you) {
      li.append(el("span", "me", "我"));
    } else {
      const kick = button("踢", "kick-btn", () => kickOperator(op.nick));
      kick.disabled = state.status !== "online";
      li.append(kick);
    }
    els.operatorList.append(li);
  }
}

function renderActivity() {
  const snap = state.snapshot;
  if (!snap) return;
  const list = (snap.activity || []).slice(-60).reverse();
  els.activityList.replaceChildren();
  if (!list.length) {
    const li = el("li", "activity-item");
    li.append(el("strong", "", "还没有动态"));
    els.activityList.append(li);
    return;
  }
  for (const act of list) {
    const li = el("li", "activity-item");
    const text = el("strong", "", act.text);
    const time = el("time", "", timeAgo(act.at));
    time.title = fmtDate(act.at);
    li.append(text, time);
    els.activityList.append(li);
  }
}

/* ---------- solvers ---------- */

function solverMatches(sv, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  return (sv.challenge || "").toLowerCase().includes(q) || (sv.nick || "").toLowerCase().includes(q);
}

function renderSolvers() {
  const snap = state.snapshot;
  if (!snap) return;
  const list = (snap.solvers || [])
    .filter((sv) => solverMatches(sv, state.search))
    .slice()
    .sort((a, b) => (parseDate(b.created_at)?.getTime() || 0) - (parseDate(a.created_at)?.getTime() || 0));

  els.solverGrid.replaceChildren();
  const empty = list.length === 0;
  els.solverEmpty.classList.toggle("hidden", !empty);
  els.solverEmpty.textContent = state.search
    ? "没有匹配的战果。"
    : "还没有战果。解出来一题就记一条。";
  if (empty) return;

  for (const sv of list) {
    const card = el("article", "solver-card");
    card.tabIndex = 0;
    card.addEventListener("click", () => openSolverDetail(sv.id));

    const head = el("div", "card-head");
    head.append(el("h3", "", sv.challenge));
    const time = el("span", "card-time", timeAgo(sv.created_at));
    time.title = fmtDate(sv.created_at);
    head.append(time);

    const meta = el("div", "card-meta");
    meta.append(el("span", "tag solver", "解题人 " + sv.nick));
    meta.append(el("span", "tag " + (sv.has_writeup ? "writeup" : "muted"), sv.has_writeup ? "有 writeup" : "未写 writeup"));
    if (sv.updated_at && sv.updated_at !== sv.created_at) {
      const updated = el("span", "tag muted", "更新于 " + timeAgo(sv.updated_at));
      updated.title = fmtDate(sv.updated_at);
      meta.append(updated);
    }

    const actions = el("div", "card-actions");
    const edit = button("编辑", "ghost", (e) => {
      e.stopPropagation();
      openSolverForm(sv);
    });
    const del = button("删除", "ghost danger", (e) => {
      e.stopPropagation();
      deleteSolver(sv);
    });
    actions.append(button("查看", "ghost", (e) => {
      e.stopPropagation();
      openSolverDetail(sv.id);
    }), edit, del);

    card.append(head, meta, actions);
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target === card) openSolverDetail(sv.id);
    });
    els.solverGrid.append(card);
  }
}

function upsertSolver(sv) {
  const list = state.snapshot.solvers || (state.snapshot.solvers = []);
  const meta = Object.assign({}, sv, { writeup: "" });
  meta.has_writeup = Boolean(sv.has_writeup || sv.writeup);
  const idx = list.findIndex((item) => item.id === sv.id);
  if (idx >= 0) {
    const old = list[idx];
    const oldAt = parseDate(old.updated_at)?.getTime() || 0;
    const newAt = parseDate(sv.updated_at)?.getTime() || 0;
    if (oldAt > newAt) return false;
    list[idx] = meta;
  } else {
    list.unshift(meta);
  }
  return true;
}

function removeSolver(id) {
  if (!state.snapshot) return;
  state.snapshot.solvers = (state.snapshot.solvers || []).filter((sv) => sv.id !== id);
}

/* ---------- slots ---------- */

function renderSlots() {
  const snap = state.snapshot;
  if (!snap) return;
  const all = snap.slots || [];
  const active = all.filter((s) => s.status === "active")
    .sort((a, b) => (parseDate(b.created_at)?.getTime() || 0) - (parseDate(a.created_at)?.getTime() || 0));
  const released = all.filter((s) => s.status !== "active")
    .sort((a, b) => (parseDate(b.released_at)?.getTime() || 0) - (parseDate(a.released_at)?.getTime() || 0));

  els.slotGrid.replaceChildren();
  els.slotEmpty.classList.toggle("hidden", active.length > 0);
  for (const sl of active) {
    const card = el("article", "slot-card");
    const head = el("div", "card-head");
    head.append(el("h3", "", sl.challenge));
    const time = el("span", "card-time", "占用 " + since(sl.created_at));
    time.title = fmtDate(sl.created_at);
    head.append(time);

    const meta = el("div", "card-meta");
    meta.append(el("span", "tag solver", "占用者 " + sl.owner));
    meta.append(el("span", "tag", "已占用 " + since(sl.created_at)));
    const url = safeUrl(sl.url);
    if (url) {
      const a = el("a", "card-link", sl.url);
      a.href = url;
      a.target = "_blank";
      a.rel = "noreferrer";
      meta.append(a);
    } else if (sl.url) {
      meta.append(el("span", "tag muted", sl.url));
    }

    const cardBody = [head, meta];
    if (sl.notes) cardBody.push(el("div", "card-notes", sl.notes));

    const actions = el("div", "card-actions");
    const edit = button("编辑", "ghost", () => openSlotForm(sl));
    edit.disabled = state.status !== "online";
    const release = button("释放", "ghost danger", () => releaseSlot(sl));
    release.disabled = state.status !== "online";
    actions.append(edit, release);
    card.append(...cardBody, actions);
    els.slotGrid.append(card);
  }

  els.releasedCount.textContent = String(released.length);
  els.releasedList.replaceChildren();
  if (!released.length) {
    els.releasedList.append(el("div", "empty", "还没有释放记录。"));
  } else {
    for (const sl of released.slice(0, 80)) {
      const row = el("div", "history-row");
      row.append(el("span", "", sl.challenge), el("span", "tag muted", sl.owner));
      const time = el("span", "time", timeAgo(sl.released_at));
      time.title = fmtDate(sl.released_at);
      row.append(time);
      els.releasedList.append(row);
    }
  }
}

function upsertSlot(sl) {
  const list = state.snapshot.slots || (state.snapshot.slots = []);
  const idx = list.findIndex((item) => item.id === sl.id);
  if (idx >= 0) {
    const oldAt = parseDate(list[idx].updated_at)?.getTime() || 0;
    const newAt = parseDate(sl.updated_at)?.getTime() || 0;
    if (oldAt > newAt) return false;
    list[idx] = sl;
  } else {
    list.push(sl);
  }
  return true;
}

/* ---------- chat ---------- */

function renderChat() {
  const snap = state.snapshot;
  if (!snap) return;
  const list = els.chatList;
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 90;
  const wasEmpty = list.childElementCount === 0;
  const messages = (snap.chat || []).slice(-200);
  list.replaceChildren();

  if (!messages.length) {
    list.append(el("div", "empty", "还没有消息，打个招呼？"));
  }
  for (const msg of messages) {
    if (msg.kind === "system" || msg.kind === "solve") {
      const line = el("div", "chat-system" + (msg.kind === "solve" ? " solve" : ""), msg.text);
      line.title = fmtDate(msg.at);
      list.append(line);
      continue;
    }
    const row = el("div", "chat-row" + (msg.nick === snap.you ? " self" : ""));
    const avatar = el("span", "chat-avatar", initial(msg.nick));
    const body = el("div", "chat-body");
    const meta = el("div", "chat-meta");
    meta.append(el("span", "nick", msg.nick));
    const time = el("time", "", timeAgo(msg.at));
    time.title = fmtDate(msg.at);
    meta.append(time);
    body.append(meta, el("div", "chat-text", msg.text));
    row.append(avatar, body);
    list.append(row);
  }

  if (nearBottom || wasEmpty) list.scrollTop = list.scrollHeight;
  updateChatBadge();
}

function updateChatBadge() {
  if (state.unread > 0) {
    els.chatBadge.textContent = state.unread > 99 ? "99+" : String(state.unread);
    show(els.chatBadge);
    els.chatBadge.classList.add("hot");
  } else {
    hide(els.chatBadge);
    els.chatBadge.classList.remove("hot");
  }
}

function updateTitle() {
  document.title = (state.unread > 0 ? `(${state.unread}) ` : "") + "CTF Blackboard";
}

function maybeNotify(msg) {
  if (!state.snapshot || msg.nick === state.snapshot.you) return;
  if (msg.kind === "system") return;
  const away = document.hidden || !document.hasFocus() || state.activeTab !== "chat";
  if (!away) return;
  if (msg.kind === "solve") {
    playPing("solve");
  } else {
    playPing("chat");
  }
  state.unread += 1;
  updateChatBadge();
  updateTitle();
}

/* ---------- rendering ---------- */

function renderAll() {
  if (!state.snapshot) return;
  renderHeader();
  renderOperators();
  renderActivity();
  renderSolvers();
  renderChat();
  renderSlots();
  updateStatus();
  updateSoundButton();
}

function applyBoard(board) {
  if (!board || !state.snapshot) return;
  const current = parseDate(state.snapshot.board?.server_time)?.getTime() || 0;
  const next = parseDate(board.server_time)?.getTime() || 0;
  if (current && next && next < current) return;
  state.snapshot.board = board;
  renderHeader();
  renderOperators();
  renderActivity();
  updateStatus();
}

function handleEvent(name, data) {
  if (!data && name !== "status") return;
  switch (name) {
    case "snapshot":
      if (data && data.you) {
        state.snapshot = data;
        renderAll();
      }
      break;
    case "status":
      state.status = data.status || "offline";
      state.error = data.error || "";
      updateStatus();
      break;
    case "board":
      applyBoard(data.board);
      break;
    case "solver.upsert":
      if (data.solver && upsertSolver(data.solver)) {
        if (data.board) applyBoard(data.board);
        renderSolvers();
        renderHeader();
      }
      break;
    case "solver.delete":
      if (data.id) {
        removeSolver(data.id);
        if (data.board) applyBoard(data.board);
        renderSolvers();
        renderHeader();
      }
      break;
    case "slot.upsert":
      if (data.slot && upsertSlot(data.slot)) {
        if (data.board) applyBoard(data.board);
        renderSlots();
        renderHeader();
      }
      break;
    case "settings":
      if (data.settings) state.snapshot.settings = data.settings;
      if (data.board) applyBoard(data.board);
      renderHeader();
      renderSolvers();
      renderSlots();
      break;
    case "message":
      if (data.message) {
        const chat = state.snapshot.chat || (state.snapshot.chat = []);
        if (!chat.some((m) => m.id === data.message.id)) {
          chat.push(data.message);
          if (chat.length > 300) chat.splice(0, chat.length - 300);
          renderChat();
          maybeNotify(data.message);
        }
      }
      break;
    case "activity":
      if (data.activity) {
        const acts = state.snapshot.activity || (state.snapshot.activity = []);
        if (!acts.some((a) => a.id === data.activity.id)) {
          acts.push(data.activity);
          if (acts.length > 300) acts.splice(0, acts.length - 300);
          renderActivity();
        }
      }
      break;
    case "kicked":
      state.status = "kicked";
      state.error = data.reason || "被踢出";
      updateStatus();
      toast(`你被 ${data.by || "操作员"} 踢出：${data.reason || ""}`, "error");
      break;
  }
}

/* ---------- SSE ---------- */

function connectSSE() {
  if (!state.token) return;
  if (state.sse) state.sse.close();
  const es = new EventSource("/api/events?token=" + encodeURIComponent(state.token));
  state.sse = es;
  es.onopen = () => { state.sseWarned = false; };
  es.onmessage = (event) => {
    try {
      const parsed = JSON.parse(event.data);
      handleEvent(parsed.name, parsed.data);
    } catch (_) {}
  };
  es.onerror = () => {
    if (!state.sseWarned) {
      state.sseWarned = true;
      toast("本地界面连接中断，正在重连…", "error");
    }
  };
}

/* ---------- login / logout ---------- */

function parseServerInfo(text) {
  const info = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const idx = line.indexOf("=");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key) info[key] = value;
  }
  if (!info.url || !info.pin) {
    throw new Error("server-info.txt 缺少 url= 或 pin=");
  }
  return info;
}

function applyServerInfo(info, source = "") {
  els.server.value = info.url;
  els.pin.value = info.pin;
  state.prefill.url = info.url;
  state.prefill.pin = info.pin;
  els.infoStatus.textContent = "已读取服务器信息：" + (source || info.url);
  els.infoStatus.classList.add("ok");
  els.advancedInfo.open = false;
  loginError("");
}

function updateInfoStatus() {
  if (state.prefill.url && state.prefill.pin) {
    els.infoStatus.textContent = "已预填服务器信息：" + state.prefill.url;
    els.infoStatus.classList.add("ok");
    els.advancedInfo.open = false;
  } else if (state.prefill.url) {
    els.infoStatus.textContent = "服务器地址已填；首次连接会提示确认指纹";
    els.infoStatus.classList.remove("ok");
    els.advancedInfo.open = false;
  } else {
    els.infoStatus.textContent = "首次连接会像 SSH 一样提示确认服务器指纹；也可导入 server-info.txt";
    els.infoStatus.classList.remove("ok");
    els.advancedInfo.open = false;
  }
}

function showLogin(message = "") {
  hide(els.boot);
  hide(els.appView);
  show(els.loginView);
  els.server.value = state.prefill.url || "";
  els.pin.value = state.prefill.pin || "";
  els.nick.value = state.prefill.nick || "";
  els.password.value = "";
  els.loginError.textContent = message;
  els.loginError.classList.toggle("hidden", !message);
  els.loginBtn.disabled = !state.token;
  updateInfoStatus();
  if (!state.token) {
    els.loginError.textContent = "缺少本地令牌。请从客户端打印的地址（带 #令牌）打开，或重新启动客户端。";
    els.loginError.classList.remove("hidden");
  }
  setTimeout(() => { if (state.token) els.password.focus(); }, 30);
  document.title = "CTF Blackboard";
}

function showApp() {
  hide(els.boot);
  hide(els.loginView);
  show(els.appView);
  renderAll();
  connectSSE();
}

function loginError(message) {
  els.loginError.textContent = message;
  els.loginError.classList.toggle("hidden", !message);
}

function applyLoginSuccess(res) {
  els.password.value = "";
  state.snapshot = res.snapshot;
  state.status = "online";
  state.error = "";
  state.unread = 0;
  showApp();
  toast("已进入黑板", "success");
}

function openTrustDialog(info, body) {
  const { dialog, body: dialogBody, foot } = openDialog("首次连接：确认服务器指纹", { wide: true });
  dialogBody.append(
    el("p", "trust-note",
      "这是第一次连接这个服务器。请核对下面的 SHA-256 指纹与服务器管理员提供的一致。确认后会记住，下次自动校验；如果指纹对不上，不要信任。"),
    el("div", "fingerprint", info.pin || ""),
    el("p", "hint small", "服务器：" + (info.server || body.server)),
  );
  const err = formError();
  dialogBody.append(err);

  const trust = button("信任并继续", "primary", async () => {
    trust.disabled = true;
    setFormError(err, "");
    try {
      const res = await api("/api/login", {
        method: "POST",
        body: Object.assign({}, body, { pin: info.pin }),
      });
      els.pin.value = info.pin;
      state.prefill.pin = info.pin;
      dialog.close();
      applyLoginSuccess(res);
    } catch (e) {
      setFormError(err, e.message || "登录失败");
      trust.disabled = false;
    }
  });
  const cancel = button("取消", "ghost", () => {
    dialog.close();
    loginError("已取消连接。");
  });
  foot.append(cancel, trust);
}

async function postLogin(body, allowTrust = true) {
  try {
    const res = await api("/api/login", { method: "POST", body });
    applyLoginSuccess(res);
    return true;
  } catch (err) {
    if (allowTrust && err.data && err.data.trustRequired) {
      openTrustDialog(err.data, body);
      return false;
    }
    loginError(err.message || "登录失败");
    return false;
  }
}

async function doLogin(event) {
  event.preventDefault();
  if (!state.token) return;
  ensureAudio();
  const server = els.server.value.trim();
  const nick = els.nick.value.trim();
  const pin = els.pin.value.trim();
  if (!server) {
    loginError("请填写服务器地址，或导入 server-info.txt");
    return;
  }
  if (!nick) {
    loginError("请填写昵称");
    return;
  }
  if (!els.password.value) {
    loginError("请填写共享密码");
    return;
  }
  els.loginBtn.disabled = true;
  els.loginBtn.textContent = "登录中…";
  loginError("");
  state.prefill = { url: server, pin, nick };
  try {
    await postLogin({ server, pin, nick, password: els.password.value });
  } finally {
    els.loginBtn.disabled = false;
    els.loginBtn.textContent = "进入黑板";
  }
}

async function logout() {
  if (!confirm("断开当前登录？本地客户端会继续运行。")) return;
  try { await api("/api/logout", { method: "POST" }); } catch (_) {}
  if (state.sse) {
    state.sse.close();
    state.sse = null;
  }
  state.snapshot = null;
  state.status = "offline";
  state.error = "";
  state.unread = 0;
  updateTitle();
  showLogin("");
  toast("已断开");
}

/* ---------- dialogs ---------- */

function openDialog(title, options = {}) {
  const dialog = el("dialog", "modal" + (options.wide ? " wide" : ""));
  const head = el("div", "modal-head");
  head.append(el("h2", "", title));
  const closeBtn = button("×", "modal-close", () => dialog.close());
  closeBtn.setAttribute("aria-label", "关闭");
  head.append(closeBtn);

  const body = el("div", "modal-body");
  const foot = el("div", "modal-foot");
  dialog.append(head, body, foot);
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => dialog.remove());
  els.modalRoot.append(dialog);
  dialog.showModal();
  return { dialog, body, foot };
}

function field(labelText, input) {
  const label = el("label");
  label.append(document.createTextNode(labelText), input);
  return label;
}

function formError() {
  const node = el("div", "form-error hidden");
  return node;
}

function setFormError(node, message) {
  node.textContent = message || "";
  node.classList.toggle("hidden", !message);
}

async function fetchSolver(id) {
  const res = await cmd("solver.get", { id });
  if (!res || !res.solver) throw new Error("战果不存在");
  return res.solver;
}

async function openSolverDetail(id) {
  let sv;
  try {
    sv = await fetchSolver(id);
  } catch (err) {
    toast(err.message, "error");
    return;
  }
  const { dialog, body, foot } = openDialog(sv.challenge, { wide: true });
  const meta = el("div", "meta-line");
  meta.append(el("span", "tag solver", "解题人 " + sv.nick));
  meta.append(el("span", "tag", "记录 " + fmtDate(sv.created_at)));
  meta.append(el("span", "tag muted", "更新 " + fmtDate(sv.updated_at)));
  body.append(meta);

  const pre = el("pre", "writeup-view", (sv.writeup || "").trim() || "还没有写 writeup。");
  body.append(pre);

  const remove = button("删除", "ghost danger", async () => {
    if (!confirm(`删除 ${sv.challenge} 的战果？`)) return;
    try {
      await cmd("solver.delete", { id: sv.id });
      dialog.close();
      toast("已删除");
    } catch (err) {
      toast(err.message, "error");
    }
  });
  const edit = button("编辑", "ghost", () => {
    dialog.close();
    openSolverForm(sv);
  });
  const close = button("关闭", "primary", () => dialog.close());
  foot.append(remove, edit, close);
}

async function openSolverForm(existing) {
  let full = existing || null;
  if (existing && existing.has_writeup) {
    try {
      full = await fetchSolver(existing.id);
    } catch (err) {
      toast(err.message, "error");
      return;
    }
  }
  const { dialog, body, foot } = openDialog(existing ? "编辑战果" : "记录战果", { wide: true });
  const form = el("form", "form-grid");
  const challenge = el("input");
  challenge.required = true;
  challenge.maxLength = 80;
  challenge.placeholder = "题目名称，例如 ezsql";
  challenge.value = full?.challenge || "";

  const nick = el("input");
  nick.required = true;
  nick.maxLength = 24;
  nick.placeholder = "最终交 flag 的人";
  nick.value = full?.nick || state.snapshot?.you || "";

  const writeup = el("textarea");
  writeup.rows = 14;
  writeup.maxLength = 262144;
  writeup.placeholder = "writeup 可以先空着，之后再来补。支持 Markdown 原文。";
  writeup.value = full?.writeup || "";

  const err = formError();
  form.append(field("题目", challenge), field("解题人", nick), field("writeup", writeup), err);
  body.append(form);

  const save = button(existing ? "保存" : "记录", "primary", async () => {
    save.disabled = true;
    setFormError(err, "");
    try {
      const payload = {
        challenge: challenge.value.trim(),
        nick: nick.value.trim(),
        writeup: writeup.value,
      };
      if (!payload.challenge) throw new Error("题目不能为空");
      if (!payload.nick) throw new Error("解题人不能为空");
      if (existing) {
        await cmd("solver.update", Object.assign({ id: existing.id }, payload));
      } else {
        await cmd("solver.add", payload);
      }
      dialog.close();
      toast(existing ? "战果已更新" : "战果已记录");
    } catch (e) {
      setFormError(err, e.message);
    } finally {
      save.disabled = false;
    }
  });
  const cancel = button("取消", "ghost", () => dialog.close());
  if (existing) {
    const remove = button("删除", "ghost danger", async () => {
      if (!confirm(`删除 ${existing.challenge} 的战果？`)) return;
      try {
        await cmd("solver.delete", { id: existing.id });
        dialog.close();
        toast("已删除");
      } catch (e) {
        toast(e.message, "error");
      }
    });
    foot.append(remove);
  }
  foot.append(cancel, save);
  writeup.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      save.click();
    }
  });
  setTimeout(() => challenge.focus(), 40);
}

function deleteSolver(sv) {
  if (!confirm(`删除 ${sv.challenge} 的战果？`)) return;
  cmd("solver.delete", { id: sv.id })
    .then(() => toast("已删除"))
    .catch((err) => toast(err.message, "error"));
}

async function openSlotForm(existing) {
  const { dialog, body, foot } = openDialog(existing ? "编辑容器位" : "占用容器位");
  const form = el("form", "form-grid");
  const challenge = el("input");
  challenge.required = true;
  challenge.maxLength = 80;
  challenge.placeholder = "这容器是哪道题的";
  challenge.value = existing?.challenge || "";

  const url = el("input");
  url.maxLength = 500;
  url.placeholder = "http://10.0.0.5:3000（可空）";
  url.value = existing?.url || "";

  const notes = el("textarea");
  notes.rows = 3;
  notes.maxLength = 2000;
  notes.placeholder = "备注：端口、账号、注意事项…";
  notes.value = existing?.notes || "";

  const err = formError();
  form.append(field("题目", challenge), field("地址 / 端口", url), field("备注", notes), err);
  body.append(form);

  const save = button(existing ? "保存" : "占用", "primary", async () => {
    save.disabled = true;
    setFormError(err, "");
    try {
      const payload = {
        challenge: challenge.value.trim(),
        url: url.value.trim(),
        notes: notes.value.trim(),
      };
      if (!payload.challenge) throw new Error("题目不能为空");
      if (existing) {
        await cmd("slot.update", Object.assign({ id: existing.id }, payload));
      } else {
        await cmd("slot.open", payload);
      }
      dialog.close();
      toast(existing ? "容器位已更新" : "已占用容器位");
    } catch (e) {
      setFormError(err, e.message);
    } finally {
      save.disabled = false;
    }
  });
  foot.append(button("取消", "ghost", () => dialog.close()), save);
  setTimeout(() => challenge.focus(), 40);
}

function releaseSlot(sl) {
  if (!confirm(`释放 ${sl.challenge} 的容器位（占用者 ${sl.owner}）？`)) return;
  cmd("slot.release", { id: sl.id })
    .then(() => toast("容器位已释放"))
    .catch((err) => toast(err.message, "error"));
}

function openSettings() {
  const snap = state.snapshot;
  if (!snap) return;
  const settings = snap.settings || {};
  const { dialog, body, foot } = openDialog("黑板设置");
  const form = el("form", "form-grid");
  const total = el("input");
  total.type = "number";
  total.min = "0";
  total.max = "10000";
  total.value = String(settings.total_challenges || 0);
  const limit = el("input");
  limit.type = "number";
  limit.min = "0";
  limit.max = "1000";
  limit.value = String(settings.slot_limit || 0);
  const motd = el("textarea");
  motd.rows = 4;
  motd.maxLength = 1000;
  motd.value = settings.motd || "";
  const err = formError();
  form.append(
    field("题目总数（比赛动态上题时随时改）", total),
    field("容器位上限（随时改，满了就不能再开）", limit),
    field("公告 / 提醒", motd),
    err,
  );
  body.append(form);

  const save = button("保存设置", "primary", async () => {
    save.disabled = true;
    setFormError(err, "");
    try {
      await cmd("settings.update", {
        total_challenges: Number(total.value),
        slot_limit: Number(limit.value),
        motd: motd.value,
      });
      dialog.close();
      toast("设置已更新");
    } catch (e) {
      setFormError(err, e.message);
    } finally {
      save.disabled = false;
    }
  });
  foot.append(button("取消", "ghost", () => dialog.close()), save);
  setTimeout(() => total.focus(), 40);
}

/* ---------- kick / export ---------- */

async function kickOperator(nick) {
  if (!confirm(`把 ${nick} 踢出黑板？对方会暂时无法重连。`)) return;
  try {
    await cmd("kick", { nick });
    toast(`已踢出 ${nick}`);
  } catch (err) {
    toast(err.message, "error");
  }
}

async function exportWriteups() {
  if (state.status !== "online") {
    toast("连接未就绪，稍后再导出", "error");
    return;
  }
  try {
    const res = await fetch("/api/export?format=md", {
      headers: { "X-CTFBB-Token": state.token },
      cache: "no-store",
    });
    if (!res.ok) {
      let message = `导出失败（HTTP ${res.status}）`;
      try { const data = await res.json(); if (data.error) message = data.error; } catch (_) {}
      throw new Error(message);
    }
    const blob = await res.blob();
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename="?([^";]+)"?/.exec(cd);
    const filename = match ? match[1] : "ctfbb-writeups.md";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("已导出 writeup", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

/* ---------- tabs / sound / focus ---------- */

function setTab(name) {
  state.activeTab = name;
  for (const tab of $$(".tab")) {
    tab.classList.toggle("active", tab.dataset.tab === name);
  }
  for (const pane of ["solvers", "chat", "slots"]) {
    const node = $("#tab-" + pane);
    if (node) node.classList.toggle("hidden", pane !== name);
  }
  if (name === "chat") {
    state.unread = 0;
    updateChatBadge();
    updateTitle();
    renderChat();
    setTimeout(() => {
      els.chatList.scrollTop = els.chatList.scrollHeight;
      els.chatInput.focus();
    }, 20);
  } else if (name === "slots") {
    renderSlots();
  }
}

function onFocusChange() {
  if (!document.hidden) {
    if (state.activeTab === "chat") {
      state.unread = 0;
      updateChatBadge();
      updateTitle();
    }
  }
}

/* ---------- boot ---------- */

function wireEvents() {
  els.loginForm.addEventListener("submit", doLogin);
  els.importInfoBtn.addEventListener("click", () => els.infoFile.click());
  els.infoFile.addEventListener("change", async () => {
    const file = els.infoFile.files && els.infoFile.files[0];
    if (!file) return;
    try {
      applyServerInfo(parseServerInfo(await file.text()), file.name);
    } catch (err) {
      loginError(err.message);
    } finally {
      els.infoFile.value = "";
    }
  });
  els.server.addEventListener("change", () => {
    const text = els.server.value;
    if (!text.includes("url=") || !text.includes("pin=")) return;
    try {
      applyServerInfo(parseServerInfo(text), "粘贴的 server-info");
    } catch (err) {
      loginError(err.message);
    }
  });
  els.chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = els.chatInput.value.trim();
    if (!text) return;
    els.chatInput.disabled = true;
    try {
      await cmd("chat.send", { text });
      els.chatInput.value = "";
    } catch (err) {
      toast(err.message, "error");
    } finally {
      els.chatInput.disabled = state.status !== "online";
      els.chatInput.focus();
    }
  });
  for (const tab of $$(".tab")) {
    tab.addEventListener("click", () => setTab(tab.dataset.tab));
  }
  els.solverSearch.addEventListener("input", () => {
    state.search = els.solverSearch.value.trim();
    renderSolvers();
  });
  els.addSolverBtn.addEventListener("click", () => openSolverForm(null));
  els.addSlotBtn.addEventListener("click", () => openSlotForm(null));
  els.settingsBtn.addEventListener("click", openSettings);
  els.exportBtn.addEventListener("click", exportWriteups);
  els.logoutBtn.addEventListener("click", logout);
  els.soundBtn.addEventListener("click", () => {
    state.sound = !state.sound;
    try { localStorage.setItem("ctfbb-sound", state.sound ? "on" : "off"); } catch (_) {}
    updateSoundButton();
    if (state.sound) {
      ensureAudio();
      playPing("chat");
    }
  });
  document.addEventListener("visibilitychange", onFocusChange);
  window.addEventListener("focus", onFocusChange);
  document.addEventListener("click", () => ensureAudio(), { passive: true });
  window.addEventListener("beforeunload", () => {
    if (state.sse) state.sse.close();
  });
}

async function boot() {
  wireEvents();
  updateSoundButton();
  if (!state.token) {
    showLogin("");
    return;
  }
  try {
    const [pre, session] = await Promise.all([
      api("/api/prefill"),
      api("/api/session"),
    ]);
    state.prefill = Object.assign({}, pre.prefill || {}, session.prefill || {});
    if (session.loggedIn && session.snapshot) {
      state.snapshot = session.snapshot;
      state.status = session.status || "online";
      state.error = session.error || "";
      hide(els.boot);
      show(els.appView);
      renderAll();
      connectSSE();
    } else {
      showLogin("");
    }
  } catch (err) {
    hide(els.boot);
    showLogin(err.message || "无法连接本地客户端");
  }
}

boot();
