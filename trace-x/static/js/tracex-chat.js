(function () {
  var FAB_ID = "tx-chat-fab";
  var PANEL_ID = "tx-chat-panel";
  var KS = "tx-chat-history";

  function el(id) { return document.getElementById(id); }

  function readHistory() {
    try { return JSON.parse(localStorage.getItem(KS) || "[]"); }
    catch (e) { return []; }
  }
  function saveHistory(h) {
    try { localStorage.setItem(KS, JSON.stringify(h.slice(-30))); } catch (e) {}
  }

  function mdEscape(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function renderInline(s, out) {
    var i = 0;
    s.replace(/```([\s\S]*?)```/g, function (m, code, off) {
      out.push(mdEscape(s.slice(i, off)));
      out.push('<pre style="background:rgba(212,175,55,.1);border:1px solid rgba(232,194,90,.28);border-radius:10px;padding:9px;overflow:auto;margin:6px 0;font:11px/1.5 Consolas,monospace;color:#f6de8e"><code>' + mdEscape(code) + "</code></pre>");
      i = off + m.length;
      return m;
    });
    out.push(mdEscape(s.slice(i)));
    var html = out.join("");
    return html
      .replace(/`([^`\n]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\n{2,}/g, "\n");
  }
  function formatBot(text) {
    var blocks = [];
    renderInline(text, blocks);
    var paras = blocks.join("").split(/\n{2,}/);
    var out = [];
    for (var i = 0; i < paras.length; i++) {
      var p = paras[i].replace(/\n/g, "<br>");
      if (p.trim()) out.push("<p>" + p + "</p>");
    }
    return out.join("");
  }

  function addMsg(role, text, opts) {
    opts = opts || {};
    var body = el("tx-chat-body");
    var div = document.createElement("div");
    div.className = "tx-msg " + role + (opts.extra || "");
    if (role === "bot" && !opts.typewriter) {
      div.innerHTML = formatBot(text);
    } else {
      div.textContent = text;
    }
    body.appendChild(div);
    body.scrollTop = body.scrollHeight;
    return div;
  }

  function typeBot(text) {
    var body = el("tx-chat-body");
    var div = document.createElement("div");
    div.className = "tx-msg bot";
    div.setAttribute("aria-live", "polite");
    var caret = document.createElement("span");
    caret.className = "tx-caret";
    div.appendChild(document.createTextNode(""));
    div.appendChild(caret);
    body.appendChild(div);

    var finalHTML = formatBot(text);
    var plain = text;
    var i = 0;
    var speed = plain.length > 400 ? 8 : plain.length > 150 ? 12 : 16;
    return new Promise(function (resolve) {
      function step() {
        var n = speed > 8 ? Math.min(speed, plain.length - i) : 1;
        i += n;
        div.firstChild.textContent = plain.substring(0, i);
        body.scrollTop = body.scrollHeight;
        if (i < plain.length) {
          setTimeout(step, 16);
        } else {
          caret.remove();
          div.innerHTML = finalHTML;
          body.scrollTop = body.scrollHeight;
          resolve();
        }
      }
      setTimeout(step, 120);
    });
  }

  function setTyping(on) {
    var body = el("tx-chat-body");
    var t = el("tx-chat-typing");
    if (on) {
      if (t) return;
      var d = document.createElement("div");
      d.className = "tx-chat-typing";
      d.id = "tx-chat-typing";
      d.innerHTML = "<i></i><i></i><i></i>";
      body.appendChild(d);
      body.scrollTop = body.scrollHeight;
    } else if (t) {
      t.remove();
    }
  }

  function setBusy(b) {
    var btn = el("tx-chat-send");
    var inp = el("tx-chat-input");
    if (btn) btn.disabled = b;
    if (inp) inp.disabled = b;
  }

  function send() {
    var inp = el("tx-chat-input");
    var text = (inp.value || "").trim();
    if (!text) return;
    var history = readHistory();
    addMsg("user", text);
    history.push({ role: "user", text: text });
    saveHistory(history);
    inp.value = "";
    inp.style.height = "";
    setBusy(true);
    setTyping(true);
    fetch("/api/chat/", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
      body: JSON.stringify({ messages: history })
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        setTyping(false);
        if (res.ok && res.j.reply) {
          history.push({ role: "assistant", text: res.j.reply });
          saveHistory(history);
          return typeBot(res.j.reply);
        } else {
          addMsg("error", (res.j && res.j.error) || "Something went wrong. Try again.");
        }
      })
      .catch(function () {
        setTyping(false);
        addMsg("error", "Could not reach the assistant. Check the server connection.");
      })
      .then(function () { setBusy(false); });
  }

  function csrfToken() {
    var m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    if (m) return decodeURIComponent(m[1]);
    var t = document.querySelector('meta[name="csrf-token"]');
    return t ? t.getAttribute("content") : "";
  }

  function autosize() {
    var inp = el("tx-chat-input");
    if (!inp) return;
    inp.style.height = "auto";
    inp.style.height = Math.min(inp.scrollHeight, 84) + "px";
  }

  function bind() {
    var fab = el(FAB_ID);
    var panel = el(PANEL_ID);
    if (!fab || !panel) return;
    var input = el("tx-chat-input");
    var sendBtn = el("tx-chat-send");
    var closeBtn = el("tx-chat-close");

    fab.addEventListener("click", function () {
      var open = panel.classList.toggle("open");
      fab.setAttribute("aria-expanded", open ? "true" : "false");
      fab.style.display = panel.classList.contains("open") ? "none" : "";
      if (open) { input.focus(); setTyping(false); }
    });
    closeBtn.addEventListener("click", function () {
      panel.classList.remove("open");
      fab.setAttribute("aria-expanded", "false");
      fab.style.display = "";
    });
    sendBtn.addEventListener("click", send);
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
    });
    input.addEventListener("input", autosize);

    var history = readHistory();
    for (var i = 0; i < history.length; i++) {
      if (history[i].role === "assistant") addMsg("bot", history[i].text);
      else addMsg("user", history[i].text);
    }
    if (!history.length) {
      addMsg("bot", "Hello, I'm TRACE-X Assist. Ask me about evidence integrity, hash validation, IOC extraction, timeline reconstruction, or cyber forensics in general.", { extra: " welcome" });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();