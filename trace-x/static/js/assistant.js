/* Sentinel — TRACE-X assistant chat. Vanilla JS, no dependencies. */
(function () {
  "use strict";

  var fab = document.getElementById("tx-fab");
  var dock = document.getElementById("tx-fab-dock");
  var panel = document.getElementById("tx-chat");
  if (!fab || !panel) return;

  var msgs = document.getElementById("tx-msgs");
  var chips = document.getElementById("tx-chips");
  var form = document.getElementById("tx-form");
  var input = document.getElementById("tx-input");
  var send = document.getElementById("tx-send");
  var closeBtn = document.getElementById("tx-min");

  var busy = false;
  var seeded = false;
  var CSRF = (document.querySelector('[name="csrfmiddlewaretoken"]') || {}).value;

  function esc(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : String(s);
    return d.innerHTML;
  }

  function now() {
    var t = new Date();
    return ("0" + t.getHours()).slice(-2) + ":" + ("0" + t.getMinutes()).slice(-2);
  }

  function scrollDown() {
    msgs.scrollTop = msgs.scrollHeight;
  }

  function addRow(side, text) {
    var row = document.createElement("div");
    row.className = "tx-row " + (side === "me" ? "me" : "bot-row");
    var time = document.createElement("div");
    time.className = "tx-time";
    time.textContent = now();
    if (side === "me") {
      var bub = document.createElement("div");
      bub.className = "tx-bub me";
      bub.textContent = text;
      row.appendChild(bub);
      row.appendChild(time);
    } else {
      var who = document.createElement("div");
      who.className = "tx-who";
      who.textContent = "S";
      var bub2 = document.createElement("div");
      bub2.className = "tx-bub bot";
      bub2.textContent = text;
      row.appendChild(who);
      row.appendChild(bub2);
      row.appendChild(time);
    }
    msgs.appendChild(row);
    scrollDown();
    return row;
  }

  function showTyping() {
    var row = document.createElement("div");
    row.className = "tx-row bot-row tx-typing";
    row.id = "tx-typing-row";
    row.innerHTML =
      '<div class="tx-who">S</div>' +
      '<div class="tx-bub bot"><i></i><i></i><i></i></div>';
    msgs.appendChild(row);
    scrollDown();
  }

  function hideTyping() {
    var el = document.getElementById("tx-typing-row");
    if (el) el.parentNode.removeChild(el);
  }

  function renderChips(list) {
    chips.innerHTML = "";
    if (!list || !list.length) return;
    list.slice(0, 4).forEach(function (label) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "tx-chip";
      b.textContent = label;
      b.addEventListener("click", function () { send_message(label); });
      chips.appendChild(b);
    });
  }

  function seed() {
    if (seeded) return;
    seeded = true;
    addRow(
      "bot",
      "Hey — Sentinel here, your TRACE-X co-pilot.\n" +
        "Ask me anything about cases, evidence, analysis, the integrity chain or who can see what. " +
        "I answer like a colleague, not a manual. What are we working on?"
    );
    renderChips(["How do I create a case?", "Upload evidence", "Run AI analysis"]);
  }

  function send_message(text) {
    text = (text || "").trim();
    if (!text || busy) return;
    busy = true;
    send.disabled = true;
    chips.innerHTML = "";
    addRow("me", text);
    input.value = "";
    autoGrow();
    showTyping();

    var wait = Math.min(1500, 420 + text.length * 6) + Math.random() * 350;

    fetch("/api/assistant/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": CSRF || "",
      },
      body: JSON.stringify({ message: text }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error("bad status " + r.status);
        return r.json();
      })
      .then(function (data) {
        setTimeout(function () {
          hideTyping();
          addRow("bot", data.reply || "…");
          renderChips(data.suggestions);
          busy = false;
          send.disabled = false;
          input.focus();
        }, wait);
      })
      .catch(function () {
        setTimeout(function () {
          hideTyping();
          addRow(
            "bot",
            "Lost my train of thought for a second — the server didn't answer. Try that again?"
          );
          busy = false;
          send.disabled = false;
        }, wait);
      });
  }

  function openChat() {
    panel.classList.add("open");
    document.body.classList.add("tx-chat-open");
    seed();
    setTimeout(function () { input.focus(); }, 350);
  }

  function closeChat() {
    panel.classList.remove("open");
    document.body.classList.remove("tx-chat-open");
  }

  function toggle() {
    if (panel.classList.contains("open")) closeChat();
    else openChat();
  }

  fab.addEventListener("click", function (e) {
    e.stopPropagation();
    toggle();
  });
  if (closeBtn) closeBtn.addEventListener("click", closeChat);
  panel.addEventListener("click", function (e) { e.stopPropagation(); });
  document.addEventListener("click", function (e) {
    if (panel.classList.contains("open") && !panel.contains(e.target)) closeChat();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && panel.classList.contains("open")) closeChat();
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    send_message(input.value);
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send_message(input.value);
    }
  });

  function autoGrow() {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 96) + "px";
  }
  input.addEventListener("input", autoGrow);

  /* magnet: the launcher leans toward the cursor */
  fab.addEventListener("mousemove", function (e) {
    if (!dock) return;
    var r = fab.getBoundingClientRect();
    var dx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2);
    var dy = (e.clientY - (r.top + r.height / 2)) / (r.height / 2);
    dock.style.transform = "translate(" + dx * 6 + "px, " + dy * 6 + "px)";
  });
  fab.addEventListener("mouseleave", function () {
    if (dock) dock.style.transform = "";
  });
})();
