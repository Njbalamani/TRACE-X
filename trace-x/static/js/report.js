/* Incident Report — click effects, compile theatre, KPI count-up. */
(function () {
  "use strict";

  var reduce = false;
  try { reduce = matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) {}

  /* ---------------------------------------------------- ripple effect */
  function ripple(e, el) {
    if (reduce || !el) return;
    var r = el.getBoundingClientRect();
    var span = el.querySelector(".btn-rocket-ripple") || document.createElement("span");
    if (!span.classList.contains("btn-rocket-ripple")) {
      span.className = "btn-rocket-ripple";
      el.appendChild(span);
    }
    var size = Math.max(r.width, r.height) * 2.2;
    span.style.width = span.style.height = size + "px";
    span.style.left = (e.clientX - r.left - size / 2) + "px";
    span.style.top = (e.clientY - r.top - size / 2) + "px";
    span.style.transform = "scale(0)";
    span.style.opacity = ".7";
    /* force reflow, then expand */
    void span.offsetWidth;
    span.style.transition = "transform .6s cubic-bezier(.22,1,.36,1), opacity .6s ease";
    span.style.transform = "scale(1)";
    span.style.opacity = "0";
    setTimeout(function () {
      span.style.transition = "";
      span.style.transform = "scale(0)";
    }, 650);
  }

  /* -------------------------------------------------- compile theatre */
  var overlay = document.getElementById("rp-overlay");
  var checklist = document.getElementById("rp-checklist");
  var bar = document.getElementById("rp-progress-bar");
  var status = document.getElementById("rp-overlay-status");
  var working = false;

  function compileThen(href) {
    if (working) return;
    working = true;
    if (!overlay || reduce) { window.location.href = href; return; }

    var items = checklist ? checklist.querySelectorAll("li") : [];
    var messages = [
      "Gathering evidence & timeline…",
      "Checking fingerprints…",
      "Replaying the hash chain…",
      "Laying out the sections…",
      "Sealing the document…",
    ];
    overlay.classList.add("on");
    overlay.setAttribute("aria-hidden", "false");

    var i = 0;
    var step = Math.max(180, Math.floor(1400 / Math.max(items.length, 1)));

    var timer = setInterval(function () {
      if (i < items.length) {
        items[i].classList.add("done");
        if (bar) bar.style.width = Math.round(((i + 1) / items.length) * 100) + "%";
        if (status) status.textContent = messages[Math.min(i, messages.length - 1)];
        i += 1;
      } else {
        clearInterval(timer);
        if (status) status.textContent = "Done — downloading…";
        setTimeout(function () {
          window.location.href = href;
          /* keep the overlay up until the download starts */
          setTimeout(function () {
            overlay.classList.remove("on");
            overlay.setAttribute("aria-hidden", "true");
            Array.prototype.forEach.call(items, function (li) { li.classList.remove("done"); });
            if (bar) bar.style.width = "0%";
            working = false;
          }, 1400);
        }, 320);
      }
    }, step);
  }

  var pdfBtn = document.getElementById("rp-pdf");
  var href = pdfBtn ? (pdfBtn.getAttribute("href") || pdfBtn.getAttribute("data-href")) : null;

  Array.prototype.forEach.call(document.querySelectorAll(".btn-rocket"), function (btn) {
    btn.addEventListener("click", function (e) {
      var target = btn.getAttribute("href") || btn.getAttribute("data-href") || href;
      if (!target) return;
      ripple(e, btn);
      if (reduce) return; /* native anchor download — no theatre */
      e.preventDefault();
      btn.classList.add("go", "is-working");
      setTimeout(function () {
        btn.classList.remove("go", "is-working");
        compileThen(target);
      }, 260);
    });
  });

  /* ------------------------------------------------------- print button */
  var printBtn = document.getElementById("rp-print");
  if (printBtn) {
    printBtn.addEventListener("click", function (e) {
      ripple(e, printBtn);
      window.print();
    });
  }

  /* -------------------------------------------------- KPI count-up */
  var nums = document.querySelectorAll(".rp-kpis .num[data-count]");
  if (!reduce && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        io.unobserve(el);
        var target = parseInt(el.getAttribute("data-count"), 10) || 0;
        var start = null;
        var dur = 750;
        function tick(ts) {
          if (!start) start = ts;
          var p = Math.min((ts - start) / dur, 1);
          var eased = 1 - Math.pow(1 - p, 3);
          el.textContent = Math.round(target * eased);
          if (p < 1) requestAnimationFrame(tick);
          else el.textContent = target;
        }
        requestAnimationFrame(tick);
      });
    }, { threshold: 0.4 });
    Array.prototype.forEach.call(nums, function (n) { io.observe(n); });
  }
})();
