/* TRACE-X motion orchestrator.
 * 1. Royal splash — full-screen intro, exactly 3 s, skippable by click/key.
 * 2. Wires up the vendored libraries AFTER the splash lifts:
 *      AOS          — scroll reveals (data-aos attributes in templates)
 *      GSAP         — hero parallax (scrub) + dashboard stat count-up
 *      lottie-web   — plays static/vendor/lottie/*.json on [data-lottie]
 * 3. Drives the .is-loading button state for forms marked data-loading.
 * Every effect is skipped when the user prefers reduced motion. */
(function () {
  "use strict";

  var reduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------- *
   * 1. Royal splash (3 s, skippable)                                  *
   * ---------------------------------------------------------------- */
  var SPLASH_MS = 3000;
  var splash = document.getElementById("tx-splash");
  var splashActive = false;
  var statusTimer = null;
  var booted = false;
  var pending = [];

  function endSplash() {
    if (!splash || splash.getAttribute("data-done")) return;
    splash.setAttribute("data-done", "1");
    if (statusTimer) { clearInterval(statusTimer); statusTimer = null; }
    splash.classList.add("is-gone");
    document.documentElement.classList.remove("splash-lock");
    setTimeout(function () {
      if (splash.parentNode) splash.parentNode.removeChild(splash);
    }, 700);
    flush();
  }

  function flush() {
    var cbs = pending;
    pending = [];
    cbs.forEach(function (fn) { try { fn(); } catch (e) {} });
  }

  function afterSplash(fn) {
    if (!splashActive) { fn(); return; }
    pending.push(fn);
  }

  if (splash && !reduced) {
    splashActive = true;
    var t0 = Date.now();
    setTimeout(endSplash, SPLASH_MS);
    var skip = function () {
      if (Date.now() - t0 < 700) return;
      endSplash();
      document.removeEventListener("pointerdown", skip);
      document.removeEventListener("keydown", skip);
    };
    document.addEventListener("pointerdown", skip);
    document.addEventListener("keydown", skip);

    var statuses = ["Verifying evidence hashes", "Replaying integrity chain", "Establishing secure session"];
    var statusEl = splash.querySelector(".tx-splash-status");
    if (statusEl) {
      var si = 0;
      statusTimer = setInterval(function () {
        si += 1;
        if (si >= statuses.length) { clearInterval(statusTimer); statusTimer = null; return; }
        statusEl.textContent = statuses[si];
      }, 950);
    }
  } else if (splash) {
    splash.classList.add("is-gone");
  }

  /* ---------------------------------------------------------------- *
   * 2. Boot the animation layer (once, after the splash)              *
   * ---------------------------------------------------------------- */
  function boot() {
    if (booted) return;
    booted = true;

    /* Lottie: any element with data-lottie="<url of json>" becomes a player. */
    if (window.lottie && !reduced) {
      document.querySelectorAll("[data-lottie]").forEach(function (el) {
        try {
          window.lottie.loadAnimation({
            container: el,
            renderer: "svg",
            loop: true,
            autoplay: true,
            path: el.getAttribute("data-lottie"),
            rendererSettings: { preserveAspectRatio: "xMidYMid meet" }
          });
        } catch (err) {
          /* purely decorative — never break the page over it */
        }
      });
    }

    /* AOS: reveal elements as they scroll into view (attributes live in the
     * templates, e.g. data-aos="fade-up"). */
    if (window.AOS) {
      window.AOS.init({
        duration: 600,
        easing: "ease-out-cubic",
        offset: 60,
        once: true,
        disable: reduced
      });
    }

    /* GSAP + ScrollTrigger: parallax drift on the dashboard hero and a
     * count-up on the stat tiles. Deferred so GSAP never records start
     * values while a CSS entrance animation is still holding the hero at
     * opacity 0 (that would pin it invisible after the scrub). */
    if (window.gsap && window.ScrollTrigger && !reduced) {
      setTimeout(function () {
        window.gsap.registerPlugin(window.ScrollTrigger);

        var hero = document.querySelector(".hero");
        if (hero) {
          window.gsap.to(hero, {
            yPercent: 14,
            ease: "none",
            scrollTrigger: {
              trigger: hero,
              start: "top top",
              end: "bottom top",
              scrub: 0.6
            }
          });
        }

        document.querySelectorAll(".stat .num").forEach(function (el) {
          var target = parseInt(el.textContent, 10);
          if (isNaN(target) || target <= 0) return;
          var state = { v: 0 };
          window.gsap.to(state, {
            v: target,
            duration: 1.1,
            ease: "power2.out",
            delay: 0.15,
            onUpdate: function () {
              el.textContent = Math.round(state.v).toLocaleString();
            }
          });
        });
      }, 450);
    }

    /* Motion (vanilla build): staggered reveal for data-table rows and
     * scroll-in lists. Purely decorative — failures must never hide content,
     * so keyframes always animate TO the visible state. */
    if (window.Motion && window.Motion.animate && window.Motion.inView && !reduced) {
      try {
        document.querySelectorAll("table.tbl").forEach(function (tbl) {
          var rows = Array.prototype.filter.call(tbl.querySelectorAll("tr"), function (r) {
            return r.parentElement && r.parentElement.tagName !== "THEAD" &&
              !r.querySelector("th");
          });
          if (!rows.length || rows.length > 60) return;
          window.Motion.inView(tbl, function () {
            window.Motion.animate(
              rows,
              { opacity: [0, 1], transform: ["translateY(10px)", "translateY(0px)"] },
              {
                duration: 0.45,
                ease: [0.23, 1, 0.32, 1],
                delay: window.Motion.stagger ? window.Motion.stagger(0.045) : 0
              }
            );
          }, { amount: 0.15 });
        });
      } catch (err) {
        /* decorative only */
      }
    }
  }

  afterSplash(boot);
  /* hard safety net: never let a splash bug keep content hidden */
  setTimeout(boot, SPLASH_MS + 900);

  /* ---------------------------------------------------------------- *
   * 3. Forms flagged with data-loading: submit button spinner state   *
   *    (motion.css .btn.is-loading). Optional data-loading-text=       *
   *    "Working…" replaces the label. Registered immediately — not     *
   *    gated by the splash.                                            *
   * ---------------------------------------------------------------- */
  document.querySelectorAll("form[data-loading]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit]");
      if (!btn || btn.classList.contains("is-loading")) return;
      btn.classList.add("is-loading");
      var label = btn.getAttribute("data-loading-text");
      if (label) {
        btn.setAttribute("data-label", btn.textContent);
        btn.textContent = label;
      }
    });
  });
})();
