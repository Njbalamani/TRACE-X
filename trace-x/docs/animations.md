# TRACE-X motion & animation layer

All animation libraries are **vendored locally** in `static/vendor/` — the app
loads everything from its own static files at runtime (no CDN, no network
dependency), matching TRACE-X's "runs fully locally" guarantee.

| Library | Version | File(s) | Role |
|---|---|---|---|
| [AOS](https://github.com/michalsnik/aos) | 2.3.4 | `static/vendor/aos/aos.{css,js}` | Scroll-entrance reveals via `data-aos` attributes |
| [GSAP](https://gsap.com) | 3.13.0 | `static/vendor/gsap/gsap.min.js` | Parallax scrub + stat count-up |
| ScrollTrigger | 3.13.0 | `static/vendor/gsap/ScrollTrigger.min.js` | Scroll-linked parallax plugin |
| [Motion](https://motion.dev) | 12.x | `static/vendor/motion/motion.min.js` | Vanilla-JS micro-interactions: staggered table-row reveals (`inView` + `animate`) |
| [lottie-web](https://github.com/airbnb/lottie-web) | 5.13.0 | `static/vendor/lottie/lottie.min.js` | Plays JSON animations (radar pulse on sign-in) |

Licenses: AOS and lottie-web are MIT; GSAP 3.13+ is free for commercial use;
Motion is MIT. ("standard license" assets on lottiefiles.com were avoided —
the bundled `radar-pulse.json` was authored for TRACE-X and has no
attribution strings.) Motion's React/Tailwind ecosystem (21st.dev components,
Framer Motion for React) is deliberately not used — TRACE-X templates are
server-rendered Django, and the vanilla `Motion` global covers the same
micro-interaction needs without React.

## Where effects are wired

- `static/css/motion.css` — button sheen hover, `.btn.is-loading` spinner,
  card hover lift, `anim-*` entrance utilities, `prefers-reduced-motion` guards.
- `static/js/animations.js` — one orchestrator: initializes lottie on
  `[data-lottie]` nodes, AOS, GSAP hero parallax + dashboard stat count-up,
  and the `data-loading` form spinner.
- `templates/base.html` — loads the stylesheets and deferred scripts.

## Recipe: use an effect on any page

```html
{# scroll reveal #}
<section data-aos="fade-up" data-aos-delay="100">…</section>

{# one-shot entrance (no scroll needed) #}
<div class="card anim-slide-up anim-d2">…</div>

{# loading spinner on submit #}
<form method="post" data-loading data-loading-text="Working…">
  <button class="btn" type="submit">Go</button>
</form>

{# lottie animation (load player first on pages that use it) #}
<div class="lottie-box sm" data-lottie="{% static 'vendor/lottie/radar-pulse.json' %}"></div>
{% block extra_js %}<script defer src="{% static 'vendor/lottie/lottie.min.js' %}"></script>{% endblock %}
```

`data-aos` values available (from AOS): `fade-up`, `fade-down`, `zoom-in`,
`flip-left`, and more — see the AOS demo. Delay is `data-aos-delay="<ms>"`.

## Accessibility & performance

- Everything checks `prefers-reduced-motion: reduce` — CSS disables the
  sheen/spinner/entrances; JS skips lottie, AOS and GSAP entirely.
- Scripts are `defer`red; lottie-web (~300 KB) is loaded only on pages that
  opt in via the `extra_js` block.
- Decorative animations are wrapped in `aria-hidden="true"`.
