"""Authentication views with brute-force throttling.

TRACE-X is an investigation platform: its own login should resist the exact
attack it detects.  Failed attempts are counted per (client address, username);
after ``TRACEX_LOGIN_MAX_ATTEMPTS`` failures the pair is locked out for the
rest of ``TRACEX_LOGIN_WINDOW_SECONDS``.
"""

from django.conf import settings
from django.contrib.auth.views import LoginView
from django.core.cache import cache

from .services import audit


def _key(request, username):
    return f"login-fail:{audit.client_ip(request)}:{(username or '').lower()[:150]}"


class ThrottledLoginView(LoginView):
    def post(self, request, *args, **kwargs):
        key = _key(request, request.POST.get("username", ""))
        if cache.get(key, 0) >= settings.TRACEX_LOGIN_MAX_ATTEMPTS:
            audit.record("LOGIN_THROTTLED", request=request, username=request.POST.get("username", "")[:150])
            form = self.get_form()
            form.add_error(None, "Too many failed sign-in attempts. Try again later.")
            response = self.render_to_response(self.get_context_data(form=form))
            response.status_code = 429
            return response
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        key = _key(self.request, self.request.POST.get("username", ""))
        try:
            cache.add(key, 0, settings.TRACEX_LOGIN_WINDOW_SECONDS)
            cache.incr(key)
        except ValueError:  # key expired between add and incr
            cache.set(key, 1, settings.TRACEX_LOGIN_WINDOW_SECONDS)
        return super().form_invalid(form)

    def form_valid(self, form):
        cache.delete(_key(self.request, self.request.POST.get("username", "")))
        return super().form_valid(form)
