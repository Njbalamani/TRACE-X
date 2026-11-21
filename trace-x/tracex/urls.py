from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import RedirectView

from investigations.views import api_health, protected_media

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("login/", RedirectView.as_view(pattern_name="login", permanent=False)),
    path("api/health", api_health, name="api_health"),
    path("", include("investigations.urls")),
]

# Evidence files are only reachable by authenticated users — never served raw
# with a public static() mapping.
urlpatterns += [
    re_path(r"^media/(?P<path>.*)$", protected_media, name="protected_media"),
]
