from django.conf import settings


def tracex_settings(request):
    """Expose deployment flags to the templates (sign-up switch, etc.)."""
    ctx = {"allow_signup": settings.ALLOW_SIGNUP}
    if request.user.is_authenticated:
        from investigations.models import Investigation

        ctx["user_case_count"] = Investigation.objects.filter(
            created_by=request.user
        ).count()
    return ctx
