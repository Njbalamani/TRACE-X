from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("signup/", views.signup, name="signup"),
    path("users/", views.users_dashboard, name="users_dashboard"),
    path("investigators/", views.investigator_roster, name="investigator_roster"),
    path("investigators/<str:username>/", views.investigator_profile, name="investigator_profile"),
    path("investigations/", views.investigation_list, name="investigation_list"),
    path("investigations/new/", views.investigation_create, name="investigation_create"),
    path("investigations/<uuid:pk>/", views.investigation_detail, name="investigation_detail"),
    path("investigations/<uuid:pk>/report/", views.incident_report, name="incident_report"),
    path("investigations/<uuid:pk>/report/pdf/", views.incident_report_pdf, name="incident_report_pdf"),
    path("investigations/<uuid:pk>/evidence/upload/", views.evidence_upload, name="evidence_upload"),
    path("investigations/<uuid:pk>/evidence/<uuid:evidence_pk>/", views.evidence_detail, name="evidence_detail"),
    path("investigations/<uuid:pk>/analyze/", views.analyze, name="analyze"),
    path("investigations/<uuid:pk>/integrity/", views.integrity_view, name="integrity_view"),
    path("investigations/<uuid:pk>/findings/<uuid:finding_pk>/", views.finding_detail, name="finding_detail"),
    path(
        "investigations/<uuid:pk>/findings/<uuid:finding_pk>/status/",
        views.finding_status,
        name="finding_status",
    ),
    path("api/investigations/", views.api_investigations, name="api_investigations"),
    path("api/investigations/<uuid:pk>/", views.api_investigation_detail, name="api_investigation_detail"),
    path("api/investigations/<uuid:pk>/analyze/", views.api_analyze, name="api_analyze"),
    path("api/investigations/<uuid:pk>/integrity/", views.api_integrity, name="api_integrity"),
    path("api/assistant/", views.api_assistant, name="api_assistant"),
]
