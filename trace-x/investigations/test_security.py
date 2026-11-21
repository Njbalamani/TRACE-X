"""Security & access-control tests: RBAC, case isolation, audit trail, uploads,
secure media serving and login throttling."""

import tempfile
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import AuditEvent, CaseAssignment, Evidence, Finding, Investigation
from .services import permissions, uploads
from .services.integrity import record_object, sha256_bytes

MEDIA = tempfile.mkdtemp(prefix="tracex-sec-media-")


def make_user(name, **kw):
    return User.objects.create_user(name, password="pw-Str0ng-test", **kw)


def make_case(owner, number="TRX-S0001"):
    return Investigation.objects.create(case_number=number, title="Sec case", created_by=owner)


@override_settings(MEDIA_ROOT=MEDIA)
class RoleBasedAccessTests(TestCase):
    def setUp(self):
        self.lead = make_user("lead")
        self.analyst = make_user("analyst")
        self.reviewer = make_user("reviewer")
        self.viewer = make_user("viewer")
        self.outsider = make_user("outsider")
        self.case = make_case(self.lead)
        for user, role in [
            (self.analyst, CaseAssignment.ROLE_ANALYST),
            (self.reviewer, CaseAssignment.ROLE_REVIEWER),
            (self.viewer, CaseAssignment.ROLE_VIEWER),
        ]:
            CaseAssignment.objects.create(investigation=self.case, user=user, role=role)

    def _upload(self, user, name="a.log", data=b"2026-09-28 02:13:07 src=203.0.113.44 user=admin status=FAILED"):
        self.client.force_login(user)
        return self.client.post(
            reverse("evidence_upload", args=[self.case.pk]), {"files": SimpleUploadedFile(name, data)}
        )

    def test_outsider_gets_404_not_403(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(reverse("investigation_detail", args=[self.case.pk])).status_code, 404)

    def test_every_assigned_role_can_view(self):
        for user in (self.lead, self.analyst, self.reviewer, self.viewer):
            self.client.force_login(user)
            self.assertEqual(self.client.get(reverse("investigation_detail", args=[self.case.pk])).status_code, 200, user)

    def test_viewer_and_reviewer_cannot_upload(self):
        for user in (self.viewer, self.reviewer):
            self.assertEqual(self._upload(user).status_code, 403, user)
        self.assertFalse(Evidence.objects.filter(investigation=self.case).exists())

    def test_analyst_can_upload(self):
        self._upload(self.analyst)
        self.assertEqual(Evidence.objects.filter(investigation=self.case).count(), 1)

    def test_viewer_cannot_run_analysis_but_analyst_can(self):
        self._upload(self.analyst)
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post(reverse("analyze", args=[self.case.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse("api_analyze", args=[self.case.pk])).status_code, 403)
        self.client.force_login(self.analyst)
        self.assertEqual(self.client.post(reverse("api_analyze", args=[self.case.pk])).status_code, 200)

    def test_reviewer_can_change_finding_status_viewer_cannot(self):
        finding = Finding.objects.create(investigation=self.case, title="t", summary="s")
        record_object(finding, self.case)
        url = reverse("finding_status", args=[self.case.pk, finding.pk])
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post(url, {"status": "confirmed"}).status_code, 403)
        self.client.force_login(self.reviewer)
        self.assertEqual(self.client.post(url, {"status": "confirmed"}).status_code, 302)
        finding.refresh_from_db()
        self.assertEqual(finding.status, "confirmed")

    def test_denied_action_is_audited(self):
        self.client.force_login(self.viewer)
        self.client.post(reverse("analyze", args=[self.case.pk]))
        event = AuditEvent.objects.get(action="ACCESS_DENIED")
        self.assertEqual(event.user, self.viewer)
        self.assertEqual(event.investigation, self.case)

    def test_assigned_user_sees_case_on_dashboard_outsider_does_not(self):
        self.client.force_login(self.viewer)
        self.assertContains(self.client.get(reverse("investigation_list")), self.case.case_number)
        self.client.force_login(self.outsider)
        self.assertNotContains(self.client.get(reverse("investigation_list")), self.case.case_number)

    def test_api_list_is_case_isolated(self):
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(reverse("api_investigations")).json()["investigations"], [])
        self.client.force_login(self.analyst)
        self.assertEqual(len(self.client.get(reverse("api_investigations")).json()["investigations"]), 1)

    def test_staff_has_lead_access_everywhere(self):
        staff = make_user("root", is_staff=True)
        self.assertEqual(permissions.role_for(staff, self.case), CaseAssignment.ROLE_LEAD)
        self.assertTrue(permissions.can(staff, self.case, "manage"))

    def test_capability_matrix(self):
        expected = {
            "viewer": (True, False, False, False),
            "reviewer": (True, True, False, False),
            "analyst": (True, True, True, False),
            "lead": (True, True, True, True),
        }
        for name, flags in expected.items():
            user = getattr(self, name)
            got = tuple(permissions.can(user, self.case, c) for c in ("view", "review", "write", "manage"))
            self.assertEqual(got, flags, name)


@override_settings(MEDIA_ROOT=MEDIA)
class AuditTrailTests(TestCase):
    def setUp(self):
        self.user = make_user("auditor")
        self.client.force_login(self.user)

    def test_case_creation_is_audited_and_creator_is_lead(self):
        self.client.post(reverse("investigation_create"), {"title": "Audit me", "description": "d"})
        case = Investigation.objects.get(title="Audit me")
        self.assertTrue(AuditEvent.objects.filter(action="CASE_CREATED", investigation=case, user=self.user).exists())
        self.assertEqual(CaseAssignment.objects.get(investigation=case, user=self.user).role, "lead_investigator")

    def test_upload_view_analyze_verify_are_all_audited(self):
        case = make_case(self.user)
        self.client.post(
            reverse("evidence_upload", args=[case.pk]),
            {"files": SimpleUploadedFile("a.log", b"2026-09-28 02:13:07 src=203.0.113.44 user=admin status=FAILED")},
        )
        evidence = Evidence.objects.get(investigation=case)
        self.client.get(reverse("evidence_detail", args=[case.pk, evidence.pk]))
        self.client.post(reverse("analyze", args=[case.pk]))
        self.client.get(reverse("integrity_view", args=[case.pk]))
        actions = set(AuditEvent.objects.filter(investigation=case).values_list("action", flat=True))
        for needed in ("EVIDENCE_UPLOADED", "EVIDENCE_VIEWED", "ANALYSIS_STARTED", "ANALYSIS_COMPLETED", "CHAIN_VERIFIED"):
            self.assertIn(needed, actions)

    def test_audit_records_hash_ip_and_user_agent(self):
        case = make_case(self.user)
        self.client.post(
            reverse("evidence_upload", args=[case.pk]),
            {"files": SimpleUploadedFile("a.log", b"hello world")},
            HTTP_USER_AGENT="pytest-agent/1.0",
        )
        event = AuditEvent.objects.get(action="EVIDENCE_UPLOADED")
        self.assertEqual(event.metadata["sha256"], sha256_bytes(b"hello world"))
        self.assertEqual(event.user_agent, "pytest-agent/1.0")
        self.assertEqual(event.ip_address, "127.0.0.1")

    def test_audit_events_are_append_only(self):
        event = AuditEvent.objects.create(action="CASE_CREATED")
        event.action = "CASE_CLOSED"
        with self.assertRaises(PermissionError):
            event.save()
        with self.assertRaises(PermissionError):
            event.delete()
        self.assertEqual(AuditEvent.objects.get(pk=event.pk).action, "CASE_CREATED")

    def test_tamper_detection_is_audited(self):
        case = make_case(self.user)
        self.client.post(
            reverse("evidence_upload", args=[case.pk]),
            {"files": SimpleUploadedFile("a.log", b"original content")},
        )
        evidence = Evidence.objects.get(investigation=case)
        Evidence.objects.filter(pk=evidence.pk).update(content="altered content")
        self.client.get(reverse("integrity_view", args=[case.pk]))
        self.assertTrue(AuditEvent.objects.filter(action="CHAIN_TAMPER_DETECTED", investigation=case).exists())

    @override_settings(TRACEX_TRUST_PROXY=False)
    def test_forged_forwarded_for_is_ignored_by_default(self):
        case = make_case(self.user)
        self.client.get(reverse("integrity_view", args=[case.pk]), HTTP_X_FORWARDED_FOR="6.6.6.6")
        self.assertEqual(AuditEvent.objects.filter(investigation=case).first().ip_address, "127.0.0.1")

    @override_settings(TRACEX_TRUST_PROXY=True)
    def test_forwarded_for_honoured_when_proxy_trusted(self):
        case = make_case(self.user)
        self.client.get(reverse("integrity_view", args=[case.pk]), HTTP_X_FORWARDED_FOR="198.51.100.9, 10.0.0.1")
        self.assertEqual(AuditEvent.objects.filter(investigation=case).first().ip_address, "198.51.100.9")


class UploadValidationTests(TestCase):
    LIMIT = 1024

    def check(self, name, head, size=None):
        uploads.validate_upload(name, head, len(head) if size is None else size, self.LIMIT)

    def test_accepts_common_evidence(self):
        self.check("auth.log", b"2026-09-28 02:13:07 failed")
        self.check("alerts.json", b'{"alert": 1}')
        self.check("capture.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        self.check("doc.pdf", b"%PDF-1.7 ...")
        self.check("shot.png", b"\x89PNG\r\n\x1a\n....")
        self.check("blob.bin", b"\x00\x01\x02")

    def test_rejects_unknown_and_dangerous_extensions(self):
        for name in ("run.exe", "page.html", "x.svg", "shell.php", "noext", "a.js", "b.bat"):
            with self.assertRaises(Exception, msg=name):
                self.check(name, b"data")

    def test_rejects_executable_disguised_as_log(self):
        with self.assertRaises(Exception):
            self.check("innocent.log", b"MZ\x90\x00\x03")
        with self.assertRaises(Exception):
            self.check("innocent.txt", b"\x7fELF\x02\x01")

    def test_rejects_binary_in_text_extension(self):
        with self.assertRaises(Exception):
            self.check("data.csv", b"a,b\x00\x01\x02")

    def test_rejects_signature_mismatch(self):
        with self.assertRaises(Exception):
            self.check("fake.pdf", b"not a pdf at all")
        with self.assertRaises(Exception):
            self.check("fake.png", b"GIF89a....")

    def test_rejects_oversize_and_empty(self):
        with self.assertRaises(Exception):
            self.check("big.log", b"x", size=self.LIMIT + 1)
        with self.assertRaises(Exception):
            self.check("empty.log", b"")

    def test_safe_filename_strips_paths_and_controls(self):
        self.assertEqual(uploads.safe_filename("../../etc/passwd"), "passwd")
        self.assertEqual(uploads.safe_filename("C:\\Windows\\evil.log"), "evil.log")
        self.assertEqual(uploads.safe_filename("a\x00b\n.log"), "a_b_.log")
        self.assertEqual(uploads.safe_filename(".hidden"), "hidden")
        self.assertEqual(uploads.safe_filename(""), "evidence")
        self.assertLessEqual(len(uploads.safe_filename("a" * 400 + ".log")), 120)


@override_settings(MEDIA_ROOT=MEDIA)
class UploadViewSecurityTests(TestCase):
    def setUp(self):
        self.user = make_user("uploader")
        self.client.force_login(self.user)
        self.case = make_case(self.user)

    def post(self, name, data):
        return self.client.post(
            reverse("evidence_upload", args=[self.case.pk]), {"files": SimpleUploadedFile(name, data)}, follow=True
        )

    def test_executable_upload_refused_through_view(self):
        response = self.post("payload.exe", b"MZ\x90\x00")
        self.assertContains(response, "not an accepted evidence format")
        self.assertFalse(Evidence.objects.exists())

    def test_disguised_executable_refused_through_view(self):
        self.post("report.txt", b"MZ\x90\x00\x03\x00")
        self.assertFalse(Evidence.objects.exists())

    def test_path_traversal_filename_is_neutralised(self):
        self.post("../../../evil.log", b"2026-09-28 02:13:07 failed login")
        evidence = Evidence.objects.get()
        self.assertEqual(evidence.title, "evil.log")
        self.assertNotIn("..", evidence.file.name)
        self.assertNotIn("/", evidence.original_name)
        self.assertNotIn("\\", evidence.original_name)

    def test_duplicate_evidence_is_skipped_and_reported(self):
        self.post("a.log", b"identical bytes")
        response = self.post("b.log", b"identical bytes")
        self.assertEqual(Evidence.objects.count(), 1)
        self.assertContains(response, "duplicate")


@override_settings(MEDIA_ROOT=MEDIA)
class SecureMediaTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner")
        self.other = make_user("other")
        self.case = make_case(self.owner)
        self.evidence = Evidence(investigation=self.case, title="x.log", evidence_type="log", sha256="0" * 64)
        self.evidence.file.save("x.log", ContentFile(b"secret evidence"), save=False)
        self.evidence.save()

    def url(self):
        return "/media/" + self.evidence.file.name

    def test_other_users_cannot_download_someone_elses_evidence(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(self.url()).status_code, 404)

    def test_owner_download_is_attachment_nosniff_and_audited(self):
        self.client.force_login(self.owner)
        response = self.client.get(self.url())
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertTrue(AuditEvent.objects.filter(action="EVIDENCE_DOWNLOADED", investigation=self.case).exists())

    def test_files_not_registered_as_evidence_are_not_served(self):
        import os
        stray = os.path.join(MEDIA, "stray.txt")
        open(stray, "w").write("not evidence")
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get("/media/stray.txt").status_code, 404)

    def test_path_traversal_rejected(self):
        self.client.force_login(self.owner)
        self.assertIn(self.client.get("/media/../../etc/passwd").status_code, (400, 404))
        self.assertEqual(self.client.get("/media/evidence/%2e%2e/%2e%2e/etc/passwd").status_code, 404)


class LoginThrottleTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user("victim")

    def attempt(self, password):
        return self.client.post(reverse("login"), {"username": "victim", "password": password})

    @override_settings(TRACEX_LOGIN_MAX_ATTEMPTS=3)
    def test_lockout_after_repeated_failures_even_with_correct_password(self):
        for _ in range(3):
            self.assertEqual(self.attempt("wrong").status_code, 200)
        locked = self.attempt("pw-Str0ng-test")
        self.assertEqual(locked.status_code, 429)
        self.assertContains(locked, "Too many failed", status_code=429)
        self.assertTrue(AuditEvent.objects.filter(action="LOGIN_THROTTLED").exists())

    @override_settings(TRACEX_LOGIN_MAX_ATTEMPTS=3)
    def test_successful_login_resets_counter(self):
        self.attempt("wrong")
        self.attempt("wrong")
        self.assertEqual(self.attempt("pw-Str0ng-test").status_code, 302)
        self.client.logout()
        for _ in range(2):
            self.attempt("wrong")
        self.assertEqual(self.attempt("pw-Str0ng-test").status_code, 302)

    @override_settings(TRACEX_LOGIN_MAX_ATTEMPTS=3)
    def test_throttle_is_per_username(self):
        make_user("other")
        for _ in range(3):
            self.attempt("wrong")
        response = self.client.post(reverse("login"), {"username": "other", "password": "pw-Str0ng-test"})
        self.assertEqual(response.status_code, 302)


class AuthenticationTests(TestCase):
    def test_all_workspace_routes_require_login(self):
        case = make_case(make_user("o"))
        for name, args in [
            ("dashboard", []), ("investigation_list", []), ("investigation_create", []),
            ("investigation_detail", [case.pk]), ("integrity_view", [case.pk]),
            ("api_investigations", []), ("api_investigation_detail", [case.pk]), ("api_integrity", [case.pk]),
        ]:
            response = self.client.get(reverse(name, args=args))
            self.assertEqual(response.status_code, 302, name)
            self.assertIn("/accounts/login/", response["Location"], name)

    def test_post_endpoints_enforce_csrf(self):
        from django.test import Client

        owner = make_user("csrf-owner")
        case = make_case(owner)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(owner)
        self.assertEqual(strict.post(reverse("analyze", args=[case.pk])).status_code, 403)
        self.assertEqual(strict.post(reverse("api_analyze", args=[case.pk])).status_code, 403)

    def test_session_cookie_flags(self):
        from django.conf import settings

        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, "Lax")
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")
