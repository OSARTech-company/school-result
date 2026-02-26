import contextlib
import importlib
from datetime import datetime, timedelta

import pytest


@pytest.fixture
def app_module(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/testdb")
    monkeypatch.setenv("DEFAULT_STUDENT_PASSWORD", "password123")
    monkeypatch.setenv("SUPER_ADMIN_PASSWORD", "supersecurepassword")
    monkeypatch.setenv("RUN_STARTUP_DDL", "0")
    monkeypatch.setenv("RUN_STARTUP_BOOTSTRAP", "0")
    monkeypatch.setenv("ALLOW_RUNTIME_SCHEMA_HEAL", "0")

    import student_scor

    mod = importlib.reload(student_scor)
    mod.app.config["TESTING"] = True
    mod.app.config["WTF_CSRF_ENABLED"] = False
    return mod


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


def test_build_subjects_from_config_ss1_combined_merges_all_tracks(app_module):
    m = app_module
    config = {
        "core_subjects": ["English Language", "Mathematics"],
        "science_subjects": ["Biology"],
        "art_subjects": ["Literature in English"],
        "commercial_subjects": ["Economics"],
        "optional_subjects": ["French"],
    }
    school = {"ss1_stream_mode": "combined"}
    subjects, final_stream, err = m.build_subjects_from_config(
        classname="SS1",
        stream="N/A",
        config=config,
        selected_optional_subjects=[],
        school=school,
    )
    assert err is None
    assert final_stream == "N/A"
    assert subjects == [
        "English Language",
        "Mathematics",
        "Biology",
        "Literature in English",
        "Economics",
        "French",
    ]


def test_build_subjects_from_config_stream_rejects_invalid_optional(app_module):
    m = app_module
    config = {
        "core_subjects": ["English Language", "Mathematics"],
        "science_subjects": ["Biology", "Chemistry"],
        "art_subjects": [],
        "commercial_subjects": [],
        "optional_subjects": ["French", "Data Processing"],
    }
    subjects, final_stream, err = m.build_subjects_from_config(
        classname="SS2",
        stream="Science",
        config=config,
        selected_optional_subjects=["French", "Invalid Subject"],
        school={"ss1_stream_mode": "separate"},
    )
    assert subjects is None
    assert final_stream is None
    assert err == "Invalid optional subject selection."


def test_build_subjects_from_config_stream_accepts_multiple_optional_without_limit(app_module):
    m = app_module
    config = {
        "core_subjects": ["English Language", "Mathematics"],
        "science_subjects": ["Biology", "Chemistry"],
        "art_subjects": [],
        "commercial_subjects": [],
        "optional_subjects": ["French", "Data Processing", "Agricultural Science"],
    }
    subjects, final_stream, err = m.build_subjects_from_config(
        classname="SS3",
        stream="Science",
        config=config,
        selected_optional_subjects=["French", "Data Processing", "Agricultural Science"],
        school={},
    )
    assert err is None
    assert final_stream == "Science"
    assert "French" in subjects
    assert "Data Processing" in subjects
    assert "Agricultural Science" in subjects


def test_review_result_approval_request_approve_path(app_module, monkeypatch):
    m = app_module
    called = {}

    monkeypatch.setattr(m, "ensure_result_publication_approval_columns", lambda: True)
    monkeypatch.setattr(
        m,
        "get_result_publication_row",
        lambda *args, **kwargs: {"approval_status": "pending", "is_published": False, "teacher_id": "teacher1"},
    )

    def fake_publish_results_for_class_atomic(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr(m, "publish_results_for_class_atomic", fake_publish_results_for_class_atomic)

    ok, message = m.review_result_approval_request(
        school_id="SCH1",
        classname="SS2",
        term="First Term",
        academic_year="2025-2026",
        admin_user_id="admin1",
        approve=True,
        review_note="Looks good",
    )

    assert ok is True
    assert "approved" in message.lower()
    assert called["teacher_id"] == "teacher1"
    assert called["classname"] == "SS2"


def test_review_result_approval_request_reject_requires_columns(app_module, monkeypatch):
    m = app_module
    monkeypatch.setattr(m, "ensure_result_publication_approval_columns", lambda: True)
    monkeypatch.setattr(
        m,
        "get_result_publication_row",
        lambda *args, **kwargs: {"approval_status": "pending", "is_published": False, "teacher_id": "teacher1"},
    )
    monkeypatch.setattr(m, "result_publication_has_approval_columns", lambda: False)

    ok, message = m.review_result_approval_request(
        school_id="SCH1",
        classname="SS2",
        term="First Term",
        academic_year="2025-2026",
        admin_user_id="admin1",
        approve=False,
        review_note="Fix issues",
    )

    assert ok is False
    assert "approval columns are missing" in message.lower()


def test_promote_students_repeat_path_updates_promoted_without_nameerror(app_module, monkeypatch):
    m = app_module
    captured_updates = []

    class FakeCursor:
        def fetchall(self):
            return [("STU1", "Aka", "JSS1", "JSS1", "[]")]

    class FakeConn:
        def __init__(self):
            self._cursor = FakeCursor()

        def cursor(self):
            return self._cursor

    @contextlib.contextmanager
    def fake_db_connection(commit=False):
        yield FakeConn()

    def fake_db_execute(_cursor, query, params=None):
        if "SET promoted" in query:
            captured_updates.append(params)

    monkeypatch.setattr(m, "db_connection", fake_db_connection)
    monkeypatch.setattr(m, "db_execute", fake_db_execute)
    monkeypatch.setattr(m, "get_school", lambda school_id: {})
    monkeypatch.setattr(m, "normalize_promoted_db_value", lambda value: 1 if value else 0)

    m.promote_students(
        school_id="SCH1",
        from_class="JSS1",
        to_class="JSS2",
        action_by_student={},
        term="",
    )

    assert len(captured_updates) == 1
    assert captured_updates[0][0] == 0


def test_is_login_blocked_returns_wait_time_when_lock_active(app_module, monkeypatch):
    m = app_module

    class FakeCursor:
        def fetchone(self):
            return (4, datetime.now() + timedelta(seconds=61))

    class FakeConn:
        def cursor(self):
            return FakeCursor()

    @contextlib.contextmanager
    def fake_db_connection(commit=False):
        yield FakeConn()

    monkeypatch.setattr(m, "purge_old_login_attempts", lambda: None)
    monkeypatch.setattr(m, "db_connection", fake_db_connection)
    monkeypatch.setattr(m, "db_execute", lambda *args, **kwargs: None)

    blocked, wait_minutes = m.is_login_blocked("login", "User1", "127.0.0.1")
    assert blocked is True
    assert wait_minutes >= 2


def test_register_failed_login_locks_when_threshold_reached(app_module, monkeypatch):
    m = app_module
    updates = []

    class FakeCursor:
        def fetchone(self):
            return (m.LOGIN_MAX_ATTEMPTS - 1, datetime.now(), None)

    class FakeConn:
        def __init__(self):
            self._cursor = FakeCursor()

        def cursor(self):
            return self._cursor

    @contextlib.contextmanager
    def fake_db_connection(commit=False):
        yield FakeConn()

    def fake_db_execute(_cursor, query, params=None):
        if "UPDATE login_attempts" in query:
            updates.append(params)

    monkeypatch.setattr(m, "purge_old_login_attempts", lambda: None)
    monkeypatch.setattr(m, "db_connection", fake_db_connection)
    monkeypatch.setattr(m, "db_execute", fake_db_execute)

    m.register_failed_login("login", "User1", "127.0.0.1")
    assert len(updates) == 1
    assert updates[0][0] == m.LOGIN_MAX_ATTEMPTS
    assert updates[0][2] is not None


def test_get_school_publication_statuses_uses_approval_columns_when_present(app_module, monkeypatch):
    m = app_module

    class FakeCursor:
        def fetchall(self):
            return [
                (
                    "JSS1",
                    "T1",
                    1,
                    "2026-02-26T10:00:00",
                    "approved",
                    "2026-02-26T09:50:00",
                    "teacher1",
                    "2026-02-26T09:55:00",
                    "admin1",
                    "ok",
                )
            ]

    class FakeConn:
        def cursor(self):
            return FakeCursor()

    @contextlib.contextmanager
    def fake_db_connection(commit=False):
        yield FakeConn()

    monkeypatch.setattr(m, "ensure_result_publication_approval_columns", lambda: None)
    monkeypatch.setattr(m, "result_publication_has_approval_columns", lambda: True)
    monkeypatch.setattr(m, "db_connection", fake_db_connection)
    monkeypatch.setattr(m, "db_execute", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        m,
        "get_class_published_view_counts",
        lambda *args, **kwargs: {"JSS1": {"published_count": 20, "viewed_count": 12}},
    )

    assignments = [{"classname": "JSS1", "teacher_name": "Mr T", "teacher_id": "T1", "term": "First Term", "academic_year": "2025-2026"}]
    rows = m.get_school_publication_statuses("SCH1", "First Term", "2025-2026", assignments=assignments)
    assert len(rows) == 1
    assert rows[0]["approval_status"] == "approved"
    assert rows[0]["is_published"] is True
    assert rows[0]["published_count"] == 20
    assert rows[0]["viewed_count"] == 12


def test_get_school_publication_statuses_fallback_when_approval_columns_missing(app_module, monkeypatch):
    m = app_module

    class FakeCursor:
        def fetchall(self):
            return [("JSS2", "T2", 0, "")]

    class FakeConn:
        def cursor(self):
            return FakeCursor()

    @contextlib.contextmanager
    def fake_db_connection(commit=False):
        yield FakeConn()

    monkeypatch.setattr(m, "ensure_result_publication_approval_columns", lambda: None)
    monkeypatch.setattr(m, "result_publication_has_approval_columns", lambda: False)
    monkeypatch.setattr(m, "db_connection", fake_db_connection)
    monkeypatch.setattr(m, "db_execute", lambda *args, **kwargs: None)
    monkeypatch.setattr(m, "get_class_published_view_counts", lambda *args, **kwargs: {})

    assignments = [{"classname": "JSS2", "teacher_name": "Mrs T", "teacher_id": "T2", "term": "First Term", "academic_year": "2025-2026"}]
    rows = m.get_school_publication_statuses("SCH1", "First Term", "2025-2026", assignments=assignments)
    assert len(rows) == 1
    assert rows[0]["approval_status"] == "not_submitted"
    assert rows[0]["is_published"] is False


def test_teacher_publish_results_route_submits_for_approval(client, app_module, monkeypatch):
    m = app_module
    called = {}

    monkeypatch.setattr(m, "get_school", lambda school_id: {"academic_year": "2025-2026", "principal_signature_image": "sig"})
    monkeypatch.setattr(m, "get_teachers", lambda school_id: {"T1": {"signature_image": "sig"}})
    monkeypatch.setattr(m, "get_current_term", lambda school: "First Term")
    monkeypatch.setattr(m, "teacher_has_class_access", lambda *args, **kwargs: True)
    monkeypatch.setattr(m, "is_result_published", lambda *args, **kwargs: False)
    monkeypatch.setattr(m, "get_result_publication_row", lambda *args, **kwargs: {})
    monkeypatch.setattr(m, "load_students", lambda *args, **kwargs: {"S1": {"firstname": "Aka"}})
    monkeypatch.setattr(m, "is_student_score_complete", lambda *args, **kwargs: True)

    def fake_submit(school_id, classname, term, academic_year, teacher_id):
        called.update(
            {
                "school_id": school_id,
                "classname": classname,
                "term": term,
                "academic_year": academic_year,
                "teacher_id": teacher_id,
            }
        )

    monkeypatch.setattr(m, "submit_result_approval_request", fake_submit)

    with client.session_transaction() as sess:
        sess["role"] = "teacher"
        sess["school_id"] = "SCH1"
        sess["user_id"] = "T1"

    resp = client.post("/teacher/publish-results", data={"classname": "JSS1"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/teacher")
    assert called["classname"] == "JSS1"
    assert called["teacher_id"] == "T1"


def test_school_admin_approve_results_route_calls_review(client, app_module, monkeypatch):
    m = app_module
    called = {}

    monkeypatch.setattr(m, "get_school", lambda school_id: {"academic_year": "2025-2026"})
    monkeypatch.setattr(m, "get_current_term", lambda school: "First Term")

    def fake_review(**kwargs):
        called.update(kwargs)
        return True, "approved"

    monkeypatch.setattr(m, "review_result_approval_request", fake_review)

    with client.session_transaction() as sess:
        sess["role"] = "school_admin"
        sess["school_id"] = "SCH1"
        sess["user_id"] = "A1"

    resp = client.post("/school-admin/approve-results", data={"classname": "JSS1", "review_note": "ok"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/school-admin")
    assert called["approve"] is True
    assert called["classname"] == "JSS1"
    assert called["admin_user_id"] == "A1"


def test_school_admin_reject_results_route_calls_review(client, app_module, monkeypatch):
    m = app_module
    called = {}

    monkeypatch.setattr(m, "get_school", lambda school_id: {"academic_year": "2025-2026"})
    monkeypatch.setattr(m, "get_current_term", lambda school: "First Term")

    def fake_review(**kwargs):
        called.update(kwargs)
        return True, "rejected"

    monkeypatch.setattr(m, "review_result_approval_request", fake_review)

    with client.session_transaction() as sess:
        sess["role"] = "school_admin"
        sess["school_id"] = "SCH1"
        sess["user_id"] = "A1"

    resp = client.post("/school-admin/reject-results", data={"classname": "JSS1", "review_note": "needs fix"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/school-admin")
    assert called["approve"] is False
    assert called["classname"] == "JSS1"
    assert called["admin_user_id"] == "A1"
    assert called["review_note"] == "needs fix"


def test_school_admin_dashboard_passes_assignments_to_publication_statuses(client, app_module, monkeypatch):
    m = app_module
    captured = {}
    assignments = [{"classname": "JSS1", "teacher_name": "Mr T", "teacher_id": "T1", "term": "First Term", "academic_year": "2025-2026"}]

    monkeypatch.setattr(m, "get_school", lambda school_id: {"academic_year": "2025-2026", "principal_signature_image": ""})
    monkeypatch.setattr(m, "get_current_term", lambda school: "First Term")
    monkeypatch.setattr(m, "get_total_student_count", lambda school_id: 1)
    monkeypatch.setattr(m, "get_teachers", lambda school_id: {})
    monkeypatch.setattr(m, "get_student_count_by_class", lambda school_id: {})
    monkeypatch.setattr(m, "get_class_assignments", lambda school_id: assignments)
    monkeypatch.setattr(m, "get_last_login_at", lambda user_id: None)
    monkeypatch.setattr(m, "format_timestamp", lambda value: "")
    monkeypatch.setattr(m, "render_template", lambda *args, **kwargs: "OK")

    def fake_statuses(school_id, term, academic_year, assignments=None):
        captured["assignments"] = assignments
        return []

    monkeypatch.setattr(m, "get_school_publication_statuses", fake_statuses)

    # also verify approval workflow flag passed through
    monkeypatch.setattr(m, "result_publication_has_approval_columns", lambda: False)

    with client.session_transaction() as sess:
        sess["role"] = "school_admin"
        sess["school_id"] = "SCH1"
        sess["user_id"] = "A1"

    # patch render_template to capture its keyword args
    captured_render = {}
    def fake_render(template, **kwargs):
        captured_render.update(kwargs)
        return "OK"
    monkeypatch.setattr(m, "render_template", fake_render)

    resp = client.get("/school-admin")
    assert resp.status_code == 200
    assert captured["assignments"] is assignments
    # ensure the flag is passed and reflects the mocked approval column state
    assert captured_render.get("approval_workflow_enabled") is False
    # dashboard should include the flag even though render_template is stubbed
    # (check second argument of render_template)
    # since render_template returns "OK" we can't inspect output easily; instead
    # monkeypatch render_template to capture kwargs
    
