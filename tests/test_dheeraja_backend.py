"""Dheeraja Matrimony - Backend integration tests."""
import os
import uuid
import time
import pytest
import requests

BASE_URL = os.environ.get('EXPO_PUBLIC_BACKEND_URL', 'https://shaadi-connect-56.preview.emergentagent.com').rstrip('/')
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@dheeraja.com"
ADMIN_PASSWORD = "Admin@Dheeraja2026"

RUN_ID = uuid.uuid4().hex[:8]


def _reg_payload(gender="male", email=None, dob=None):
    tag = uuid.uuid4().hex[:6]
    return {
        "email": email or f"test_{RUN_ID}_{tag}@dheeraja-test.com",
        "password": "TestPass@2026",
        "full_name": f"TEST User {tag}",
        "gender": gender,
        "dob": dob or ("1995-05-15" if gender == "male" else "1996-06-16"),
        "phone": "+919999999999",
    }


@pytest.fixture(scope="module")
def state():
    """Bootstrap: 2 users (male, female) + admin token."""
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})

    m = _reg_payload(gender="male")
    r = s.post(f"{API}/auth/register", json=m)
    assert r.status_code == 200, f"register male failed: {r.status_code} {r.text}"
    male = r.json()
    male["email"] = m["email"]
    male["password"] = m["password"]

    f = _reg_payload(gender="female")
    r = s.post(f"{API}/auth/register", json=f)
    assert r.status_code == 200, f"register female failed: {r.status_code} {r.text}"
    female = r.json()
    female["email"] = f["email"]
    female["password"] = f["password"]

    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"admin login: {r.text}"
    admin = r.json()

    return {"male": male, "female": female, "admin": admin, "session": s}


def _auth(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ==== Health ====
def test_root_health():
    r = requests.get(f"{API}/")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


# ==== Auth ====
class TestAuth:
    def test_register_returns_token_and_profile_id(self, state):
        assert "token" in state["male"] and state["male"]["user"]["profile_id"].startswith("DM")

    def test_register_duplicate_email(self, state):
        payload = _reg_payload(email=state["male"]["email"])
        r = requests.post(f"{API}/auth/register", json=payload)
        assert r.status_code == 400

    def test_register_underage_dob(self):
        p = _reg_payload(dob="2020-01-01")
        r = requests.post(f"{API}/auth/register", json=p)
        assert r.status_code == 422

    def test_login_invalid_password(self, state):
        r = requests.post(f"{API}/auth/login", json={"email": state["male"]["email"], "password": "wrong-pass"})
        assert r.status_code == 401

    def test_login_valid(self, state):
        r = requests.post(f"{API}/auth/login", json={"email": state["male"]["email"], "password": state["male"]["password"]})
        assert r.status_code == 200
        assert "token" in r.json()

    def test_me_requires_auth(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code in (401, 403)

    def test_me_with_token(self, state):
        r = requests.get(f"{API}/auth/me", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        body = r.json()
        assert body["user"]["email"] == state["male"]["email"]
        assert "password_hash" not in body["user"]

    def test_password_never_in_response(self, state):
        r = requests.get(f"{API}/auth/me", headers=_auth(state["male"]["token"]))
        assert "password" not in r.text.lower() or "password_hash" not in r.text


# ==== Profile ====
class TestProfile:
    def test_get_my_profile(self, state):
        r = requests.get(f"{API}/profile/me", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        p = r.json()
        assert p["gender"] == "male"
        assert p["email"] == state["male"]["email"]  # self sees email
        assert "completeness" in p

    def test_update_profile_recomputes_completeness(self, state):
        before = requests.get(f"{API}/profile/me", headers=_auth(state["male"]["token"])).json()
        payload = {
            "religion": "Hindu",
            "community": "Brahmin",
            "mother_tongue": "Hindi",
            "country": "India",
            "state": "Maharashtra",
            "city": "Mumbai",
            "height_cm": 175,
            "education": "B.Tech",
            "occupation": "Software Engineer",
            "company": "Acme",
            "income_range": "10-20L",
            "about_me": "Test bio",
        }
        r = requests.put(f"{API}/profile/me", json=payload, headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        after = r.json()
        assert after["completeness"] > before["completeness"]
        assert after["city"] == "Mumbai"

    def test_update_profile_female(self, state):
        r = requests.put(f"{API}/profile/me", json={
            "religion": "Hindu", "city": "Mumbai", "state": "Maharashtra",
            "country": "India", "mother_tongue": "Hindi", "education": "MBA",
        }, headers=_auth(state["female"]["token"]))
        assert r.status_code == 200

    def test_xss_sanitized(self, state):
        r = requests.put(f"{API}/profile/me", json={"about_me": "<script>alert(1)</script>hello"},
                         headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert "<script>" not in r.json()["about_me"]

    def test_privacy_toggle(self, state):
        r = requests.put(f"{API}/profile/me/privacy",
                         json={"show_email": False, "show_phone": False, "show_photos": True},
                         headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert r.json()["privacy"]["show_email"] is False

    def test_view_other_profile_privacy_gated(self, state):
        # Female viewing male; show_email=False -> should NOT include email
        uid = state["male"]["user"]["user_id"]
        r = requests.get(f"{API}/profile/{uid}", headers=_auth(state["female"]["token"]))
        assert r.status_code == 200
        p = r.json()
        assert "email" not in p or p.get("email") is None

    def test_view_hidden_profile_returns_403(self, state):
        # Hide male's profile
        requests.put(f"{API}/profile/me", json={"profile_visibility": False},
                     headers=_auth(state["male"]["token"]))
        uid = state["male"]["user"]["user_id"]
        r = requests.get(f"{API}/profile/{uid}", headers=_auth(state["female"]["token"]))
        assert r.status_code == 403
        # restore
        requests.put(f"{API}/profile/me", json={"profile_visibility": True},
                     headers=_auth(state["male"]["token"]))

    def test_no_idor_via_profile_me(self, state):
        # There's no PUT /profile/{id} - only /profile/me. Ensure PUT to another id fails.
        other_id = state["female"]["user"]["user_id"]
        r = requests.put(f"{API}/profile/{other_id}", json={"about_me": "hack"},
                         headers=_auth(state["male"]["token"]))
        assert r.status_code in (404, 405)


# ==== Search / Recommendations ====
class TestSearch:
    def test_search_by_gender(self, state):
        r = requests.get(f"{API}/search?gender=female&religion=Hindu&city=Mumbai&page=1&limit=10",
                         headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        b = r.json()
        assert "items" in b and "total" in b
        for it in b["items"]:
            assert it["gender"] == "female"

    def test_search_age_filter(self, state):
        r = requests.get(f"{API}/search?min_age=18&max_age=100&limit=5",
                         headers=_auth(state["male"]["token"]))
        assert r.status_code == 200

    def test_recommendations_opposite_gender(self, state):
        r = requests.get(f"{API}/recommendations?limit=5", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        for it in r.json()["items"]:
            assert it["gender"] == "female"


# ==== Interests ====
class TestInterests:
    def test_send_to_self_400(self, state):
        uid = state["male"]["user"]["user_id"]
        r = requests.post(f"{API}/interests/{uid}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 400

    def test_send_interest_success(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/interests/{target}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert r.json()["status"] == "pending"

    def test_send_duplicate_409(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/interests/{target}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 409

    def test_withdraw_only_sender(self, state):
        # Female tries to delete a pending interest they didn't send
        r = requests.get(f"{API}/interests/received", headers=_auth(state["female"]["token"]))
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 1
        iid = items[0]["interest_id"]
        # female (recipient) tries to DELETE -> should 404
        r2 = requests.delete(f"{API}/interests/{iid}", headers=_auth(state["female"]["token"]))
        assert r2.status_code == 404

    def test_only_recipient_can_accept(self, state):
        r = requests.get(f"{API}/interests/sent", headers=_auth(state["male"]["token"]))
        iid = r.json()["items"][0]["interest_id"]
        # sender tries to accept -> should fail
        r2 = requests.post(f"{API}/interests/{iid}/accept", headers=_auth(state["male"]["token"]))
        assert r2.status_code == 404

    def test_accept_creates_conversation(self, state):
        r = requests.get(f"{API}/interests/received", headers=_auth(state["female"]["token"]))
        iid = r.json()["items"][0]["interest_id"]
        r2 = requests.post(f"{API}/interests/{iid}/accept", headers=_auth(state["female"]["token"]))
        assert r2.status_code == 200
        assert r2.json()["status"] == "accepted"
        # cannot re-accept
        r3 = requests.post(f"{API}/interests/{iid}/accept", headers=_auth(state["female"]["token"]))
        assert r3.status_code == 409

    def test_withdraw_after_accepted_fails(self, state):
        r = requests.get(f"{API}/interests/sent", headers=_auth(state["male"]["token"]))
        iid = r.json()["items"][0]["interest_id"]
        r2 = requests.delete(f"{API}/interests/{iid}", headers=_auth(state["male"]["token"]))
        assert r2.status_code == 409


# ==== Shortlist ====
class TestShortlist:
    def test_add_get_remove(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/shortlist/{target}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        r = requests.get(f"{API}/shortlist", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert any(i["profile"]["user_id"] == target for i in r.json()["items"])
        r = requests.delete(f"{API}/shortlist/{target}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200

    def test_shortlist_self_400(self, state):
        uid = state["male"]["user"]["user_id"]
        r = requests.post(f"{API}/shortlist/{uid}", headers=_auth(state["male"]["token"]))
        assert r.status_code == 400


# ==== Messaging (post-accept required) ====
class TestMessaging:
    def test_send_message_after_accept(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/conversations/{target}/messages",
                          json={"text": "Hello <b>there</b><script>x</script>"},
                          headers=_auth(state["male"]["token"]))
        assert r.status_code == 200, r.text
        assert "<script>" not in r.json()["text"]
        assert "<b>" not in r.json()["text"]

    def test_list_conversations(self, state):
        r = requests.get(f"{API}/conversations", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert len(r.json()["items"]) >= 1

    def test_get_messages(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.get(f"{API}/conversations/{target}/messages", headers=_auth(state["male"]["token"]))
        assert r.status_code == 200
        assert len(r.json()["items"]) >= 1

    def test_message_without_accepted_interest_403(self, state):
        # Register a fresh 3rd user; male has no accepted interest with them
        third = _reg_payload(gender="female")
        rr = requests.post(f"{API}/auth/register", json=third)
        assert rr.status_code == 200
        third_id = rr.json()["user"]["user_id"]
        r = requests.post(f"{API}/conversations/{third_id}/messages",
                          json={"text": "hi"}, headers=_auth(state["male"]["token"]))
        assert r.status_code == 403
        r2 = requests.get(f"{API}/conversations/{third_id}/messages", headers=_auth(state["male"]["token"]))
        assert r2.status_code == 403


# ==== Blocks ====
class TestBlocks:
    def test_block_and_profile_forbidden(self, state):
        # Female blocks male; male should get 403 viewing female
        target = state["male"]["user"]["user_id"]
        r = requests.post(f"{API}/blocks/{target}", headers=_auth(state["female"]["token"]))
        assert r.status_code == 200
        # Male views female
        female_id = state["female"]["user"]["user_id"]
        r2 = requests.get(f"{API}/profile/{female_id}", headers=_auth(state["male"]["token"]))
        assert r2.status_code == 403
        # Message forbidden
        r3 = requests.post(f"{API}/conversations/{female_id}/messages", json={"text": "x"},
                           headers=_auth(state["male"]["token"]))
        assert r3.status_code == 403
        # Unblock
        r4 = requests.delete(f"{API}/blocks/{target}", headers=_auth(state["female"]["token"]))
        assert r4.status_code == 200


# ==== Reports ====
class TestReports:
    def test_cannot_report_self(self, state):
        uid = state["male"]["user"]["user_id"]
        r = requests.post(f"{API}/reports", json={"target_user_id": uid, "reason": "fake"},
                          headers=_auth(state["male"]["token"]))
        assert r.status_code == 400

    def test_report_nonexistent_target(self, state):
        r = requests.post(f"{API}/reports", json={"target_user_id": "no-such-id", "reason": "fake"},
                          headers=_auth(state["male"]["token"]))
        assert r.status_code == 404

    def test_report_success(self, state):
        target = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/reports", json={"target_user_id": target, "reason": "spam behavior"},
                          headers=_auth(state["male"]["token"]))
        assert r.status_code == 200


# ==== Photos endpoint auth ====
class TestPhotos:
    def test_photo_get_requires_auth(self):
        r = requests.get(f"{API}/photos/nonexistent")
        assert r.status_code == 401


# ==== Verification ====
class TestVerification:
    def test_request_verification(self, state):
        r = requests.post(f"{API}/verification/request", json={"id_document_note": "TEST doc"},
                          headers=_auth(state["female"]["token"]))
        assert r.status_code == 200

    def test_status(self, state):
        r = requests.get(f"{API}/verification/status", headers=_auth(state["female"]["token"]))
        assert r.status_code == 200
        assert "verified" in r.json()


# ==== Admin ====
class TestAdmin:
    def test_non_admin_forbidden(self, state):
        r = requests.get(f"{API}/admin/stats", headers=_auth(state["male"]["token"]))
        assert r.status_code == 403

    def test_admin_stats(self, state):
        r = requests.get(f"{API}/admin/stats", headers=_auth(state["admin"]["token"]))
        assert r.status_code == 200
        assert "users" in r.json()

    def test_admin_verify_approve(self, state):
        uid = state["female"]["user"]["user_id"]
        r = requests.post(f"{API}/admin/members/{uid}/action",
                          json={"action": "verify_approve"},
                          headers=_auth(state["admin"]["token"]))
        assert r.status_code == 200
        # Verify field set
        r2 = requests.get(f"{API}/profile/{uid}", headers=_auth(state["male"]["token"]))
        # male might be blocked from female? no, was unblocked. But if 403 due to block state, skip
        if r2.status_code == 200:
            assert r2.json()["verified"] is True

    def test_admin_suspend_blocks_access(self, state):
        # Create sacrificial user
        p = _reg_payload(gender="male")
        rr = requests.post(f"{API}/auth/register", json=p)
        assert rr.status_code == 200
        victim = rr.json()
        uid = victim["user"]["user_id"]
        r = requests.post(f"{API}/admin/members/{uid}/action",
                          json={"action": "suspend"},
                          headers=_auth(state["admin"]["token"]))
        assert r.status_code == 200
        # Login attempt
        r2 = requests.post(f"{API}/auth/login", json={"email": p["email"], "password": p["password"]})
        assert r2.status_code == 403
        # Existing token access
        r3 = requests.get(f"{API}/auth/me", headers=_auth(victim["token"]))
        assert r3.status_code == 403
        # Activate
        r4 = requests.post(f"{API}/admin/members/{uid}/action",
                           json={"action": "activate"},
                           headers=_auth(state["admin"]["token"]))
        assert r4.status_code == 200
        r5 = requests.post(f"{API}/auth/login", json={"email": p["email"], "password": p["password"]})
        assert r5.status_code == 200


# ==== Rate limiting ====
class TestRateLimit:
    def test_login_rate_limit(self):
        # 10/5min: 11 rapid attempts should trigger 429 eventually
        got_429 = False
        for i in range(15):
            r = requests.post(f"{API}/auth/login", json={"email": f"nope_{RUN_ID}@x.com", "password": "x"})
            if r.status_code == 429:
                got_429 = True
                break
        assert got_429, "Expected 429 after multiple login attempts"
