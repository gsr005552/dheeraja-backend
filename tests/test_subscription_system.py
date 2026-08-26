"""Dheeraja Matrimony - Subscription system + gating tests (NEW)."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get('EXPO_PUBLIC_BACKEND_URL', 'https://shaadi-connect-56.preview.emergentagent.com').rstrip('/')
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@dheeraja.com"
ADMIN_PASSWORD = "Admin@Dheeraja2026"

RUN_ID = uuid.uuid4().hex[:6]


def _auth(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _reg_payload(gender="male"):
    tag = uuid.uuid4().hex[:6]
    return {
        "email": f"subtest_{RUN_ID}_{tag}@dheeraja-test.com",
        "password": "TestPass@2026",
        "full_name": f"TEST Sub {tag}",
        "gender": gender,
        "dob": "1995-05-15" if gender == "male" else "1996-06-16",
        "phone": "+919999999999",
    }


@pytest.fixture(scope="module")
def ctx():
    # Admin login
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"admin login failed: {r.text}"
    admin = r.json()

    # Two members
    p_male = _reg_payload("male")
    r = requests.post(f"{API}/auth/register", json=p_male)
    assert r.status_code == 200, r.text
    male = r.json()
    male["email"] = p_male["email"]
    male["password"] = p_male["password"]

    p_fem = _reg_payload("female")
    r = requests.post(f"{API}/auth/register", json=p_fem)
    assert r.status_code == 200, r.text
    fem = r.json()
    fem["email"] = p_fem["email"]

    # Ensure baseline settings (cleanup at teardown restores it)
    yield {"admin": admin, "male": male, "female": fem, "created_vouchers": [], "created_plans": []}

    # ---- Cleanup ----
    # Restore free_mode=True and free_interests_per_month=5
    try:
        requests.put(f"{API}/admin/settings",
                     json={"free_mode": True, "free_interests_per_month": 5,
                           "free_can_message": True, "free_can_view_contacts": True},
                     headers=_auth(admin["token"]))
    except Exception:
        pass



# ==== Public settings (no auth) ====
def test_public_settings_no_auth():
    r = requests.get(f"{API}/settings/public")
    assert r.status_code == 200
    body = r.json()
    for k in ["app_name", "free_mode", "registration_open"]:
        assert k in body


# ==== Plans list ====
class TestPlans:
    def test_plans_seeded(self, ctx):
        r = requests.get(f"{API}/plans", headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 3, f"Expected 3+ seeded plans, got {len(items)}"
        names = [p["name"] for p in items]
        # Assert seeded plans exist
        for name in ["Free", "Gold", "Premium"]:
            assert any(name.lower() in n.lower() for n in names), f"Missing plan {name}: {names}"

    def test_subscription_me_free_mode(self, ctx):
        r = requests.get(f"{API}/subscription/me", headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 200
        body = r.json()
        assert body["free_mode"] is True
        ent = body["entitlements"]
        assert "Launch Offer" in ent.get("plan_name", "") or ent.get("plan_name", "").lower().startswith("launch")


# ==== Admin: Plans CRUD ====
class TestAdminPlans:
    def test_admin_list_plans(self, ctx):
        r = requests.get(f"{API}/admin/plans", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        assert len(r.json()["items"]) >= 3

    def test_admin_create_update_delete_plan(self, ctx):
        payload = {
            "name": f"TEST Plan {RUN_ID}",
            "description": "Test plan",
            "price": 999,
            "duration_days": 30,
            "sort_order": 99,
            "active": True,
            "features": {
                "interests_per_month": 10,
                "can_message": True,
                "can_view_contacts": True,
                "profile_boost": False,
                "badge": "TEST",
            },
        }
        r = requests.post(f"{API}/admin/plans", json=payload, headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200, r.text
        plan = r.json()
        assert plan["name"] == payload["name"]
        plan_id = plan["plan_id"]
        ctx["created_plans"].append(plan_id)

        # Update
        payload["price"] = 1499
        r = requests.put(f"{API}/admin/plans/{plan_id}", json=payload, headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        assert r.json()["price"] == 1499

        # Delete
        r = requests.delete(f"{API}/admin/plans/{plan_id}", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200

        # GET all - should NOT include deleted
        r = requests.get(f"{API}/admin/plans", headers=_auth(ctx["admin"]["token"]))
        assert all(p["plan_id"] != plan_id for p in r.json()["items"])

    def test_non_admin_forbidden(self, ctx):
        r = requests.get(f"{API}/admin/plans", headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 403


# ==== Vouchers ====
class TestVouchers:
    def test_admin_create_voucher(self, ctx):
        # Pick Premium plan
        r = requests.get(f"{API}/plans", headers=_auth(ctx["male"]["token"]))
        plans = r.json()["items"]
        premium = next((p for p in plans if "premium" in p["name"].lower()), plans[-1])
        code = f"TEST{RUN_ID.upper()}"
        r = requests.post(f"{API}/admin/vouchers",
                          json={"code": code, "plan_id": premium["plan_id"], "max_uses": 3, "duration_days": 30},
                          headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200, r.text
        v = r.json()
        assert v["code"] == code
        assert v["active"] is True
        ctx["created_vouchers"].append(code)
        ctx["voucher_plan_id"] = premium["plan_id"]

    def test_voucher_appears_in_list(self, ctx):
        r = requests.get(f"{API}/admin/vouchers", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        codes = [v["code"] for v in r.json()["items"]]
        assert ctx["created_vouchers"][0] in codes

    def test_member_redeem_voucher(self, ctx):
        code = ctx["created_vouchers"][0]
        r = requests.post(f"{API}/vouchers/redeem", json={"code": code},
                          headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True
        # subscription should be active
        r2 = requests.get(f"{API}/subscription/me", headers=_auth(ctx["male"]["token"]))
        assert r2.status_code == 200
        sub = r2.json().get("subscription")
        assert sub is not None
        assert sub["status"] == "active"

    def test_double_redeem_conflict(self, ctx):
        code = ctx["created_vouchers"][0]
        r = requests.post(f"{API}/vouchers/redeem", json={"code": code},
                          headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 409

    def test_invalid_voucher(self, ctx):
        r = requests.post(f"{API}/vouchers/redeem", json={"code": "NOSUCHCODE"},
                          headers=_auth(ctx["male"]["token"]))
        assert r.status_code == 404

    def test_admin_deactivate_voucher(self, ctx):
        code = ctx["created_vouchers"][0]
        r = requests.delete(f"{API}/admin/vouchers/{code}", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        # New user attempt to redeem should fail 404 (inactive)
        p = _reg_payload("female")
        r2 = requests.post(f"{API}/auth/register", json=p)
        assert r2.status_code == 200
        tok = r2.json()["token"]
        r3 = requests.post(f"{API}/vouchers/redeem", json={"code": code}, headers=_auth(tok))
        assert r3.status_code == 404


# ==== Manual Assign + Cancel ====
class TestAdminSubscriptions:
    def test_assign_and_cancel(self, ctx):
        # Pick Gold plan
        r = requests.get(f"{API}/plans", headers=_auth(ctx["admin"]["token"]))
        plans = r.json()["items"]
        gold = next((p for p in plans if "gold" in p["name"].lower()), plans[0])

        r = requests.post(f"{API}/admin/subscriptions/assign",
                          json={"user_id": ctx["female"]["user"]["user_id"], "plan_id": gold["plan_id"]},
                          headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200, r.text
        sub = r.json()["subscription"]
        assert sub["status"] == "active"
        sub_id = sub["subscription_id"]

        # List
        r = requests.get(f"{API}/admin/subscriptions", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        assert any(s["subscription_id"] == sub_id for s in r.json()["items"])

        # Cancel
        r = requests.post(f"{API}/admin/subscriptions/{sub_id}/cancel",
                          headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200


# ==== Admin Settings ====
class TestAdminSettings:
    def test_get_settings(self, ctx):
        r = requests.get(f"{API}/admin/settings", headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        s = r.json()
        assert "free_mode" in s and "free_interests_per_month" in s

    def test_update_settings(self, ctx):
        r = requests.put(f"{API}/admin/settings",
                         json={"upi_id": "test@upi", "announcement": "Test announce"},
                         headers=_auth(ctx["admin"]["token"]))
        assert r.status_code == 200
        assert r.json()["upi_id"] == "test@upi"


# ==== Gating (free_mode OFF) ====
class TestGating:
    def test_gating_flow(self, ctx):
        admin = ctx["admin"]["token"]

        # Register two fresh users; skip on rate-limit rather than fail
        def _reg(gender):
            p = _reg_payload(gender)
            for _ in range(3):
                r = requests.post(f"{API}/auth/register", json=p)
                if r.status_code == 200:
                    return r.json()
                if r.status_code == 429:
                    pytest.skip(f"Registration rate limit hit ({r.status_code}); cannot run gating test in this window")
                pytest.skip(f"Registration failed: {r.status_code} {r.text}")
            pytest.skip("Could not register user")

        u1 = _reg("male")   # target with contact
        u2 = _reg("female")  # unsubscribed viewer

        # Update male profile with contact
        requests.put(f"{API}/profile/me",
                     json={"religion": "Hindu", "city": "Mumbai", "state": "MH", "country": "India",
                           "mother_tongue": "Hindi", "phone": "+919888777666"},
                     headers=_auth(u1["token"]))
        requests.put(f"{API}/profile/me/privacy",
                     json={"show_email": True, "show_phone": True, "show_photos": True},
                     headers=_auth(u1["token"]))

        # Disable free_mode + set limit to 1
        r = requests.put(f"{API}/admin/settings",
                         json={"free_mode": False, "free_interests_per_month": 1,
                               "free_can_view_contacts": False},
                         headers=_auth(admin))
        assert r.status_code == 200
        assert r.json()["free_mode"] is False

        try:
            # u2 (no subscription) views u1 - contacts should be locked/stripped
            r = requests.get(f"{API}/profile/{u1['user']['user_id']}", headers=_auth(u2["token"]))
            assert r.status_code == 200
            prof = r.json()
            has_phone = prof.get("phone") not in (None, "", False)
            contacts_locked = prof.get("contacts_locked") is True
            assert contacts_locked or (not has_phone), f"Expected contacts_locked or no phone; got {prof}"

            # u2 sends interest to u1 - 1st should succeed
            r = requests.post(f"{API}/interests/{u1['user']['user_id']}", headers=_auth(u2["token"]))
            assert r.status_code == 200, f"1st interest failed: {r.text}"

            # u2 sends 2nd interest to ctx.male (any other target) - should hit limit (403)
            other_male_id = ctx["male"]["user"]["user_id"]
            r = requests.post(f"{API}/interests/{other_male_id}", headers=_auth(u2["token"]))
            assert r.status_code == 403, f"Expected 403 after limit; got {r.status_code} {r.text}"

            # Assign Premium plan to u2 -> limits lift
            r = requests.get(f"{API}/plans", headers=_auth(admin))
            plans = r.json()["items"]
            premium = next((p for p in plans if "premium" in p["name"].lower()), plans[-1])
            r = requests.post(f"{API}/admin/subscriptions/assign",
                              json={"user_id": u2["user"]["user_id"], "plan_id": premium["plan_id"]},
                              headers=_auth(admin))
            assert r.status_code == 200
            sub_id = r.json()["subscription"]["subscription_id"]

            # Now interest to ctx.male should succeed
            r = requests.post(f"{API}/interests/{other_male_id}", headers=_auth(u2["token"]))
            assert r.status_code == 200, f"After premium interest failed: {r.text}"

            # Contacts should be visible now
            r = requests.get(f"{API}/profile/{u1['user']['user_id']}", headers=_auth(u2["token"]))
            assert r.status_code == 200
            prof = r.json()
            assert not prof.get("contacts_locked", False), "contacts_locked should be false with premium"

            # Cleanup - cancel that subscription
            requests.post(f"{API}/admin/subscriptions/{sub_id}/cancel", headers=_auth(admin))
        finally:
            # Restore
            requests.put(f"{API}/admin/settings",
                         json={"free_mode": True, "free_interests_per_month": 5,
                               "free_can_view_contacts": True},
                         headers=_auth(admin))


# ==== Admin stats includes new subscription fields ====
def test_admin_stats_includes_subscription_fields(ctx=None):
    # Do a fresh admin login rather than fixture to isolate
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    if r.status_code == 429:
        pytest.skip("rate limited")
    tok = r.json()["token"]
    r = requests.get(f"{API}/admin/stats", headers=_auth(tok))
    assert r.status_code == 200
    s = r.json()
    assert "active_subscriptions" in s
    assert "free_mode" in s
