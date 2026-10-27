"""Real Chromium + PostgreSQL end-to-end journeys for the DevShield console.

Requires an isolated, disposable PostgreSQL database and Playwright Chromium:
  DEVSHIELD_TEST_PG_DSN=... pytest -q tests/test_browser_console_e2e.py

Creates unique tenants, does not truncate any table or access production data.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect, sync_playwright

from devshield.ops_console import make_handler as console_handler
from devshield.ops_store import OpsStore
from devshield.protected_api import make_handler as protected_handler

DSN = os.environ.get("DEVSHIELD_TEST_PG_DSN")
ADMIN_PASSWORD = "Only-for-local-browser-tests-123!"
TOKEN = "local-e2e-token-" + ("X" * 48)


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as pw:
        instance = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            yield instance
        finally:
            instance.close()


@pytest.fixture()
def site():
    if not DSN:
        pytest.skip("DEVSHIELD_TEST_PG_DSN must target an isolated test database")
    store = OpsStore(DSN)
    store.migrate()
    tenant = "browser-" + secrets.token_hex(9)
    assert store.provision_user(
        tenant=tenant, user="root", password=ADMIN_PASSWORD, role="org_admin"
    )
    with serve(console_handler(store)) as base:
        yield store, tenant, base


@contextmanager
def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def sign_in(page, base, tenant, user="root", password=ADMIN_PASSWORD):
    response = page.goto(base, wait_until="domcontentloaded")
    assert response and response.status == 200
    expect(page.locator("#login")).to_be_visible()
    page.locator("#tenant").fill(tenant)
    page.locator("#user").fill(user)
    page.locator("#password").fill(password)
    page.locator("#login-form button").click()
    expect(page.locator("#dash")).to_be_visible(timeout=10000)
    expect(page.locator("#identity")).to_contain_text(tenant)
    expect(page.locator("#identity")).to_contain_text(user)


def quote(base):
    req = Request(
        base + "/v1/quote",
        data=json.dumps({"tier": "basic", "units": 2}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + TOKEN},
        method="POST",
    )
    try:
        response = urlopen(req, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read())


def test_admin_browser_login_restriction_enforcement_users_and_logout(browser, site):
    store, tenant, base = site
    with browser.new_context(viewport={"width": 1440, "height": 900}) as ctx:
        page = ctx.new_page()
        sign_in(page, base, tenant)
        expect(page.locator("#metrics .card")).to_have_count(3)
        expect(page.locator("#restrictions-panel")).to_be_visible()
        expect(page.locator("#users-panel")).to_be_visible()
        assert ctx.cookies()[0]["httpOnly"] is True
        assert ctx.cookies()[0]["sameSite"] == "Strict"
        assert page.request.get(base + "/api/users?tenant=other").status == 200

        with serve(protected_handler(store.db, token=TOKEN, tenant=tenant, limit=50)) as api:
            assert quote(api)[0] == 200
            page.locator("#subject").fill("demo-api-client")
            page.locator("#minutes").fill("10")
            page.locator("#restrict-form button").click()
            row = page.locator("#restrictions-body tr").filter(has_text="demo-api-client")
            expect(row).to_be_visible()
            assert quote(api)[0] == 403
            row.get_by_role("button", name="Revoke").click()
            expect(row).to_have_count(0)
            assert quote(api)[0] == 200

        page.locator("#new-user").fill("bob")
        page.locator("#new-password").fill("Only-for-browser-testing-456!")
        page.locator("#new-role").select_option("operator")
        page.locator("#user-form button").click()
        bob = page.locator("#users-body tr").filter(has_text="bob")
        expect(bob).to_contain_text("Active")
        bob.get_by_role("button", name="Disable").click()
        expect(bob).to_contain_text("Disabled")

        with browser.new_context() as other_ctx:
            invalid = other_ctx.new_page()
            invalid.goto(base)
            invalid.locator("#tenant").fill(tenant)
            invalid.locator("#user").fill("bob")
            invalid.locator("#password").fill("Only-for-browser-testing-456!")
            invalid.locator("#login-form button").click()
            expect(invalid.locator("#notice")).to_contain_text("invalid credentials")
            expect(invalid.locator("#login")).to_be_visible()

        # Successful login event and both restriction changes must be persisted.
        audit = [e["action"] for e in store.audit(tenant)]
        assert "restrict:demo-api-client" in audit
        assert "unrestrict:demo-api-client" in audit
        assert "user-created:bob" in audit
        assert "user-disabled:bob" in audit

        page.locator("#logout").click()
        expect(page.locator("#login")).to_be_visible()
        expect(page.locator("#dash")).to_be_hidden()
        assert page.request.get(base + "/api/me").status == 401


@pytest.mark.parametrize(
    "role,metrics,restrictions,users",
    [
        ("operator", True, True, False),
        ("analyst", True, False, False),
        ("auditor", False, False, False),
    ],
)
def test_real_browser_role_visibility_and_server_authorization(
    browser, site, role, metrics, restrictions, users
):
    store, tenant, base = site
    password = "Only-for-browser-roles-789!"
    assert store.provision_user(tenant=tenant, user="staff", password=password, role=role)
    with browser.new_context() as ctx:
        page = ctx.new_page()
        sign_in(page, base, tenant, user="staff", password=password)
        assert page.locator("#restrictions-panel").is_visible() == restrictions
        assert page.locator("#users-panel").is_visible() == users
        if metrics:
            expect(page.locator("#metrics .card")).to_have_count(3)
        else:
            expect(page.locator("#metrics")).to_contain_text("Metrics unavailable")
        assert page.request.get(base + "/api/users").status == 403
        assert page.request.get(base + "/api/restrictions").status == (
            200 if restrictions else 403
        )
        assert page.request.get(base + "/api/metrics").status == (
            200 if metrics else 403
        )


def test_browser_renders_untrusted_client_labels_as_text_not_html(browser, site):
    store, tenant, base = site
    with browser.new_context() as ctx:
        page = ctx.new_page()
        sign_in(page, base, tenant)
        payload = '<img src=x onerror=alert(1)>'
        page.locator("#subject").fill(payload)
        page.locator("#minutes").fill("5")
        page.locator("#restrict-form button").click()
        row = page.locator("#restrictions-body tr").filter(has_text=payload)
        expect(row).to_be_visible()
        assert row.locator("img").count() == 0
        assert payload in row.inner_text()
        assert page.locator("#restrictions-body img").count() == 0
