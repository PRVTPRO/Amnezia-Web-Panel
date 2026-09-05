"""Playwright E2E tests for Amnezia Web Panel."""
import pytest
from playwright.sync_api import Page, expect

BASE_URL = "http://127.0.0.1:8000"


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


class TestLoginPage:
    def test_login_page_loads(self, page: Page):
        page.goto(BASE_URL)
        expect(page).to_have_url(f"{BASE_URL}/login")
        expect(page).to_have_title("Amnezia — Login")

    def test_login_page_has_username_field(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('#username')).to_be_visible()

    def test_login_page_has_password_field(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('#password')).to_be_visible()

    def test_login_page_has_login_button(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('button[type="submit"]')).to_be_visible()

    def test_login_page_has_logo(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('.login-logo')).to_be_visible()

    def test_login_page_has_theme_toggle(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('#themeToggle')).to_be_visible()

    def test_login_page_has_language_toggle(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('#langToggle')).to_be_visible()

    def test_login_form_structure(self, page: Page):
        page.goto(BASE_URL)
        expect(page.locator('#loginForm')).to_be_visible()
        expect(page.locator('.login-card')).to_be_visible()


class TestDashboard:
    def test_dashboard_requires_auth(self, page: Page):
        page.goto(f"{BASE_URL}/")
        expect(page).to_have_url(f"{BASE_URL}/login")

class TestAPI:
    def test_openapi_json_available(self, page: Page):
        response = page.request.get(f"{BASE_URL}/openapi.json")
        assert response.status == 200
        body = response.json()
        assert "paths" in body
        assert "info" in body

    def test_static_files_served(self, page: Page):
        response = page.request.get(f"{BASE_URL}/static/js/searchable-select.js")
        assert response.status == 200

    def test_favicon_served(self, page: Page):
        response = page.request.get(f"{BASE_URL}/static/favicon.svg")
        assert response.status == 200

    def test_manifest_served(self, page: Page):
        response = page.request.get(f"{BASE_URL}/manifest.webmanifest")
        assert response.status == 200


if __name__ == '__main__':
    pytest.main([__file__, "-v", "--headed", "--browser", "chromium"])
