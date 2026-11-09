"""Capture the IPv6 modal in both themes with Playwright (headless)."""
import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
OUT = os.path.dirname(os.path.abspath(__file__))

FAKE = """
renderIpSettings({
  preference: {new_instances: true, env_override: 'auto'}, can_write: true,
  host: {ipv4: '203.0.113.7', ipv6: '2a0a:9300:1:5::1', ipv6_state: 'in_use',
         ipv6_default_route: true, ipv6_disabled_by_sysctl: false},
  docker: {installed: true, ipv6_enabled: false, restart_required: true, flags_conflict: false},
  instances: [
    {proto:'awg3', subnet_v4:'10.8.1.1', peers:36, peers_v6:0, ipv6_enabled:false,
     subnet_v6:null, blocked_reason:'peers', can_enable:false, can_disable:true,
     exit_linked:true, container_running:true},
    {proto:'awg2', subnet_v4:'10.8.2.1', peers:0, peers_v6:0, ipv6_enabled:false,
     subnet_v6:null, blocked_reason:'needs_recreate', can_enable:true, can_disable:false,
     exit_linked:false, container_running:true},
    {proto:'awg', subnet_v4:'10.8.3.1', peers:4, peers_v6:4, ipv6_enabled:true,
     subnet_v6:'fd42:8:3::1', blocked_reason:'none', can_enable:false, can_disable:true,
     exit_linked:false, container_running:true}
  ]
});
renderIpChips({
  host: {ipv4: '203.0.113.7', ipv6: '2a0a:9300:1:5::1', ipv6_state: 'in_use'},
  docker: {installed: true, ipv6_enabled: false, restart_required: true, flags_conflict: false}
});
"""


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in ("dark", "light"):
            ctx = browser.new_context(viewport={"width": 1280, "height": 1000})
            ctx.add_init_script(f"localStorage.setItem('theme','{theme}')")
            page = ctx.new_page()
            page.goto(BASE + "/login")
            page.fill("#username", "admin")
            page.fill("#password", "admin")
            page.click("button[type=submit]")
            page.wait_for_url(BASE + "/")
            page.goto(BASE + "/server/0")
            page.wait_for_selector("#ipSettingsBtn")
            page.evaluate("openIpSettings()")
            page.evaluate(FAKE)
            page.wait_for_timeout(400)
            page.locator("#ipSettingsModal .modal").screenshot(
                path=os.path.join(OUT, f"ipv6-modal-{theme}.png"))
            ctx.close()

        # Mobile: the table drops the subnet column, the segments stretch.
        ctx = browser.new_context(viewport={"width": 390, "height": 844})
        page = ctx.new_page()
        page.goto(BASE + "/login")
        page.fill("#username", "admin")
        page.fill("#password", "admin")
        page.click("button[type=submit]")
        page.wait_for_url(BASE + "/")
        page.goto(BASE + "/server/0")
        page.wait_for_selector("#ipSettingsBtn")
        page.evaluate("openIpSettings()")
        page.evaluate(FAKE)
        page.wait_for_timeout(400)
        page.locator("#ipSettingsModal .modal").screenshot(
            path=os.path.join(OUT, "ipv6-modal-mobile.png"))
        ctx.close()
        browser.close()
    print(json.dumps({"written": [f"design/ipv6-modal-{t}.png" for t in ("dark", "light", "mobile")]}))


if __name__ == "__main__":
    main()