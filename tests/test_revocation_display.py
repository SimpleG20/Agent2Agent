"""
Playwright test: verifies revocation display on the A2A dashboard.
1. Starts CA, Key Guards (alfa, beta), Dashboard
2. Opens dashboard in browser
3. Checks alfa credential shows "✅ Credencial Verificada"
4. Revokes alfa's credential via CA
5. Notifies alfa to refresh CRL cache
6. Reloads dashboard and verifies status changes to "🚫 Credencial Revogada"
"""

import os, sys, json, time, subprocess, requests, socket, signal, shutil

from playwright.sync_api import sync_playwright

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_DIR = os.path.join(PROJECT_DIR, "data_test_revocation")
DASH_DIR = os.path.join(PROJECT_DIR, "data_dashboard")
CA_BIN = os.path.join(PROJECT_DIR, "credential-authority", "ca-bin")
KG_BIN = os.path.join(PROJECT_DIR, "key-guard", "key-guard-bin")

# Custom ports to avoid conflicts
CA_PORT = 19001
KG_ALFA_PORT = 18001
KG_BETA_PORT = 18002
DASH_PORT = 9000
CA_URL = f"http://localhost:{CA_PORT}"
DASH_URL = f"http://localhost:{DASH_PORT}"
AGENTS_MAP = {"alfa": KG_ALFA_PORT, "beta": KG_BETA_PORT}


def cleanup():
    subprocess.run(["pkill", "-f", "key-guard-bin"], capture_output=True)
    subprocess.run(["pkill", "-f", "ca-bin"], capture_output=True)
    subprocess.run(["pkill", "-f", "server.py"], capture_output=True)
    for d in [TEST_DIR, DASH_DIR]:
        if os.path.exists(d): shutil.rmtree(d, ignore_errors=True)
    time.sleep(0.5)


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) == 0: return True
        time.sleep(0.3)
    return False


def main():
    cleanup()
    os.makedirs(os.path.join(TEST_DIR, "ca"), exist_ok=True)
    procs = []

    # 1. Start CA
    ca_proc = subprocess.Popen(
        [CA_BIN, "-port", str(CA_PORT), "-datadir", os.path.join(TEST_DIR, "ca")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    procs.append(ca_proc)
    assert wait_port(CA_PORT), "CA failed"
    print("✅ CA")

    # 2. Start Key Guards
    for name, port in [("alfa", KG_ALFA_PORT), ("beta", KG_BETA_PORT)]:
        p = subprocess.Popen([
            KG_BIN, "-port", str(port), "-name", name,
            "-endpoint", f"http://localhost:{port}",
            "-datadir", TEST_DIR, "-ca-url", CA_URL, "-ca-enabled",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
    assert wait_port(KG_ALFA_PORT) and wait_port(KG_BETA_PORT), "KGs failed"
    print("✅ Key Guards")
    time.sleep(1)

    # 3. Verify credentials
    for name, port in [("alfa", KG_ALFA_PORT), ("beta", KG_BETA_PORT)]:
        r = requests.get(f"http://localhost:{port}/credential", timeout=3)
        data = r.json()
        assert data.get("valid") != False, f"{name} invalid: {data}"
        print(f"  ✓ {name}: {data.get('credential', {}).get('id', 'N/A')}")

    # 4. Write agents.json for dashboard
    os.makedirs(DASH_DIR, exist_ok=True)
    with open(os.path.join(DASH_DIR, "agents.json"), "w") as f:
        json.dump(AGENTS_MAP, f)

    # 5. Start Dashboard with CA_URL override
    env = os.environ.copy()
    env["CA_URL"] = CA_URL
    dash_log = open(os.path.join(TEST_DIR, "dashboard.log"), "w")
    dash_proc = subprocess.Popen(
        [sys.executable, os.path.join(PROJECT_DIR, "dashboard", "server.py")],
        stdout=dash_log, stderr=subprocess.STDOUT, env=env,
    )
    procs.append(dash_proc)
    assert wait_port(DASH_PORT, timeout=15), "Dashboard failed"
    time.sleep(3)  # Let Flask debug mode finish restarting
    print("✅ Dashboard")

    # 6. Playwright test
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(15000)

            print("\n🔍 Opening dashboard...")
            page.goto(DASH_URL, wait_until="load", timeout=20000)
            print("  Page loaded, waiting for JS rendering...")

            # Wait for alfa credential status
            page.wait_for_function(
                """() => {
                    const el = document.getElementById('alfa-vc-status');
                    return el && el.innerText.includes('Credencial');
                }""",
                timeout=20000
            )
            alfa_status = page.inner_text("#alfa-vc-status")
            print(f"  alfa status: {alfa_status}")
            assert "Credencial Verificada" in alfa_status, \
                f"Expected verified, got: {alfa_status}"
            print("  ✅ Credencial VERIFICADA before revocation")

            # 7. Revoke alfa's credential
            r = requests.get(f"http://localhost:{KG_ALFA_PORT}/credential", timeout=3)
            cred_id = r.json().get("credential", {}).get("id", "")
            assert cred_id, f"No credential ID"

            print(f"  Revoking: {cred_id}")
            r = requests.post(f"{CA_URL}/credential/revoke",
                              json={"credentialId": cred_id}, timeout=5)
            assert r.status_code == 200, f"Revoke failed: {r.text}"

            # Notify alfa
            r = requests.post(f"http://localhost:{KG_ALFA_PORT}/credential/refresh-status",
                              timeout=5)
            refresh_data = r.json()
            print(f"  alfa refresh: valid={refresh_data.get('valid')}")
            assert refresh_data.get("valid") == False

            # 8. Reload and verify revocation display
            print("⏳ Reloading dashboard...")
            page.goto(DASH_URL, wait_until="load", timeout=20000)
            time.sleep(1)

            page.wait_for_function(
                """() => {
                    const el = document.getElementById('alfa-vc-status');
                    return el && el.innerText.includes('Revogada');
                }""",
                timeout=15000
            )
            alfa_after = page.inner_text("#alfa-vc-status")
            print(f"  alfa after: {alfa_after}")
            assert "Revogada" in alfa_after, \
                f"Expected revoked, got: {alfa_after}"
            print("  ✅ Credencial REVOGADA!")

            # Beta still verified
            beta_status = page.inner_text("#beta-vc-status")
            print(f"  beta: {beta_status}")
            assert "Verificada" in beta_status
            print("  ✅ Beta still VERIFICADA")

            print("\n🎉 ALL TESTS PASSED!")
            browser.close()

    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)

    cleanup()
    print("🧹 Cleanup.")


if __name__ == "__main__":
    main()
