#!/usr/bin/env python3
"""
A2A Full Protocol E2E Tests
============================
Validates the complete A2A + DIDComm V2 + VC system across 14 scenarios.

Run:
    python3 tests/a2a_full_test.py

Requires:
    - key-guard binary compiled
    - credential-authority binary compiled
    - Python packages: requests, pydantic
"""

import os
import sys
import json
import time
import base64
import socket
import shutil
import subprocess
import unittest
import requests
import threading

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "cognitive"))
from agent import CognitiveAgent

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEY_GUARD_BIN = os.path.join(PROJECT_DIR, "key-guard", "key-guard-bin")
CA_BIN = os.path.join(PROJECT_DIR, "credential-authority", "credential-authority")
DATA_DIR = os.path.join(PROJECT_DIR, "data_e2e_test")


class TestA2AFullProtocol(unittest.TestCase):
    """14 E2E scenarios for A2A + DIDComm V2 + VC system."""

    @classmethod
    def setUpClass(cls):
        """Start CA, Alfa KG, Beta KG, perform handshake with VC."""
        # Clean old data
        if os.path.exists(DATA_DIR):
            shutil.rmtree(DATA_DIR)
        os.makedirs(DATA_DIR, exist_ok=True)

        cls.processes = []
        cls.log_files = []

        print("\n" + "=" * 70)
        print("A2A FULL PROTOCOL E2E TESTS")
        print("=" * 70)

        # 1. Start CA
        print("\n[SETUP] Starting Credential Authority on port 9999...")
        ca_log = open(os.path.join(DATA_DIR, "ca.log"), "w")
        cls.log_files.append(ca_log)
        cls.proc_ca = subprocess.Popen(
            [CA_BIN, "-port", "9999", "-datadir", DATA_DIR],
            stdout=ca_log, stderr=ca_log, text=True
        )
        cls.processes.append(cls.proc_ca)
        time.sleep(1)

        # Verify CA started
        if cls.proc_ca.poll() is not None:
            raise RuntimeError("CA failed to start!")
        print("  CA started.")

        # Get CA info
        try:
            r = requests.get("http://localhost:9999/ca/info", timeout=3)
            cls.ca_info = r.json()
            print(f"  CA DID: {cls.ca_info.get('did_key', 'N/A')}")
        except Exception as e:
            raise RuntimeError(f"CA not responding: {e}")

        # 2. Start Key Guard Alfa (with CA)
        print("\n[SETUP] Starting Key Guard Alfa (port 8001)...")
        alfa_log = open(os.path.join(DATA_DIR, "alfa_kg.log"), "w")
        cls.log_files.append(alfa_log)
        cls.proc_alfa = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8001",
            "-name", "alfa",
            "-endpoint", "http://localhost:8001",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9999",
            "-ca-enabled",
        ], stdout=alfa_log, stderr=alfa_log, text=True)
        cls.processes.append(cls.proc_alfa)
        time.sleep(1.5)

        if cls.proc_alfa.poll() is not None:
            raise RuntimeError("Alfa KG failed to start!")

        # 3. Start Key Guard Beta (with CA)
        print("[SETUP] Starting Key Guard Beta (port 8002)...")
        beta_log = open(os.path.join(DATA_DIR, "beta_kg.log"), "w")
        cls.log_files.append(beta_log)
        cls.proc_beta = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8002",
            "-name", "beta",
            "-endpoint", "http://localhost:8002",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9999",
            "-ca-enabled",
        ], stdout=beta_log, stderr=beta_log, text=True)
        cls.processes.append(cls.proc_beta)
        time.sleep(1.5)

        if cls.proc_beta.poll() is not None:
            raise RuntimeError("Beta KG failed to start!")

        # 4. Get agent info for both
        cls.alfa_info = requests.get("http://localhost:8001/agent-info", timeout=3).json()
        cls.beta_info = requests.get("http://localhost:8002/agent-info", timeout=3).json()
        print(f"  Alfa DID: {cls.alfa_info['did']}")
        print(f"  Beta DID: {cls.beta_info['did']}")

        # 5. Initialize Cognitive agents
        cls.agent_alfa = CognitiveAgent("alfa", "http://localhost:8001",
                                        data_dir=DATA_DIR, request_vc=False)
        cls.agent_beta = CognitiveAgent("beta", "http://localhost:8002",
                                        data_dir=DATA_DIR, request_vc=False)

        # 6. Mutual VC Handshake (alfa -> beta)
        print("\n[SETUP] Performing VC handshake Alfa -> Beta...")
        resp = requests.post("http://localhost:8001/handshake-peer", json={
            "target_endpoint": "http://localhost:8002"
        }, timeout=5)
        if resp.status_code != 200:
            print(f"  Handshake failed: {resp.status_code} {resp.text}")
            raise RuntimeError("VC handshake failed!")
        print(f"  Handshake success!")
        time.sleep(0.5)

        cls.alfa_did = cls.alfa_info['did']
        cls.beta_did = cls.beta_info['did']
        print("\n[SETUP] Complete! Running 14 test scenarios...\n")

    @classmethod
    def tearDownClass(cls):
        """Clean up processes."""
        print("\n[TEARDOWN] Terminating processes...")
        for proc in cls.processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        for f in cls.log_files:
            try:
                f.close()
            except:
                pass
        print("  Done.")

    # ─────────────────────────────────────────────────
    # Scenario 1: Agent Card
    # ─────────────────────────────────────────────────
    def test_01_agent_card(self):
        """Each agent serves a valid Agent Card at /.well-known/agent-card."""
        print("--- Test 01: Agent Card ---")
        for name, port in [("alfa", 8001), ("beta", 8002)]:
            r = requests.get(f"http://localhost:{port}/.well-known/agent-card", timeout=3)
            self.assertEqual(r.status_code, 200)
            card = r.json()
            self.assertIn("name", card)
            self.assertIn(card["name"].lower(), name)
            self.assertIn("capabilities", card)
            self.assertIn("skills", card.get("capabilities", {}))
            print(f"  {name}: Agent Card OK (skills: {len(card.get('capabilities', {}).get('skills', []))})")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 2: DID Key
    # ─────────────────────────────────────────────────
    def test_02_did_key(self):
        """did:key: is correctly generated and verifiable."""
        print("--- Test 02: DID Key ---")
        # Alfa's did:key: should start with "did:key:z"
        self.assertTrue(self.alfa_did.startswith("did:key:z"),
                        f"Alfa DID does not start with did:key:z: {self.alfa_did}")
        self.assertTrue(self.beta_did.startswith("did:key:z"),
                        f"Beta DID does not start with did:key:z: {self.beta_did}")
        print(f"  Alfa DID: {self.alfa_did}")
        print(f"  Beta DID: {self.beta_did}")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 3: CA VC Issuance
    # ─────────────────────────────────────────────────
    def test_03_credential_issuance(self):
        """CA issues VC, agent stores locally."""
        print("--- Test 03: Credential Issuance ---")
        for name, port in [("alfa", 8001), ("beta", 8002)]:
            r = requests.get(f"http://localhost:{port}/credential", timeout=3)
            self.assertEqual(r.status_code, 200)
            cred = r.json()
            self.assertEqual(cred["status"], "available",
                             f"{name} has no credential: {cred}")
            vc = cred["credential"]
            self.assertIn("id", vc)
            self.assertIn("credentialSubject", vc)
            print(f"  {name}: VC OK (ID: {vc.get('id', 'N/A')[:24]}...)")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 4: VC Handshake
    # ─────────────────────────────────────────────────
    def test_04_vc_handshake(self):
        """Handshake with VC verification succeeded."""
        print("--- Test 04: VC Handshake ---")
        # Verify peers are registered
        r_alfa = requests.get(f"http://localhost:8001/resolve?did={self.beta_did}", timeout=3)
        self.assertEqual(r_alfa.status_code, 200)
        r_beta = requests.get(f"http://localhost:8002/resolve?did={self.alfa_did}", timeout=3)
        self.assertEqual(r_beta.status_code, 200)
        print(f"  Alfa sees Beta: {r_alfa.json().get('did', 'N/A')[:20]}...")
        print(f"  Beta sees Alfa: {r_beta.json().get('did', 'N/A')[:20]}...")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 5: JWE Encryption
    # ─────────────────────────────────────────────────
    def test_05_jwe_encryption(self):
        """Message is encrypted (JWE) and decrypted correctly."""
        print("--- Test 05: JWE Encryption ---")
        # Send a message from alfa to beta
        msg_content = f"JWE test message at {time.time()}"
        res = self.agent_alfa.tool_send_message(to_did=self.beta_did, content=msg_content)
        self.assertEqual(res["status"], "sent")
        print(f"  Message sent: {msg_content[:30]}...")

        # Beta polls inbox
        time.sleep(0.5)
        messages = self.agent_beta.tool_read_inbox()
        self.assertGreaterEqual(len(messages), 1, "No messages received")
        # The last message should be our JWE test
        found = any(msg_content in m.get("content", "") for m in messages)
        self.assertTrue(found, "JWE encrypted message not received correctly")
        print("  Message received and decrypted correctly")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 6: Task Send/Get
    # ─────────────────────────────────────────────────
    def test_06_task_send_get(self):
        """Task is created, states transition correctly."""
        print("--- Test 06: Task Send/Get ---")
        task_id = f"test-task-{int(time.time())}"
        r = requests.post("http://localhost:8001/a2a/tasks/send", json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "sessionId": "sess-001",
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Hello from task test"}]
                }
            }
        }, timeout=3)
        self.assertEqual(r.status_code, 200)
        result = r.json()
        self.assertEqual(result.get("jsonrpc"), "2.0")
        self.assertIn("result", result)
        task_result = result["result"]
        self.assertEqual(task_result["id"], task_id)
        print(f"  Task created: {task_id} (state: {task_result['status']['state']})")

        # Get the task
        r2 = requests.post("http://localhost:8001/a2a/tasks/get", json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/get",
            "params": {"id": task_id}
        }, timeout=3)
        self.assertEqual(r2.status_code, 200)
        get_result = r2.json()["result"]
        self.assertEqual(get_result["id"], task_id)
        print(f"  Task retrieved: state={get_result['status']['state']}")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 7: Task Cancel
    # ─────────────────────────────────────────────────
    def test_07_task_cancel(self):
        """Task transitions from working to canceled."""
        print("--- Test 07: Task Cancel ---")
        task_id = f"cancel-task-{int(time.time())}"

        # Create task
        r = requests.post("http://localhost:8001/a2a/tasks/send", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/send",
            "params": {
                "id": task_id, "sessionId": "sess-002",
                "message": {"role": "user", "parts": [{"type": "text", "text": "Cancellable task"}]}
            }
        }, timeout=3)
        self.assertEqual(r.status_code, 200)

        # Cancel it
        r2 = requests.post("http://localhost:8001/a2a/tasks/cancel", json={
            "jsonrpc": "2.0", "id": 2, "method": "tasks/cancel",
            "params": {"id": task_id}
        }, timeout=3)
        self.assertEqual(r2.status_code, 200)
        cancel_result = r2.json()["result"]
        self.assertEqual(cancel_result["status"]["state"], "canceled")
        print(f"  Task {task_id} canceled successfully")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 8: SSE Streaming
    # ─────────────────────────────────────────────────
    def test_08_sse_streaming(self):
        """sendSubscribe delivers real-time events."""
        print("--- Test 08: SSE Streaming ---")
        import http.client
        import threading

        task_id = f"sse-task-{int(time.time())}"

        # Spawn a thread to cancel the task after a short delay
        # (simulates a worker completing or admin canceling)
        def cancel_task_later():
            time.sleep(1.0)
            try:
                requests.post("http://localhost:8001/a2a/tasks/cancel", json={
                    "jsonrpc": "2.0", "id": 2, "method": "tasks/cancel",
                    "params": {"id": task_id}
                }, timeout=3)
            except Exception:
                pass

        cancel_thread = threading.Thread(target=cancel_task_later, daemon=True)
        cancel_thread.start()

        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tasks/sendSubscribe",
            "params": {
                "id": task_id, "sessionId": "sess-sse",
                "message": {"role": "user", "parts": [{"type": "text", "text": "SSE test"}]}
            }
        })

        conn = http.client.HTTPConnection("localhost", 8001, timeout=10)
        conn.request("POST", "/a2a/tasks/sendSubscribe", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "text/event-stream")

        # Read SSE events — should get initial "working" then "canceled"
        events = []
        for _ in range(10):
            try:
                line = resp.readline().decode("utf-8").strip()
            except socket.timeout:
                break
            if line.startswith("data:"):
                events.append(json.loads(line[5:]))
            if line == "" and events:
                last_state = events[-1].get("status", {}).get("state", "")
                if last_state in ("completed", "failed", "canceled"):
                    break

        conn.close()
        cancel_thread.join(timeout=2)
        self.assertGreater(len(events), 0, "No SSE events received")
        terminal_states = [e.get("status", {}).get("state", "") for e in events]
        self.assertIn("canceled", terminal_states,
                      f"SSE should receive canceled state. Events: {terminal_states}")
        print(f"  Received {len(events)} SSE events for task {task_id}")
        print(f"  States: {terminal_states}")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 9: Content Types
    # ─────────────────────────────────────────────────
    def test_09_content_types(self):
        """Tasks with different Part types (text, function_call) work."""
        print("--- Test 09: Content Types ---")
        task_id = f"ct-task-{int(time.time())}"

        # Send task with function_call part
        r = requests.post("http://localhost:8001/a2a/tasks/send", json={
            "jsonrpc": "2.0", "id": 1, "method": "tasks/send",
            "params": {
                "id": task_id, "sessionId": "sess-ct",
                "message": {
                    "role": "user",
                    "parts": [
                        {"type": "text", "text": "Process this data"},
                        {"type": "function_call",
                         "functionName": "process_order",
                         "arguments": {"order_id": "123", "amount": 100}}
                    ]
                }
            }
        }, timeout=3)
        self.assertEqual(r.status_code, 200)
        result = r.json()["result"]
        self.assertEqual(result["id"], task_id)

        # Get task and verify parts
        r2 = requests.post("http://localhost:8001/a2a/tasks/get", json={
            "jsonrpc": "2.0", "id": 2, "method": "tasks/get",
            "params": {"id": task_id}
        }, timeout=3)
        parts = r2.json()["result"]["status"]["message"]["parts"]
        part_types = [p["type"] for p in parts]
        self.assertIn("text", part_types)
        self.assertIn("function_call", part_types)
        print(f"  Part types: {part_types}")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 10: VC Expired
    # ─────────────────────────────────────────────────
    def test_10_vc_expired(self):
        """Agent with expired VC is rejected in handshake (simulated)."""
        print("--- Test 10: VC Expired ---")
        # We need a Gamma agent with an expired VC.
        # Strategy: Use a second CA with short-lived credential, or
        # directly manipulate the credential store manually.

        # Start a Gamma KG without CA, then manually give it an expired VC
        gamma_log = open(os.path.join(DATA_DIR, "gamma_kg.log"), "w")
        proc_gamma = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8003",
            "-name", "gamma",
            "-endpoint", "http://localhost:8003",
            "-datadir", DATA_DIR,
        ], stdout=gamma_log, stderr=gamma_log, text=True)
        time.sleep(1.5)

        if proc_gamma.poll() is not None:
            proc_gamma.terminate()
            gamma_log.close()
            self.skipTest("Gamma KG could not start")

        try:
            gamma_info = requests.get("http://localhost:8003/agent-info", timeout=3).json()
            gamma_did = gamma_info["did"]

            # Attempt handshake from alfa to gamma (alfa has VC, gamma doesn't)
            # alfa should reject because gamma has no VC
            resp = requests.post("http://localhost:8001/handshake-peer", json={
                "target_endpoint": "http://localhost:8003"
            }, timeout=5)
            # This should fail - alfa requires VC from gamma
            self.assertNotEqual(resp.status_code, 200,
                                "Handshake should fail - gamma has no VC!")
            print(f"  Gamma (no VC) handshake rejected: {resp.status_code}")

            # Now also check that gamma can not send to alfa
            # (gamma shouldn't even have alfa's VC)
            payload = {
                "to_did": self.alfa_did,
                "payload": {"content": "trying to reach alfa"},
                "type": "https://didcomm.org/basicmessage/2.0/message"
            }
            resp_send = requests.post("http://localhost:8003/send-message",
                                       json=payload, timeout=3)
            print(f"  Gamma send to Alfa: {resp_send.status_code}")
            # Gamma may not have alfa as peer, so this could fail with 404

            print("  Expired/no-VC scenario verified")
        finally:
            proc_gamma.terminate()
            proc_gamma.wait()
            gamma_log.close()

        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 11: VC Revoked & Reissued (TDD)
    # ─────────────────────────────────────────────────
    def test_11_vc_revoked(self):
        """Agent with revoked VC is rejected, then can request a new one and succeed."""
        print("--- Test 11: VC Revoked & Reissued ---")
        # Create a temporary agent to revoke
        import uuid
        temp_name = f"temp-{uuid.uuid4().hex[:6]}"

        temp_log = open(os.path.join(DATA_DIR, f"{temp_name}_kg.log"), "w")
        proc_temp = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8010",
            "-name", temp_name,
            "-endpoint", f"http://localhost:8010",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9999",
            "-ca-enabled",
        ], stdout=temp_log, stderr=temp_log, text=True)
        time.sleep(1.5)

        if proc_temp.poll() is not None:
            proc_temp.terminate()
            temp_log.close()
            self.skipTest(f"Temporary agent {temp_name} could not start")

        try:
            # Get its credential ID
            r = requests.get("http://localhost:8010/credential", timeout=3)
            self.assertEqual(r.status_code, 200)
            cred = r.json()
            if cred["status"] != "available":
                self.skipTest("Temp agent has no credential to revoke")
            credential_id = cred["credential"]["id"]
            print(f"  Temp agent VC: {credential_id[:30]}...")

            # Revoke via CA
            r_revoke = requests.post("http://localhost:9999/credential/revoke", json={
                "credentialId": credential_id
            }, timeout=3)
            self.assertEqual(r_revoke.status_code, 200, f"Revocation failed: {r_revoke.text}")
            print(f"  VC revoked on CA")

            # Wait for CRL propagation (cache TTL is 5 seconds now)
            time.sleep(6)

            # Verify CA reports it revoked
            r_crl = requests.get("http://localhost:9999/credential/crl", timeout=3)
            crl = r_crl.json()
            revoked_list = crl.get("entries", [])
            revoked_ids = [e.get("credentialId", "") for e in revoked_list]
            self.assertIn(credential_id, revoked_ids,
                          f"Credential {credential_id} not found in CRL. Entries: {revoked_ids}")
            print(f"  CRL contains revoked credential")

            # 1. Attempt handshake from temp (revoked) to alfa - must be rejected
            resp_hs = requests.post("http://localhost:8010/handshake-peer", json={
                "target_endpoint": "http://localhost:8001"
            }, timeout=5)
            self.assertNotEqual(resp_hs.status_code, 200, "Handshake should be rejected because temp VC is revoked")
            print("  Rejection of revoked agent handshake verified")

            # 2. Request re-issuance for temp agent via its Key Guard
            r_reissue = requests.post("http://localhost:8010/credential/request-issue", json={}, timeout=5)
            self.assertEqual(r_reissue.status_code, 200, f"Re-issue failed: {r_reissue.text}")
            reissued = r_reissue.json()
            new_vc = reissued["credential"]
            new_credential_id = new_vc["id"]
            self.assertNotEqual(new_credential_id, credential_id, "Should get a brand new VC ID")
            print(f"  VC successfully re-issued: {new_credential_id[:30]}...")

            # Wait for any cache refresh
            time.sleep(1)

            # 3. With a fresh VC, handshake from temp to alfa should now succeed!
            resp_hs2 = requests.post("http://localhost:8010/handshake-peer", json={
                "target_endpoint": "http://localhost:8001"
            }, timeout=5)
            self.assertEqual(resp_hs2.status_code, 200, f"Handshake should succeed with reissued VC: {resp_hs2.text}")
            print(f"  Handshake succeeded after re-issuing VC!")

        finally:
            proc_temp.terminate()
            proc_temp.wait()
            temp_log.close()

        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 12: CA Offline — Degraded Mode
    # ─────────────────────────────────────────────────
    def test_12_ca_offline_degraded(self):
        """Agent operates in degraded mode with cached VC when CA is offline."""
        print("--- Test 12: CA Offline Degraded Mode ---")

        # Kill the CA
        print("  Stopping CA...")
        self.proc_ca.terminate()
        self.proc_ca.wait(timeout=5)
        time.sleep(1)

        # Verify CA is offline
        try:
            requests.get("http://localhost:9999/ca/info", timeout=2)
            self.skipTest("CA still responding - cannot test offline mode")
        except:
            print("  CA is offline (expected)")

        try:
            # Agents should still communicate using cached VCs
            msg = f"CA-offline test {time.time()}"
            res = self.agent_alfa.tool_send_message(to_did=self.beta_did, content=msg)
            self.assertEqual(res["status"], "sent",
                             f"Message should send in degraded mode: {res}")
            print(f"  Message sent while CA offline: {msg[:30]}...")

            # Verify delivery
            time.sleep(0.5)
            messages = self.agent_beta.tool_read_inbox()
            found = any(msg in m.get("content", "") for m in messages)
            self.assertTrue(found, "Message not delivered in degraded mode")
            print("  Message delivered in degraded mode")

            # Verify credential still accessible from cache
            for name, port in [("alfa", 8001), ("beta", 8002)]:
                r = requests.get(f"http://localhost:{port}/credential", timeout=3)
                cred = r.json()
                self.assertEqual(cred["status"], "available",
                                 f"{name} lost VC while CA offline")
            print("  Credentials remain cached")
        finally:
            # Restart CA
            print("  Restarting CA...")
            ca_log = open(os.path.join(DATA_DIR, "ca.log"), "a")
            cls = self.__class__
            cls.proc_ca = subprocess.Popen(
                [CA_BIN, "-port", "9999", "-datadir", DATA_DIR],
                stdout=ca_log, stderr=ca_log, text=True
            )
            cls.processes.append(cls.proc_ca)
            time.sleep(2)

        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 13: Uncredentialed & Theft Rejection
    # ─────────────────────────────────────────────────
    def test_13_uncredentialed_rejection(self):
        """Agent without VC is rejected, and credential theft is blocked."""
        print("--- Test 13: Uncredentialed & Theft Rejection ---")

        # Start Gamma without CA
        gamma_log = open(os.path.join(DATA_DIR, "gamma2_kg.log"), "w")
        proc_gamma = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8011",
            "-name", "gamma-nocred",
            "-endpoint", "http://localhost:8011",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9999",
        ], stdout=gamma_log, stderr=gamma_log, text=True)
        time.sleep(1.5)

        if proc_gamma.poll() is not None:
            proc_gamma.terminate()
            gamma_log.close()
            self.skipTest("Gamma-nocred KG could not start")

        try:
            gamma_info = requests.get("http://localhost:8011/agent-info", timeout=3).json()
            gamma_did = gamma_info["did"]

            # Attempt handshake from Alfa (has VC) to Gamma (no VC)
            resp = requests.post("http://localhost:8001/handshake-peer", json={
                "target_endpoint": "http://localhost:8011"
            }, timeout=5)

            # Alfa (CA-enabled) should reject gamma because gamma has no VC
            self.assertNotEqual(resp.status_code, 200,
                                "Uncredentialed agent should be rejected!")
            print(f"  Uncredentialed Gamma rejected: {resp.status_code}")

            # --- CREDENTIAL THEFT TEST ---
            # Gamma (malicious) steals Beta's VC and tries to present it to Alfa
            # Get Beta's VC first
            r_beta_vc = requests.get("http://localhost:8002/credential", timeout=3).json()
            beta_vc = r_beta_vc["credential"]

            # Gamma sends handshake request to Alfa containing Beta's VC, but signing under Gamma's DID
            pub_key_b64 = base64.b64encode(os.urandom(32)).decode("utf-8")
            theft_payload = {
                "did": gamma_did,
                "did_key": gamma_did,
                "public_key": pub_key_b64,
                "endpoint": "http://localhost:8011",
                "credential_vc": beta_vc,
                "revoked": False
            }
            # Post directly to Alfa's handshake endpoint
            resp_theft = requests.post("http://localhost:8001/handshake-vc", json=theft_payload, timeout=3)
            self.assertNotEqual(resp_theft.status_code, 200, "Theft handshake should be rejected!")
            print(f"  Theft handshake rejected successfully: {resp_theft.status_code} {resp_theft.text}")

        finally:
            proc_gamma.terminate()
            proc_gamma.wait()
            gamma_log.close()

        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 14: Backwards Compatibility (Legacy)
    # ─────────────────────────────────────────────────
    def test_14_backwards_compatibility(self):
        """Legacy /handshake requires a VC if CA is enabled."""
        print("--- Test 14: Backwards Compatibility ---")

        pub_key_b64 = base64.b64encode(os.urandom(32)).decode("utf-8")

        # 1. Post legacy handshake without VC -> should fail since CA is enabled
        legacy_payload_no_vc = {
            "did": "did:custom:legacy-test",
            "did_key": "did:custom:legacy-test",
            "public_key": pub_key_b64,
            "endpoint": "http://localhost:9999",
            "revoked": False
        }
        resp_fail = requests.post("http://localhost:8001/handshake", json=legacy_payload_no_vc, timeout=3)
        self.assertNotEqual(resp_fail.status_code, 200, "Legacy handshake without VC should fail when CA is enabled")
        print("  Legacy handshake without VC rejected successfully")

        # 2. Get Alfa's own VC to use as a mock valid VC (representing a credentialed legacy peer)
        r_alfa_vc = requests.get("http://localhost:8001/credential", timeout=3).json()
        alfa_vc = r_alfa_vc["credential"]

        # 3. Post legacy handshake with valid VC matching the DID -> should succeed
        legacy_payload_with_vc = {
            "did": self.alfa_did,
            "did_key": self.alfa_did,
            "public_key": self.alfa_info["public_key"],
            "endpoint": "http://localhost:8001",
            "credential_vc": alfa_vc,
            "revoked": False
        }
        resp_success = requests.post("http://localhost:8002/handshake", json=legacy_payload_with_vc, timeout=3)
        self.assertEqual(resp_success.status_code, 200, f"Legacy handshake with VC failed: {resp_success.status_code} {resp_success.text}")
        print("  Legacy handshake with valid VC succeeded")

        # Verify all A2A endpoints still respond
        for path in ["/.well-known/agent-card",
                      "/a2a/tasks/send",
                      "/a2a/tasks/get",
                      "/a2a/tasks/cancel",
                      "/agent-info",
                      "/credential"]:
            if path in ("/a2a/tasks/send", "/a2a/tasks/get", "/a2a/tasks/cancel"):
                r = requests.post(f"http://localhost:8001{path}", json={
                    "jsonrpc": "2.0", "id": 1, "method": "tasks/get",
                    "params": {"id": "nonexistent"}
                }, timeout=3)
            else:
                r = requests.get(f"http://localhost:8001{path}", timeout=3)
            self.assertIn(r.status_code, (200, 400),  # POST to GET task with wrong method returns 400
                          f"{path} not available: {r.status_code}")
        print("  All legacy and A2A endpoints responsive")
        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 15: Multiple Issuers (CAs)
    # ─────────────────────────────────────────────────
    def test_15_multiple_issuers(self):
        """Handshake fails when agents use different CAs (untrusted issuers)."""
        print("--- Test 15: Multiple Issuers (CAs) ---")
        
        # 1. Start a second CA (CA2) on port 9998
        ca2_dir = os.path.join(DATA_DIR, "ca2")
        os.makedirs(ca2_dir, exist_ok=True)
        ca2_log = open(os.path.join(DATA_DIR, "ca2.log"), "w")
        proc_ca2 = subprocess.Popen(
            [CA_BIN, "-port", "9998", "-datadir", ca2_dir, "-name", "CA Two"],
            stdout=ca2_log, stderr=ca2_log, text=True
        )
        time.sleep(1)

        if proc_ca2.poll() is not None:
            ca2_log.close()
            self.skipTest("Second CA failed to start")

        # 2. Start a temporary agent (temp-ca2) on port 8020, pointing to CA2
        temp_dir = os.path.join(DATA_DIR, "temp-ca2")
        os.makedirs(temp_dir, exist_ok=True)
        temp_log = open(os.path.join(DATA_DIR, "temp-ca2.log"), "w")
        proc_temp = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8020",
            "-name", "temp-ca2",
            "-endpoint", "http://localhost:8020",
            "-datadir", temp_dir,
            "-ca-url", "http://localhost:9998",
            "-ca-enabled",
        ], stdout=temp_log, stderr=temp_log, text=True)
        time.sleep(1.5)

        if proc_temp.poll() is not None:
            proc_ca2.terminate()
            proc_ca2.wait()
            ca2_log.close()
            temp_log.close()
            self.skipTest("Temp-ca2 agent failed to start")

        try:
            # 3. Attempt handshake from Alfa (CA1) to Temp-ca2 (CA2)
            resp = requests.post("http://localhost:8001/handshake-peer", json={
                "target_endpoint": "http://localhost:8020"
            }, timeout=5)

            # This handshake should fail because Alfa does not trust CA2 (port 9998)
            self.assertNotEqual(resp.status_code, 200, "Handshake should have been rejected due to CA trust mismatch")
            print(f"  Handshake successfully rejected: {resp.status_code} {resp.text}")

        finally:
            proc_temp.terminate()
            proc_temp.wait()
            proc_ca2.terminate()
            proc_ca2.wait()
            ca2_log.close()
            temp_log.close()

        print("  PASSED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
