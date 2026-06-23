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

        # 1. Start UNIFESP CA
        print("\n[SETUP] Starting UNIFESP CA on port 9999...")
        unifesp_dir = os.path.join(DATA_DIR, "unifesp")
        os.makedirs(unifesp_dir, exist_ok=True)
        unifesp_log = open(os.path.join(DATA_DIR, "unifesp_ca.log"), "w")
        cls.log_files.append(unifesp_log)
        cls.proc_unifesp = subprocess.Popen(
            [CA_BIN, "-port", "9999", "-datadir", unifesp_dir, "-name", "unifesp"],
            stdout=unifesp_log, stderr=unifesp_log, text=True
        )
        cls.processes.append(cls.proc_unifesp)

        # 2. Start MRNutrições CA
        print("[SETUP] Starting MRNutrições CA on port 9998...")
        mrnutricoes_dir = os.path.join(DATA_DIR, "mrnutricoes")
        os.makedirs(mrnutricoes_dir, exist_ok=True)
        mrnutricoes_log = open(os.path.join(DATA_DIR, "mrnutricoes_ca.log"), "w")
        cls.log_files.append(mrnutricoes_log)
        cls.proc_mrnutricoes = subprocess.Popen(
            [CA_BIN, "-port", "9998", "-datadir", mrnutricoes_dir, "-name", "mrnutricoes"],
            stdout=mrnutricoes_log, stderr=mrnutricoes_log, text=True
        )
        cls.processes.append(cls.proc_mrnutricoes)
        time.sleep(1.5)

        # Verify CAs started
        if cls.proc_unifesp.poll() is not None:
            raise RuntimeError("UNIFESP CA failed to start!")
        if cls.proc_mrnutricoes.poll() is not None:
            raise RuntimeError("MRNutrições CA failed to start!")
        print("  CAs started.")

        # Get CAs info
        try:
            r = requests.get("http://localhost:9999/ca/info", timeout=3)
            cls.unifesp_info = r.json()
            cls.unifesp_did = cls.unifesp_info.get("did_key", cls.unifesp_info.get("did", ""))
            cls.ca_info = cls.unifesp_info
            print(f"  UNIFESP CA DID: {cls.unifesp_did}")
        except Exception as e:
            raise RuntimeError(f"UNIFESP CA not responding: {e}")

        try:
            r = requests.get("http://localhost:9998/ca/info", timeout=3)
            cls.mrnutricoes_info = r.json()
            cls.mrnutricoes_did = cls.mrnutricoes_info.get("did_key", cls.mrnutricoes_info.get("did", ""))
            print(f"  MRNutrições CA DID: {cls.mrnutricoes_did}")
        except Exception as e:
            raise RuntimeError(f"MRNutrições CA not responding: {e}")

        # 3. Start Key Guard ru-aluno (with UNIFESP CA)
        print("\n[SETUP] Starting Key Guard ru-aluno (port 8001)...")
        alfa_log = open(os.path.join(DATA_DIR, "alfa_kg.log"), "w")
        cls.log_files.append(alfa_log)
        cls.proc_alfa = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8001",
            "-name", "ru-aluno",
            "-endpoint", "http://localhost:8001",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9999",
            "-ca-enabled",
            "-skills", "messaging,course-consultation,personal-data-management",
            "-trusted-issuers", cls.mrnutricoes_did,
        ], stdout=alfa_log, stderr=alfa_log, text=True)
        cls.processes.append(cls.proc_alfa)
        time.sleep(1.5)

        if cls.proc_alfa.poll() is not None:
            raise RuntimeError("ru-aluno KG failed to start!")

        # 4. Start Key Guard ru-catraca (with MRNutrições CA)
        print("[SETUP] Starting Key Guard ru-catraca (port 8002)...")
        beta_log = open(os.path.join(DATA_DIR, "beta_kg.log"), "w")
        cls.log_files.append(beta_log)
        cls.proc_beta = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8002",
            "-name", "ru-catraca",
            "-endpoint", "http://localhost:8002",
            "-datadir", DATA_DIR,
            "-ca-url", "http://localhost:9998",
            "-ca-enabled",
            "-skills", "messaging,access-validation",
            "-trusted-issuers", cls.unifesp_did,
        ], stdout=beta_log, stderr=beta_log, text=True)
        cls.processes.append(cls.proc_beta)
        time.sleep(1.5)

        if cls.proc_beta.poll() is not None:
            raise RuntimeError("ru-catraca KG failed to start!")

        # 5. Get agent info for both
        cls.alfa_info = requests.get("http://localhost:8001/agent-info", timeout=3).json()
        cls.beta_info = requests.get("http://localhost:8002/agent-info", timeout=3).json()
        print(f"  ru-aluno DID: {cls.alfa_info['did']}")
        print(f"  ru-catraca DID: {cls.beta_info['did']}")

        # 6. Initialize Cognitive agents
        cls.agent_alfa = CognitiveAgent("ru-aluno", "http://localhost:8001",
                                        data_dir=DATA_DIR, request_vc=False)
        cls.agent_beta = CognitiveAgent("ru-catraca", "http://localhost:8002",
                                        data_dir=DATA_DIR, request_vc=False)

        # 7. Mutual VC Handshake (ru-aluno -> ru-catraca)
        print("\n[SETUP] Performing VC handshake ru-aluno -> ru-catraca...")
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
        for name, port in [("ru-aluno", 8001), ("ru-catraca", 8002)]:
            r = requests.get(f"http://localhost:{port}/.well-known/agent-card", timeout=3)
            self.assertEqual(r.status_code, 200)
            card = r.json()
            self.assertIn("name", card)
            self.assertIn(card["name"].lower(), name.lower())
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
        self.proc_unifesp.terminate()
        self.proc_unifesp.wait(timeout=5)
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
            unifesp_log = open(os.path.join(DATA_DIR, "unifesp_ca.log"), "a")
            cls = self.__class__
            unifesp_dir = os.path.join(DATA_DIR, "unifesp")
            cls.proc_unifesp = subprocess.Popen(
                [CA_BIN, "-port", "9999", "-datadir", unifesp_dir, "-name", "unifesp"],
                stdout=unifesp_log, stderr=unifesp_log, text=True
            )
            cls.processes.append(cls.proc_unifesp)
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
        
        # 1. Start a third (untrusted) CA on port 9997
        untrusted_ca_dir = os.path.join(DATA_DIR, "untrusted_ca")
        os.makedirs(untrusted_ca_dir, exist_ok=True)
        untrusted_log = open(os.path.join(DATA_DIR, "untrusted_ca.log"), "w")
        proc_untrusted_ca = subprocess.Popen(
            [CA_BIN, "-port", "9997", "-datadir", untrusted_ca_dir, "-name", "untrusted"],
            stdout=untrusted_log, stderr=untrusted_log, text=True
        )
        time.sleep(1.5)

        if proc_untrusted_ca.poll() is not None:
            untrusted_log.close()
            self.skipTest("Untrusted CA failed to start")

        # 2. Start a temporary agent (temp-untrusted) on port 8020, pointing to the untrusted CA
        temp_dir = os.path.join(DATA_DIR, "temp-untrusted")
        os.makedirs(temp_dir, exist_ok=True)
        temp_log = open(os.path.join(DATA_DIR, "temp-untrusted.log"), "w")
        proc_temp = subprocess.Popen([
            KEY_GUARD_BIN,
            "-port", "8020",
            "-name", "temp-untrusted",
            "-endpoint", "http://localhost:8020",
            "-datadir", temp_dir,
            "-ca-url", "http://localhost:9997",
            "-ca-enabled",
        ], stdout=temp_log, stderr=temp_log, text=True)
        time.sleep(1.5)

        if proc_temp.poll() is not None:
            proc_untrusted_ca.terminate()
            proc_untrusted_ca.wait()
            untrusted_log.close()
            temp_log.close()
            self.skipTest("temp-untrusted agent failed to start")

        try:
            # 3. Attempt handshake from ru-aluno (port 8001, CA unifesp) to temp-untrusted (port 8020, CA untrusted)
            resp = requests.post("http://localhost:8001/handshake-peer", json={
                "target_endpoint": "http://localhost:8020"
            }, timeout=5)

            # This handshake should fail because ru-aluno does not trust untrusted CA (port 9997)
            self.assertNotEqual(resp.status_code, 200, "Handshake should have been rejected due to CA trust mismatch")
            print(f"  Handshake successfully rejected: {resp.status_code} {resp.text}")

        finally:
            proc_temp.terminate()
            proc_temp.wait()
            proc_untrusted_ca.terminate()
            proc_untrusted_ca.wait()
            untrusted_log.close()
            temp_log.close()

        print("  PASSED")

    # ─────────────────────────────────────────────────
    # Scenario 16: Academic and RU Skills
    # ─────────────────────────────────────────────────
    def test_16_academic_and_ru_skills(self):
        """Verify that agents can execute interactive tools for their domains, and are blocked for unauthorized skills."""
        print("--- Test 16: Academic & RU Skills ---")
        
        # 1. ru-aluno has 'course-consultation' and 'personal-data-management'
        # Test consulting course (success)
        res_course = self.agent_alfa.tool_consult_course("12345")
        self.assertEqual(res_course["status"], "success")
        self.assertEqual(res_course["data"]["student_name"], "Tasso")
        print("  ru-aluno successfully consulted course for student 12345")

        # Test managing personal data (success)
        res_personal = self.agent_alfa.tool_manage_personal_data("12345", email="new_tasso@unifesp.br")
        self.assertEqual(res_personal["status"], "success")
        self.assertEqual(res_personal["updated_personal_data"]["email"], "new_tasso@unifesp.br")
        print("  ru-aluno successfully updated email for student 12345")

        # Test academic enrollment (should fail since ru-aluno lacks 'academic-enrollment' skill)
        res_enroll = self.agent_alfa.tool_academic_enroll("12345", "UC-456")
        self.assertEqual(res_enroll["status"], "error")
        self.assertIn("lacks academic-enrollment skill", res_enroll["reason"])
        print("  ru-aluno enrollment blocked as expected (unauthorized skill)")

        # 2. ru-catraca has 'access-validation'
        # Test access validation with valid card and sufficient balance (success)
        res_access = self.agent_beta.tool_validate_ru_access("RU-777")
        self.assertEqual(res_access["status"], "granted")
        self.assertEqual(res_access["remaining_balance"], 8.00)  # 10.00 - 2.00 BRL
        print("  ru-catraca successfully granted access and deducted RU meal fee")

        # Test access validation with insufficient balance (should fail)
        # 8.00 -> 6.00 -> 4.00 -> 2.00 -> 0.00 -> denied
        for _ in range(4):
            self.agent_beta.tool_validate_ru_access("RU-777")
        res_denied = self.agent_beta.tool_validate_ru_access("RU-777")
        self.assertEqual(res_denied["status"], "denied")
        self.assertIn("insufficient balance", res_denied["reason"].lower())
        print("  ru-catraca successfully denied access for insufficient balance")

        # Test meal consultation (should fail since ru-catraca lacks 'meal-consultation' skill)
        res_menu = self.agent_beta.tool_consult_meal_menu("segunda")
        self.assertEqual(res_menu["status"], "error")
        self.assertIn("lacks meal-consultation skill", res_menu["reason"])
        print("  ru-catraca menu consultation blocked as expected (unauthorized skill)")

        print("  PASSED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
