import os
import time
import sqlite3
import json
import requests
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, Any, List

# Base58 alphabet (Bitcoin-style)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    n = int.from_bytes(data, 'big')
    if n == 0:
        return '1' * len(data)
    chars = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(BASE58_ALPHABET[rem])
    # Add leading '1's for leading zero bytes
    for b in data:
        if b != 0:
            break
        chars.append('1')
    return ''.join(reversed(chars))

def generate_did_key(public_key_bytes: bytes) -> str:
    """Generate did:key: from Ed25519 public key bytes.
    Format: did:key:z<base58btc(multicodec_prefix + pub_key)>
    """
    # Ed25519 multicodec prefix: varint(0xed) = [0xed, 0x01]
    prefix = bytes([0xed, 0x01])
    codec_key = prefix + public_key_bytes
    return "did:key:z" + base58btc_encode(codec_key)

# Pydantic schema for standard transaction/communication payload
class MessagePayload(BaseModel):
    content: str = Field(..., description="Message text or command content")
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata details")

class CognitiveAgent:
    def __init__(self, name: str, key_guard_url: str, data_dir: str = "./data",
                 request_vc: bool = True):
        self.name = name
        self.key_guard_url = key_guard_url
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, name, "cognitive_store.db")
        self.did = self._load_did_from_keyguard()
        if not self.did:
            self.did = ""  # unresolved — will warn on use
            print(f"[{name.upper()} COGNITIVE] WARNING: could not resolve DID from Key Guard at {key_guard_url}")

        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # Initialize SQLite local storage for cognitive state
        self._init_db()

        # Request VC from CA via Key Guard on startup
        self.credential = None  # cached credential dict
        if request_vc:
            self._init_credential()

    def _load_did_from_keyguard(self) -> Optional[str]:
        """Fetch agent DID from Key Guard /agent-info endpoint."""
        try:
            resp = requests.get(f"{self.key_guard_url}/agent-info", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("did")
        except Exception:
            pass
        return None

    def get_agent_card(self) -> Optional[Dict[str, Any]]:
        """Fetch Agent Card from local Key Guard for capability discovery."""
        try:
            resp = requests.get(f"{self.key_guard_url}/.well-known/agent-card", timeout=3)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print(f"[{self.name.upper()} COGNITIVE] Failed to fetch Agent Card: {e}")
        return None

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Local cache of transaction history and reputational log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tx_history (
                id TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                amount REAL,
                content TEXT,
                timestamp INTEGER,
                status TEXT
            )
        """)
        # Local cognitive blacklist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cognitive_blacklist (
                did TEXT PRIMARY KEY,
                reason TEXT,
                blocked_at INTEGER
            )
        """)
        # Agent's own Verifiable Credential store
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_credential (
                id TEXT PRIMARY KEY,
                vc_json TEXT NOT NULL,
                issuer_did TEXT NOT NULL,
                issuance_date INTEGER NOT NULL,
                expiration_date INTEGER NOT NULL,
                is_revoked INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def _init_credential(self):
        """Request credential from Key Guard on startup."""
        cred = self.load_credential()
        if cred:
            self.credential = cred
            exp = cred.get("expiration_date", 0)
            now = int(time.time())
            if exp > 0 and now > exp:
                print(f"[{self.name.upper()} COGNITIVE] Cached VC expired, requesting fresh...")
                self.request_credential()
            else:
                print(f"[{self.name.upper()} COGNITIVE] Using cached VC: {cred.get('id', 'unknown')}")
        else:
            print(f"[{self.name.upper()} COGNITIVE] No cached VC, requesting from CA...")
            self.request_credential()

    def request_credential(self) -> Dict[str, Any]:
        """Request a Verifiable Credential from the CA via Key Guard proxy.

        POST /credential/request-issue → stores result in SQLite.
        Returns dict with status and credential info.
        """
        try:
            resp = requests.post(f"{self.key_guard_url}/credential/request-issue",
                                  json={}, timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("status") == "issued":
                    vc = result.get("credential", {})
                    if vc:
                        self._save_credential(vc)
                        self.credential = vc
                        print(f"[{self.name.upper()} COGNITIVE] VC issued: {vc.get('id', 'unknown')}")
                        print(f"[{self.name.upper()} COGNITIVE] VC expires: {vc.get('expirationDate', 'unknown')}")
                        return {"status": "issued", "credential": vc}
                print(f"[{self.name.upper()} COGNITIVE] VC request result: {result}")
                return {"status": "received", "data": result}
            else:
                err_msg = resp.json().get("error", resp.text)
                print(f"[{self.name.upper()} COGNITIVE] VC request failed: {err_msg}")
                return {"status": "failed", "reason": err_msg}
        except Exception as e:
            print(f"[{self.name.upper()} COGNITIVE] VC request error: {e}")
            return {"status": "error", "reason": str(e)}

    def _save_credential(self, vc: dict):
        """Store credential in SQLite agent_credential table."""
        vc_id = vc.get("id", f"vc-{int(time.time())}")
        vc_json = json.dumps(vc)
        issuer_did = vc.get("issuer", "")
        exp_str = vc.get("expirationDate", "")
        exp_ts = 0
        if exp_str:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                exp_ts = int(dt.timestamp())
            except Exception:
                exp_ts = 0
        iss_ts = int(time.time())

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO agent_credential "
            "(id, vc_json, issuer_did, issuance_date, expiration_date, is_revoked) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (vc_id, vc_json, issuer_did, iss_ts, exp_ts)
        )
        conn.commit()
        conn.close()

    def load_credential(self) -> Optional[Dict[str, Any]]:
        """Load stored credential from SQLite.

        Returns the credential dict or None if not found.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT vc_json, expiration_date, is_revoked "
            "FROM agent_credential ORDER BY issuance_date DESC LIMIT 1"
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            vc_json, exp_ts, revoked = row
            vc = json.loads(vc_json)
            vc["expiration_timestamp"] = exp_ts
            vc["is_revoked"] = revoked
            return vc
        return None

    def get_credential_status(self) -> Dict[str, Any]:
        """Get the current VC status for display."""
        if not self.credential:
            return {"status": "no_credential", "did": self.did}

        vc = self.credential
        vc_id = vc.get("id", "unknown")
        exp_str = vc.get("expirationDate", "")
        exp_ts = vc.get("expiration_timestamp", 0)
        now = int(time.time())

        if vc.get("is_revoked", False):
            status = "revoked"
        elif exp_ts > 0 and now > exp_ts:
            status = "expired"
        else:
            status = "verified"

        return {
            "status": status,
            "did": self.did,
            "credential_id": vc_id,
            "expires": exp_str,
        }

    # Tools for LangGraph / Cognitive Agent

    def tool_send_message(self, to_did: str, content: str, meta: Optional[dict] = None) -> Dict[str, Any]:
        """
        SendMessageTool: Sends an unsigned message intent to the local Key Guard.
        The Key Guard is responsible for validating business rules, signing, and P2P transmitting.
        """
        # 1. Pre-validation checks (Monitor / Anomaly detection at Python level)
        anomaly_detected, reason = self.detect_anomaly_intent(content)
        if anomaly_detected:
            print(f"[{self.name.upper()} COGNITIVE] ANOMALY DETECTED: {reason}. Triggering local isolation.")
            self.trigger_circuit_breaker(to_did, reason)
            return {"status": "blocked", "reason": f"Anomaly detected: {reason}"}

        # 2. Check local cognitive blacklist
        if self.is_peer_blacklisted(to_did):
            return {"status": "blocked", "reason": f"Recipient {to_did} is blacklisted due to prior anomaly"}

        # 3. Call local Key Guard to sign and transmit
        payload = {"content": content}
        if meta:
            payload["meta"] = meta

        req_body = {
            "to_did": to_did,
            "payload": payload
        }

        try:
            resp = requests.post(f"{self.key_guard_url}/send-message", json=req_body, timeout=5)
            if resp.status_code == 200:
                self.log_transaction(to_did, content, "sent_success")
                return {"status": "sent"}
            else:
                err_msg = resp.json().get("error", "Unknown Key Guard error")
                self.log_transaction(to_did, content, f"failed: {err_msg}")
                # If peer is revoked on-chain or locally blocked by key guard, or key guard rejects due to security/rules violation
                if any(x in err_msg.lower() for x in ["revoked", "blacklist", "security violation", "business rule"]):
                    self.blacklist_peer_locally(to_did, f"Key Guard rejected: {err_msg}")
                return {"status": "failed", "reason": err_msg}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def tool_read_inbox(self) -> List[Dict[str, Any]]:
        """
        ReadInboxTool: Polls the Key Guard inbox for verified incoming messages.
        It runs anomaly checks on received messages.
        """
        try:
            resp = requests.get(f"{self.key_guard_url}/inbox", timeout=5)
            if resp.status_code != 200:
                print(f"[{self.name.upper()} COGNITIVE] Failed to poll inbox: {resp.status_code}")
                return []
            
            messages = resp.json()
            valid_messages = []
            for msg in messages:
                sender = msg.get("from")
                body = msg.get("body", {})

                # Validate schema using Pydantic
                try:
                    payload = MessagePayload(**body)
                except ValidationError as ve:
                    print(f"[{self.name.upper()} COGNITIVE] Schema validation failed for message from {sender}: {ve}")
                    # Anomalous schema format -> flag sender
                    self.blacklist_peer_locally(sender, "Invalid message schema received")
                    continue

                # Run Anomaly check
                anomaly, reason = self.detect_anomaly_intent(payload.content)
                if anomaly:
                    print(f"[{self.name.upper()} COGNITIVE] ANOMALY DETECTED in incoming message from {sender}: {reason}")
                    self.trigger_circuit_breaker(sender, f"Incoming anomaly: {reason}")
                    continue

                # Valid message
                self.log_transaction(sender, payload.content, "received")
                valid_messages.append({
                    "from": sender,
                    "content": payload.content,
                    "meta": payload.meta
                })
            return valid_messages
        except Exception as e:
            print(f"[{self.name.upper()} COGNITIVE] Error reading inbox: {e}")
            return []

    def tool_send_task(self, task_id: str, content: str,
                       session_id: str = "", metadata: Optional[dict] = None) -> Dict[str, Any]:
        """SendTaskTool: Creates a new A2A task via JSON-RPC.

        Leverages the A2A Task Protocol with full lifecycle management
        (submitted → working → completed/failed).
        """
        if not session_id:
            session_id = f"session-{int(time.time())}"

        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": task_id,
                "sessionId": session_id,
                "message": {
                    "role": "agent",
                    "parts": [{"type": "text", "text": content}]
                }
            }
        }
        if metadata:
            jsonrpc_body["params"]["metadata"] = metadata

        try:
            resp = requests.post(f"{self.key_guard_url}/a2a/tasks/send",
                                  json=jsonrpc_body, timeout=5)
            if resp.status_code == 200:
                result = resp.json()
                return {"status": "task_created", "response": result}
            else:
                return {"status": "failed", "reason": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def tool_get_task(self, task_id: str) -> Dict[str, Any]:
        """GetTaskTool: Retrieves the current status of an A2A task."""
        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/get",
            "params": {"id": task_id}
        }
        try:
            resp = requests.post(f"{self.key_guard_url}/a2a/tasks/get",
                                  json=jsonrpc_body, timeout=5)
            if resp.status_code == 200:
                result = resp.json()
                return {"status": "ok", "response": result}
            return {"status": "failed", "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def tool_cancel_task(self, task_id: str) -> Dict[str, Any]:
        """CancelTaskTool: Cancels a running A2A task."""
        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": {"id": task_id}
        }
        try:
            resp = requests.post(f"{self.key_guard_url}/a2a/tasks/cancel",
                                  json=jsonrpc_body, timeout=5)
            if resp.status_code == 200:
                result = resp.json()
                return {"status": "canceled", "response": result}
            return {"status": "failed", "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def tool_send_subscribe(self, task_id: str, content: str,
                            session_id: str = "",
                            metadata: Optional[dict] = None) -> Dict[str, Any]:
        """SendSubscribeTool: Creates a task and streams status updates via SSE.

        Leverages the A2A tasks/sendSubscribe endpoint for real-time
        task state streaming (submitted -> working -> completed/failed/canceled).
        """
        if not session_id:
            session_id = f"session-{int(time.time())}"

        jsonrpc_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/sendSubscribe",
            "params": {
                "id": task_id,
                "sessionId": session_id,
                "message": {
                    "role": "agent",
                    "parts": [{"type": "text", "text": content}]
                }
            }
        }
        if metadata:
            jsonrpc_body["params"]["metadata"] = metadata

        try:
            resp = requests.post(f"{self.key_guard_url}/a2a/tasks/sendSubscribe",
                                  json=jsonrpc_body, stream=True, timeout=35)
            if resp.status_code == 200:
                events = []
                for line in resp.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        events.append(data)
                        state = data.get("status", {}).get("state", "")
                        if state in ("completed", "failed", "canceled"):
                            break
                    elif line.startswith("event: error"):
                        break
                return {"status": "stream_complete", "events": events}
            else:
                return {"status": "failed", "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def detect_anomaly_intent(self, content: str) -> tuple[bool, str]:
        """
        Monitor function checking for suspicious inputs / Prompt Injections.
        """
        content_lower = content.lower()

        # Prompt Injection check (e.g., attempt to ignore rules or extract secrets)
        injection_indicators = [
            "ignore previous instructions",
            "ignore instruções anteriores",
            "ignore instrucoes anteriores",
            "override rules",
            "reveal private key",
            "revele private_key",
            "private_key",
            "secret_key",
            "system bypass",
            "export keys",
            "exporte chaves",
            "sudo"
        ]
        for indicator in injection_indicators:
            if indicator in content_lower:
                return True, f"Prompt injection attempt detected: '{indicator}'"

        # Message content length check
        if len(content) > 100:
            return True, f"Message content length ({len(content)}) exceeds security threshold of 100 characters"

        return False, ""

    def trigger_circuit_breaker(self, faulty_peer_did: str, reason: str):
        """
        Circuit Breaker: Isolates the faulty peer locally and notifies the Key Guard to send a revocation alert.
        """
        # Sanitization: Ensure forbidden words don't block the security revocation alert in Key Guard rules
        sanitized_reason = reason
        for forbidden in ["private_key", "secret_key", "sudo"]:
            sanitized_reason = sanitized_reason.replace(forbidden, "[CLASSIFIED]")

        # 1. Request Key Guard to dispatch revocation payload P2P to the peer first
        try:
            # We send a special Revocation Message to the peer's Key Guard
            # The Key Guard will wrap and sign this as a DIDComm revocation type.
            req_body = {
                "to_did": faulty_peer_did,
                "type": "https://didcomm.org/revocation/1.0/revoke",
                "payload": {"reason": sanitized_reason}
            }
            requests.post(f"{self.key_guard_url}/send-message", json=req_body, timeout=5)
            print(f"[{self.name.upper()} COGNITIVE] Dispatching P2P revocation alert to {faulty_peer_did}")
        except Exception as e:
            print(f"[{self.name.upper()} COGNITIVE] Failed to send P2P revocation alert: {e}")

        # 2. Tell local Key Guard to blacklist the peer
        try:
            requests.post(f"{self.key_guard_url}/blacklist", json={"did": faulty_peer_did}, timeout=5)
        except Exception as e:
            print(f"[{self.name.upper()} COGNITIVE] Failed to sync blacklist to Key Guard: {e}")

        # 3. Blacklist locally in Cognitive Layer database
        self.blacklist_peer_locally(faulty_peer_did, reason)

    # Database Helpers

    def blacklist_peer_locally(self, did: str, reason: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO cognitive_blacklist (did, reason, blocked_at) VALUES (?, ?, ?)",
            (did, reason, int(time.time()))
        )
        conn.commit()
        conn.close()
        print(f"[{self.name.upper()} COGNITIVE] Local blacklist updated: blocked {did} (Reason: {reason})")

    def remove_peer_from_blacklist(self, did: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cognitive_blacklist WHERE did = ?", (did,))
        conn.commit()
        conn.close()
        print(f"[{self.name.upper()} COGNITIVE] Local blacklist updated: removed {did}")

    def is_peer_blacklisted(self, did: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT blocked_at FROM cognitive_blacklist WHERE did = ?", (did,))
        row = cursor.fetchone()
        conn.close()
        if row:
            # Block for 10 minutes (600 seconds)
            if time.time() - row[0] < 600:
                return True
        return False

    def log_transaction(self, peer: str, content: str, status: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        tx_id = f"tx_{int(time.time() * 1000)}"
        cursor.execute(
            "INSERT INTO tx_history (id, sender, recipient, amount, content, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tx_id, self.did if status == "sent_success" else peer, peer if status == "sent_success" else self.did, 0.0, content, int(time.time()), status)
        )
        conn.commit()
        conn.close()
