import os
import time
import sqlite3
import requests
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, Any, List

# Pydantic schema for standard transaction/communication payload
class MessagePayload(BaseModel):
    content: str = Field(..., description="Message text or command content")
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata details")

class CognitiveAgent:
    def __init__(self, name: str, key_guard_url: str, data_dir: str = "./data"):
        self.name = name
        self.did = f"did:custom:{name}"
        self.key_guard_url = key_guard_url
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, name, "cognitive_store.db")
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize SQLite local storage for cognitive state
        self._init_db()

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
        conn.commit()
        conn.close()

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

    # Monitor & Reputation logic

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
