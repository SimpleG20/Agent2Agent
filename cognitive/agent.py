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
            self.did = f"did:custom:{name}"  # fallback

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
        # UNIFESP Academic tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_enrollments (
                student_id TEXT,
                course_code TEXT,
                timestamp INTEGER,
                PRIMARY KEY (student_id, course_code)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_records (
                student_id TEXT PRIMARY KEY,
                student_name TEXT,
                course_name TEXT,
                grades TEXT,
                attendance REAL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_personal_data (
                student_id TEXT PRIMARY KEY,
                email TEXT,
                phone TEXT,
                rg TEXT,
                cpf TEXT
            )
        """)
        # MRNutrições RU tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ru_menu (
                day TEXT PRIMARY KEY,
                lunch TEXT,
                dinner TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ru_accounts (
                card_number TEXT PRIMARY KEY,
                student_id TEXT,
                balance REAL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ru_access_log (
                id TEXT PRIMARY KEY,
                card_number TEXT,
                timestamp INTEGER,
                status TEXT
            )
        """)
        # Seed initial/mock data if empty
        cursor.execute("SELECT COUNT(*) FROM student_records")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT OR REPLACE INTO student_records VALUES ('12345', 'Tasso', 'Ciência da Computação', '{\"Álgebra Linear\": 8.5, \"SSI\": 10.0}', 95.0)")
            cursor.execute("INSERT OR REPLACE INTO student_personal_data VALUES ('12345', 'tasso@unifesp.br', '11999999999', 'RG-1234', 'CPF-5678')")
            cursor.execute("INSERT OR REPLACE INTO ru_menu VALUES ('segunda', 'Arroz, Feijão, Frango Grelhado', 'Sopa de Legumes, Pão')")
            cursor.execute("INSERT OR REPLACE INTO ru_menu VALUES ('terca', 'Arroz, Feijão, Carne Panela', 'Polenta com Ragu')")
            cursor.execute("INSERT OR REPLACE INTO ru_menu VALUES ('quarta', 'Feijoada Completa', 'Creme de Abóbora')")
            cursor.execute("INSERT OR REPLACE INTO ru_accounts VALUES ('RU-777', '12345', 10.0)")
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

    def has_skill(self, skill_id: str) -> bool:
        """Check if the agent possesses a specific skill according to its Agent Card."""
        card = self.get_agent_card()
        if not card:
            return False
        skills = card.get("capabilities", {}).get("skills", [])
        return any(s.get("id") == skill_id for s in skills)

    def tool_academic_enroll(self, student_id: str, course_code: str) -> Dict[str, Any]:
        """academic-enrollment: Enrolls a student in a course at UNIFESP."""
        if not self.has_skill("academic-enrollment"):
            return {"status": "error", "reason": "Agent lacks academic-enrollment skill"}
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO student_enrollments (student_id, course_code, timestamp) VALUES (?, ?, ?)",
                (student_id, course_code, int(time.time()))
            )
            conn.commit()
            return {
                "status": "success",
                "message": f"Student {student_id} successfully enrolled in course {course_code} at UNIFESP",
                "student_id": student_id,
                "course_code": course_code
            }
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def tool_consult_course(self, student_id: str) -> Dict[str, Any]:
        """course-consultation: Retrieves course name, grades, and attendance from UNIFESP."""
        if not self.has_skill("course-consultation"):
            return {"status": "error", "reason": "Agent lacks course-consultation skill"}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM student_records WHERE student_id = ?", (student_id,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                data["grades"] = json.loads(data["grades"])
                return {"status": "success", "data": data}
            return {"status": "error", "reason": f"Student ID {student_id} not found"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def tool_manage_personal_data(self, student_id: str, email: str = None, phone: str = None) -> Dict[str, Any]:
        """personal-data-management: Updates and manages student personal contact details at UNIFESP."""
        if not self.has_skill("personal-data-management"):
            return {"status": "error", "reason": "Agent lacks personal-data-management skill"}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM student_personal_data WHERE student_id = ?", (student_id,))
            row = cursor.fetchone()
            if not row:
                return {"status": "error", "reason": f"Student ID {student_id} not found"}
            curr = dict(row)
            new_email = email if email is not None else curr["email"]
            new_phone = phone if phone is not None else curr["phone"]
            cursor.execute(
                "UPDATE student_personal_data SET email = ?, phone = ? WHERE student_id = ?",
                (new_email, new_phone, student_id)
            )
            conn.commit()
            return {
                "status": "success",
                "student_id": student_id,
                "updated_personal_data": {
                    "email": new_email,
                    "phone": new_phone,
                    "rg": curr["rg"],
                    "cpf": curr["cpf"]
                }
            }
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def tool_consult_meal_menu(self, day: str) -> Dict[str, Any]:
        """meal-consultation: Consults the daily menu and schedule for the MRNutrições RU."""
        if not self.has_skill("meal-consultation"):
            return {"status": "error", "reason": "Agent lacks meal-consultation skill"}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM ru_menu WHERE day = ?", (day.lower(),))
            row = cursor.fetchone()
            if row:
                return {"status": "success", "menu": dict(row)}
            return {"status": "error", "reason": f"No menu found for day '{day}'"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def tool_recharge_ru_balance(self, card_number: str, amount: float) -> Dict[str, Any]:
        """balance-recharge: Recharges balance on a card in the MRNutrições RU system."""
        if not self.has_skill("balance-recharge"):
            return {"status": "error", "reason": "Agent lacks balance-recharge skill"}
        if amount <= 0:
            return {"status": "error", "reason": "Recharge amount must be greater than zero"}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT balance FROM ru_accounts WHERE card_number = ?", (card_number,))
            row = cursor.fetchone()
            if not row:
                return {"status": "error", "reason": f"Card number {card_number} not found"}
            new_balance = row["balance"] + amount
            cursor.execute("UPDATE ru_accounts SET balance = ? WHERE card_number = ?", (new_balance, card_number))
            conn.commit()
            return {
                "status": "success",
                "message": f"Successfully recharged {amount:.2f} BRL",
                "card_number": card_number,
                "new_balance": new_balance
            }
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()

    def tool_validate_ru_access(self, card_number: str) -> Dict[str, Any]:
        """access-validation: Controls physical gate access based on card balance at MRNutrições RU."""
        if not self.has_skill("access-validation"):
            return {"status": "error", "reason": "Agent lacks access-validation skill"}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT balance FROM ru_accounts WHERE card_number = ?", (card_number,))
            row = cursor.fetchone()
            if not row:
                log_id = f"log_{int(time.time() * 1000)}"
                cursor.execute(
                    "INSERT INTO ru_access_log (id, card_number, timestamp, status) VALUES (?, ?, ?, 'DENIED_INVALID_CARD')",
                    (log_id, card_number, int(time.time()))
                )
                conn.commit()
                return {"status": "denied", "reason": f"Card {card_number} is invalid"}
            balance = row["balance"]
            meal_cost = 2.00
            if balance >= meal_cost:
                new_balance = balance - meal_cost
                cursor.execute("UPDATE ru_accounts SET balance = ? WHERE card_number = ?", (new_balance, card_number))
                log_id = f"log_{int(time.time() * 1000)}"
                cursor.execute(
                    "INSERT INTO ru_access_log (id, card_number, timestamp, status) VALUES (?, ?, ?, 'GRANTED')",
                    (log_id, card_number, int(time.time()))
                )
                conn.commit()
                return {
                    "status": "granted",
                    "card_number": card_number,
                    "deducted_amount": meal_cost,
                    "remaining_balance": new_balance
                }
            else:
                log_id = f"log_{int(time.time() * 1000)}"
                cursor.execute(
                    "INSERT INTO ru_access_log (id, card_number, timestamp, status) VALUES (?, ?, ?, 'DENIED_INSUFFICIENT_BALANCE')",
                    (log_id, card_number, int(time.time()))
                )
                conn.commit()
                return {
                    "status": "denied",
                    "reason": "Insufficient balance on RU card",
                    "card_number": card_number,
                    "balance": balance
                }
        except Exception as e:
            return {"status": "error", "reason": str(e)}
        finally:
            conn.close()
