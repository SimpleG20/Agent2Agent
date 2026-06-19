import os
import sys
import json
import time
import sqlite3
import socket
import subprocess
import requests
import shutil
from flask import Flask, jsonify, request, render_template

# Adjust Python path to include cognitive layer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cognitive")))
from agent import CognitiveAgent

app = Flask(__name__)

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_DIR, "data_dashboard")
CA_URL = os.environ.get("CA_URL", "http://localhost:9999")

# Maintain subprocesses dynamically
subprocesses_dict = {}

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def load_agents_registry():
    path = os.path.join(DATA_DIR, "agents.json")
    if not os.path.exists(path):
        default_registry = {"alfa": 8001, "beta": 8002}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(default_registry, f, indent=4)
        return default_registry
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {"alfa": 8001, "beta": 8002}

def save_agents_registry(registry):
    path = os.path.join(DATA_DIR, "agents.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(registry, f, indent=4)

def get_db_data(db_path, query, params=()):
    if not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        return [{"error": str(e)}]

def get_json_file(file_path):
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def start_key_guards():
    key_guard_bin = os.path.join(PROJECT_DIR, "key-guard", "key-guard-bin")
    registry = load_agents_registry()
    
    started_any = False
    for name, port in registry.items():
        proc_key = f"key_guard_{name}"
        if not is_port_in_use(port) and subprocesses_dict.get(proc_key) is None:
            print(f"Starting {name} Key Guard on port {port}...")
            os.makedirs(os.path.join(DATA_DIR, name), exist_ok=True)
            log_file = open(os.path.join(DATA_DIR, f"{name}_key_guard.log"), "w")
            cmd = [
                key_guard_bin,
                "-port", str(port),
                "-name", name,
                "-endpoint", f"http://localhost:{port}",
                "-datadir", DATA_DIR,
                "-ca-url", CA_URL,
                "-ca-enabled",
            ]
            subprocesses_dict[proc_key] = subprocess.Popen(cmd, stdout=log_file, stderr=log_file, text=True)
            started_any = True

    if started_any:
        # Allow startup
        time.sleep(2)
    return True

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    # 1. Start key guards if they aren't running
    start_key_guards()

    registry = load_agents_registry()
    agents_status = {}
    
    for name, port in registry.items():
        # Check active status of Key Guard
        online = is_port_in_use(port)

        # Fetch DID key from Key Guard's agent-info endpoint
        did = f"did:custom:{name}"
        did_key = ""
        if online:
            try:
                r = requests.get(f"http://localhost:{port}/agent-info", timeout=2)
                if r.status_code == 200:
                    info = r.json()
                    did_key = info.get("did_key", "")
                    if did_key:
                        did = did_key
            except:
                pass

        # Retrieve direct info of peers resolved in peers_store
        db_path = os.path.join(DATA_DIR, name, "cognitive_store.db")
        blacklist_path = os.path.join(DATA_DIR, name, "blacklist.json")
        peers_path = os.path.join(DATA_DIR, name, "peers.json")

        # Query local state
        tx_history = get_db_data(db_path, "SELECT * FROM tx_history ORDER BY timestamp DESC LIMIT 15")
        cognitive_blacklist = get_db_data(db_path, "SELECT * FROM cognitive_blacklist")
        key_guard_blacklist = get_json_file(blacklist_path)
        peers_store = get_json_file(peers_path)

        # Fetch credential info from Key Guard
        credential = {}
        if online:
            try:
                r = requests.get(f"http://localhost:{port}/credential", timeout=2)
                if r.status_code == 200:
                    credential = r.json()
                else:
                    credential = {"error": f"status {r.status_code}"}
            except Exception as e:
                credential = {"error": str(e)}

        agents_status[name] = {
            "name": name,
            "did": did,
            "did_key": did_key,
            "key_guard_online": online,
            "key_guard_port": port,
            "cognitive_blacklist": cognitive_blacklist,
            "key_guard_blacklist": key_guard_blacklist,
            "peers_store": peers_store,
            "tx_history": tx_history,
            "credential": credential
        }

    return jsonify({
        "contract_address": "N/D - Modo de Handshake P2P Puro",
        "agents": agents_status
    })

@app.route("/api/send", methods=["POST"])
def send_message():
    data = request.json
    sender = data.get("sender")
    recipient = data.get("recipient")
    content = data.get("content")

    if not sender or not recipient or not content:
        return jsonify({"error": "Campos obrigatórios ausentes"}), 400

    registry = load_agents_registry()
    if sender not in registry:
        return jsonify({"error": f"Remetente {sender} não encontrado"}), 404
        
    port = registry[sender]
    agent = CognitiveAgent(sender, f"http://localhost:{port}", data_dir=DATA_DIR)
    
    res = agent.tool_send_message(to_did=recipient, content=content)
    return jsonify(res)

@app.route("/api/poll", methods=["POST"])
def poll_inbox():
    data = request.json
    name = data.get("name")
    if not name:
        return jsonify({"error": "Nome do agente ausente"}), 400

    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agente {name} não encontrado"}), 404
        
    port = registry[name]
    agent = CognitiveAgent(name, f"http://localhost:{port}", data_dir=DATA_DIR)
    
    messages = agent.tool_read_inbox()
    return jsonify({"polled_messages": messages})

@app.route("/api/handshake", methods=["POST"])
def trigger_handshake():
    data = request.json
    sender = data.get("sender")
    target_endpoint = data.get("target_endpoint")
    
    if not sender or not target_endpoint:
        return jsonify({"error": "Remetente ou target_endpoint ausente"}), 400

    registry = load_agents_registry()
    if sender not in registry:
        return jsonify({"error": f"Remetente {sender} não encontrado"}), 404

    port = registry[sender]
    try:
        r = requests.post(f"http://localhost:{port}/handshake-peer", json={"target_endpoint": target_endpoint}, timeout=5)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/agents/create", methods=["POST"])
def create_agent():
    data = request.json or {}
    name = data.get("name", "").strip().lower()
    if not name:
        return jsonify({"error": "Nome do agente é obrigatório"}), 400
    
    if not name.isalnum():
        return jsonify({"error": "Nome do agente deve ser alfanumérico"}), 400

    registry = load_agents_registry()
    if name in registry:
        return jsonify({"error": f"Agente {name} já existe"}), 400

    # Allocate port dynamically (scanning starting from 8003)
    port = 8003
    while True:
        if port not in registry.values() and not is_port_in_use(port):
            break
        port += 1

    registry[name] = port
    save_agents_registry(registry)

    # Spawn process
    key_guard_bin = os.path.join(PROJECT_DIR, "key-guard", "key-guard-bin")
    proc_key = f"key_guard_{name}"
    
    os.makedirs(os.path.join(DATA_DIR, name), exist_ok=True)
    log_file = open(os.path.join(DATA_DIR, f"{name}_key_guard.log"), "w")
    subprocesses_dict[proc_key] = subprocess.Popen([
        key_guard_bin,
        "-port", str(port),
        "-name", name,
        "-endpoint", f"http://localhost:{port}",
        "-datadir", DATA_DIR,
        "-ca-url", CA_URL,
        "-ca-enabled",
    ], stdout=log_file, stderr=log_file, text=True)
    
    # Wait for initialization
    time.sleep(2)

    # Verify startup
    if subprocesses_dict[proc_key].poll() is not None:
        del registry[name]
        save_agents_registry(registry)
        if proc_key in subprocesses_dict:
            del subprocesses_dict[proc_key]
        return jsonify({"error": f"Falha ao iniciar Key Guard para o agente {name}. Verifique os logs."}), 500

    return jsonify({"status": "created", "name": name, "port": port})

@app.route("/api/agents/remove", methods=["POST"])
def remove_agent():
    data = request.json or {}
    name = data.get("name", "").strip().lower()
    if not name:
        return jsonify({"error": "Nome do agente é obrigatório"}), 400
    
    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agente {name} não existe"}), 404

    # Terminate process
    proc_key = f"key_guard_{name}"
    proc = subprocesses_dict.get(proc_key)
    if proc:
        proc.terminate()
        proc.wait()
        del subprocesses_dict[proc_key]

    # Remove from registry
    del registry[name]
    save_agents_registry(registry)

    # Delete files
    agent_dir = os.path.join(DATA_DIR, name)
    if os.path.exists(agent_dir):
        try:
            shutil.rmtree(agent_dir)
        except Exception:
            time.sleep(0.5)
            try:
                shutil.rmtree(agent_dir)
            except Exception:
                pass

    # Clean log file
    log_path = os.path.join(DATA_DIR, f"{name}_key_guard.log")
    if os.path.exists(log_path):
        try:
            os.remove(log_path)
        except Exception:
            pass

    return jsonify({"status": "removed", "name": name})

@app.route("/api/blacklist/remove", methods=["POST"])
def remove_from_blacklist():
    data = request.json or {}
    name = data.get("name")
    did = data.get("did")
    
    if not name or not did:
        return jsonify({"error": "Campos obrigatórios ausentes"}), 400
        
    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agente {name} não encontrado"}), 404
        
    port = registry[name]
    
    # 1. Remove from SQLite (Cognitive layer)
    agent = CognitiveAgent(name, f"http://localhost:{port}", data_dir=DATA_DIR)
    agent.remove_peer_from_blacklist(did)
    
    # 2. Remove from Go Key Guard
    try:
        r = requests.delete(f"http://localhost:{port}/blacklist", json={"did": did}, timeout=5)
        if r.status_code == 200:
            return jsonify({"status": "removed"})
        else:
            return jsonify({"error": f"Erro do Key Guard: {r.text}"}), r.status_code
    except Exception as e:
        return jsonify({"error": f"Falha ao sincronizar com o Key Guard: {str(e)}"}), 500

@app.route("/api/db_view")
def db_view():
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "Parâmetro name ausente"}), 400

    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agente {name} não encontrado"}), 404

    db_path = os.path.join(DATA_DIR, name, "cognitive_store.db")
    blacklist_path = os.path.join(DATA_DIR, name, "blacklist.json")
    peers_path = os.path.join(DATA_DIR, name, "peers.json")
    pub_key_path = os.path.join(DATA_DIR, name, "keys", "public.key")

    tx_history = get_db_data(db_path, "SELECT * FROM tx_history ORDER BY timestamp DESC")
    cognitive_blacklist = get_db_data(db_path, "SELECT * FROM cognitive_blacklist ORDER BY blocked_at DESC")
    
    key_guard_blacklist = get_json_file(blacklist_path)
    peers_store = get_json_file(peers_path)

    pub_key = "N/A"
    if os.path.exists(pub_key_path):
        try:
            with open(pub_key_path, "r") as f:
                pub_key = f.read().strip()
        except Exception:
            pass

    return jsonify({
        "name": name,
        "port": registry[name],
        "public_key": pub_key,
        "tx_history": tx_history,
        "cognitive_blacklist": cognitive_blacklist,
        "key_guard_blacklist": key_guard_blacklist,
        "peers_store": peers_store
    })

@app.route("/api/ca/status")
def ca_status():
    """Returns CA status: online/offline, public key, VC counts."""
    try:
        r = requests.get(f"{CA_URL}/ca/info", timeout=2)
        if r.status_code == 200:
            info = r.json()
            return jsonify({"online": True, "did_key": info.get("did", ""), "public_key": info.get("publicKeyBase64", ""), "total_issued": info.get("totalIssued", 0), "total_revoked": info.get("totalRevoked", 0)})
        return jsonify({"online": False, "error": f"CA returned {r.status_code}"})
    except Exception as e:
        return jsonify({"online": False, "error": str(e)})

@app.route("/api/ca/credentials")
def ca_credentials():
    """Returns list of all credentials issued by the CA."""
    try:
        r = requests.get(f"{CA_URL}/credential/list", timeout=2)
        if r.status_code == 200:
            return jsonify(r.json())
        return jsonify({"error": f"CA returned {r.status_code}", "credentials": []})
    except Exception as e:
        return jsonify({"error": str(e), "credentials": []})

@app.route("/api/credential/revoke", methods=["POST"])
def revoke_credential():
    """Revokes an agent's credential via the CA."""
    data = request.json or {}
    agent_name = data.get("name")
    credential_id = data.get("credential_id")

    if not agent_name:
        return jsonify({"error": "Agent name required"}), 400
    if not credential_id:
        return jsonify({"error": "Credential ID required"}), 400

    # Revoke via CA (CA expects camelCase credentialId)
    try:
        r = requests.post(f"{CA_URL}/credential/revoke", json={"credentialId": credential_id}, timeout=5)
        if r.status_code == 200:
            return jsonify({"status": "revoked", "credential_id": credential_id})
        else:
            return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/agent-card")
def agent_card_view():
    """Fetches the Agent Card from a specific key guard."""
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "Name parameter required"}), 400
    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agent {name} not found"}), 404
    port = registry[name]
    try:
        r = requests.get(f"http://localhost:{port}/.well-known/agent-card", timeout=3)
        if r.status_code == 200:
            return jsonify(r.json())
        return jsonify({"error": f"Agent card returned {r.status_code}"}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tasks/list")
def tasks_list():
    """Lists tasks from a specific agent's Key Guard."""
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "Name parameter required"}), 400
    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agent {name} not found"}), 404
    port = registry[name]
    tasks = []
    try:
        # Fetch all tasks via the task store endpoint
        # For now, list known tasks from task store
        r = requests.get(f"http://localhost:{port}/a2a/tasks/list", timeout=3)
        if r.status_code == 200:
            tasks = r.json().get("tasks", [])
    except:
        pass
    return jsonify({"agent": name, "tasks": tasks})

@app.route("/api/credential/request-issue", methods=["POST"])
def credential_request_issue():
    """Requests a new VC for an agent from the CA via the Key Guard."""
    data = request.json or {}
    name = data.get("name")
    if not name:
        return jsonify({"error": "Agent name required"}), 400
    registry = load_agents_registry()
    if name not in registry:
        return jsonify({"error": f"Agent {name} not found"}), 404
    port = registry[name]
    try:
        r = requests.post(f"http://localhost:{port}/credential/request-issue", json={}, timeout=5)
        if r.status_code == 200:
            return jsonify(r.json())
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reset", methods=["POST"])
def reset_system():
    # Kill all running Key Guards
    for key in list(subprocesses_dict.keys()):
        proc = subprocesses_dict[key]
        if proc:
            try:
                proc.terminate()
                proc.wait()
            except Exception:
                pass
            subprocesses_dict[key] = None

    # Force kill any hanging key-guard-bin
    try:
        subprocess.run(["pkill", "-f", "key-guard-bin"])
    except Exception:
        pass

    # Reset registry to default alfa/beta
    default_registry = {"alfa": 8001, "beta": 8002}
    save_agents_registry(default_registry)

    # Clean data dir
    if os.path.exists(DATA_DIR):
        try:
            shutil.rmtree(DATA_DIR)
        except Exception:
            pass
    os.makedirs(DATA_DIR, exist_ok=True)
    save_agents_registry(default_registry)

    # Restart default Key Guards
    success = start_key_guards()
    
    return jsonify({"status": "reset_success", "key_guards_restarted": success})

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=9000, debug=True)
