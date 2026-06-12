import os
import sys
import json
import time
import sqlite3
import socket
import subprocess
import requests
from flask import Flask, jsonify, request, render_template

# Adjust Python path to include cognitive layer
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cognitive")))
from agent import CognitiveAgent

app = Flask(__name__)

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_DIR, "data_dashboard")

# Maintain sub-processes
subprocesses_dict = {
    "key_guard_alfa": None,
    "key_guard_beta": None
}

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

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
    
    # Alfa
    if not is_port_in_use(8001) and subprocesses_dict["key_guard_alfa"] is None:
        print("Starting Alfa Key Guard...")
        alfa_log = open(os.path.join(DATA_DIR, "alfa_key_guard.log"), "w")
        subprocesses_dict["key_guard_alfa"] = subprocess.Popen([
            key_guard_bin,
            "-port", "8001",
            "-name", "alfa",
            "-endpoint", "http://localhost:8001",
            "-datadir", DATA_DIR
        ], stdout=alfa_log, stderr=alfa_log, text=True)

    # Beta
    if not is_port_in_use(8002) and subprocesses_dict["key_guard_beta"] is None:
        print("Starting Beta Key Guard...")
        beta_log = open(os.path.join(DATA_DIR, "beta_key_guard.log"), "w")
        subprocesses_dict["key_guard_beta"] = subprocess.Popen([
            key_guard_bin,
            "-port", "8002",
            "-name", "beta",
            "-endpoint", "http://localhost:8002",
            "-datadir", DATA_DIR
        ], stdout=beta_log, stderr=beta_log, text=True)

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

    # 2. Get status of both agents
    agents_status = {}
    for name, port in [("alfa", 8001), ("beta", 8002)]:
        # Check active status of Key Guard
        online = is_port_in_use(port)

        # Resolve details via local key guard if online
        local_peer_info = {}
        if online:
            try:
                # Query local Key Guard resolve endpoint (check target did)
                target_did = "did:custom:beta" if name == "alfa" else "did:custom:alfa"
                r = requests.get(f"http://localhost:{port}/resolve?did={target_did}", timeout=1)
                if r.status_code == 200:
                    local_peer_info = r.json()
            except Exception as e:
                local_peer_info = {"error": str(e)}

        # Paths to caches
        db_path = os.path.join(DATA_DIR, name, "cognitive_store.db")
        blacklist_path = os.path.join(DATA_DIR, name, "blacklist.json")
        peers_path = os.path.join(DATA_DIR, name, "peers.json")

        # Query databases
        tx_history = get_db_data(db_path, "SELECT * FROM tx_history ORDER BY timestamp DESC LIMIT 15")
        cognitive_blacklist = get_db_data(db_path, "SELECT * FROM cognitive_blacklist")
        key_guard_blacklist = get_json_file(blacklist_path)
        peers_store = get_json_file(peers_path)

        agents_status[name] = {
            "name": name,
            "did": f"did:custom:{name}",
            "key_guard_online": online,
            "key_guard_port": port,
            "resolved_partner": local_peer_info,
            "cognitive_blacklist": cognitive_blacklist,
            "key_guard_blacklist": key_guard_blacklist,
            "peers_store": peers_store,
            "tx_history": tx_history
        }

    return jsonify({
        "contract_address": "N/A - Pure P2P Handshake Mode",
        "agents": agents_status
    })

@app.route("/api/send", methods=["POST"])
def send_message():
    data = request.json
    sender = data.get("sender")
    recipient = data.get("recipient")
    content = data.get("content")
    amount = data.get("amount")

    if not sender or not recipient or not content:
        return jsonify({"error": "Missing fields"}), 400

    if amount is not None:
        try:
            amount = float(amount)
        except ValueError:
            amount = None

    port = 8001 if sender == "alfa" else 8002
    agent = CognitiveAgent(sender, f"http://localhost:{port}", data_dir=DATA_DIR)
    
    res = agent.tool_send_message(to_did=recipient, content=content, amount=amount)
    return jsonify(res)

@app.route("/api/poll", methods=["POST"])
def poll_inbox():
    data = request.json
    name = data.get("name")
    if not name:
        return jsonify({"error": "Missing agent name"}), 400

    port = 8001 if name == "alfa" else 8002
    agent = CognitiveAgent(name, f"http://localhost:{port}", data_dir=DATA_DIR)
    
    messages = agent.tool_read_inbox()
    return jsonify({"polled_messages": messages})

@app.route("/api/handshake", methods=["POST"])
def trigger_handshake():
    data = request.json
    sender = data.get("sender")
    target_endpoint = data.get("target_endpoint")
    
    if not sender or not target_endpoint:
        return jsonify({"error": "Missing sender or target_endpoint"}), 400

    port = 8001 if sender == "alfa" else 8002
    try:
        r = requests.post(f"http://localhost:{port}/handshake-peer", json={"target_endpoint": target_endpoint}, timeout=5)
        if r.status_code == 200:
            return jsonify(r.json())
        else:
            return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reset", methods=["POST"])
def reset_system():
    # Kill Key Guards
    for key in subprocesses_dict:
        proc = subprocesses_dict[key]
        if proc:
            proc.terminate()
            proc.wait()
            subprocesses_dict[key] = None

    # Force kill any hanging key-guard-bin
    try:
        subprocess.run(["pkill", "-f", "key-guard-bin"])
    except Exception:
        pass

    # Clean data dir
    import shutil
    if os.path.exists(DATA_DIR):
        shutil.rmtree(DATA_DIR)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Restart Key Guards
    success = start_key_guards()
    
    return jsonify({"status": "reset_success", "key_guards_restarted": success})

if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=9000, debug=True)
