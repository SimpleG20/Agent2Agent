import argparse
import time
import sys
from agent import CognitiveAgent

def main():
    parser = argparse.ArgumentParser(description="A2A Cognitive Agent")
    parser.add_argument("--name", required=True, help="Agent name (alfa/beta)")
    parser.add_argument("--keyguard", required=True, help="Local Key Guard base URL")
    parser.add_argument("--no-vc", action="store_true", help="Skip VC request on startup")
    args = parser.parse_args()

    print(f"=== Starting Cognitive Agent {args.name.upper()} ===")
    print(f"Key Guard URL: {args.keyguard}")

    agent = CognitiveAgent(name=args.name, key_guard_url=args.keyguard,
                           request_vc=not args.no_vc)
    print(f"DID: {agent.did}")

    # Show credential status
    cred_status = agent.get_credential_status()
    if cred_status["status"] == "verified":
        print(f"VC: ✅ {cred_status['status'].upper()}")
        print(f"VC ID: {cred_status['credential_id']}")
        print(f"Expires: {cred_status['expires']}")
    elif cred_status["status"] == "no_credential":
        print(f"VC: ⚠️ NO CREDENTIAL (degraded mode)")
    else:
        print(f"VC: ❌ {cred_status['status'].upper()}")

    # Show agent card on startup
    card = agent.get_agent_card()
    if card:
        capabilities = card.get("capabilities", {})
        skills = capabilities.get("skills", [])
        protocols = capabilities.get("protocols", [])
        skill_names = [s.get("id", "?") for s in skills]
        proto_str = ", ".join(protocols) if protocols else "none"
        print(f"Agent Card: {len(skills)} skills ({', '.join(skill_names)})")
        print(f"Protocols: {proto_str}")

    try:
        while True:
            # Poll inbox for verified incoming messages
            messages = agent.tool_read_inbox()
            for msg in messages:
                print(f"\n[{args.name.upper()} COGNITIVE INBOX] SECURE MESSAGE RECEIVED:")
                print(f"  From:   {msg['from']}")
                print(f"  Text:   {msg['content']}")
                print("-" * 40)

            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\nStopping Cognitive Agent {args.name.upper()}...")
        sys.exit(0)

if __name__ == "__main__":
    main()
