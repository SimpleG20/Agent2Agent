import argparse
import time
import sys
from agent import CognitiveAgent

def main():
    parser = argparse.ArgumentParser(description="A2A Cognitive Agent")
    parser.add_argument("--name", required=True, help="Agent name (alfa/beta)")
    parser.add_argument("--keyguard", required=True, help="Local Key Guard base URL")
    args = parser.parse_args()

    print(f"=== Starting Cognitive Agent {args.name.upper()} ===")
    print(f"DID: did:custom:{args.name}")
    print(f"Key Guard URL: {args.keyguard}")
    
    agent = CognitiveAgent(name=args.name, key_guard_url=args.keyguard)

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
