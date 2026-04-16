import sys
import codecs
from flask import Flask, jsonify

# Override stdout to handle cp1251 problems in Windows terminal
if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    except Exception:
        pass

from shop_bot.modules.key_checker import update_server_garant_link

app = Flask(__name__)

@app.route('/')
def get_garant():
    print("Received request for Garant link...")
    # call local_only so we actually test links from this machine instead of querying another server
    link = update_server_garant_link(local_only=True)
    return jsonify({"link": link})

def run_server():
    print("Testing Garant servers locally first...")
    link = update_server_garant_link(local_only=True)
    print(f"Success! Best link: {link}")
    
    print("\nStarting local API server on port 8080...")
    print("Use ngrok or tuna to expose this port, e.g.:")
    print("  ngrok http 8080")
    print("  tuna http 8080")
    print("Then set GARANT_API_URL on the main server (e.g. in .env) to the ngrok/tuna URL (e.g. https://xxx.tuna.am)")
    app.run(host="0.0.0.0", port=8080)

if __name__ == "__main__":
    run_server()
