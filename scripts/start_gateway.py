import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from nexus.gateway.app import app

if __name__ == "__main__":
    port = int(os.environ.get("NEXUS_PORT", "7800"))
    print(f"Starting CangSight Gateway on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)