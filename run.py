"""
Cyber Risk Prioritization Platform Launcher
Run this script to start the server!
"""
import os
import sys

backend_dir = os.path.join(os.path.dirname(__file__), "backend")
sys.path.insert(0, backend_dir)

from app import run

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("Starting Cyber Risk Prioritization Platform...")
    run(8000)

