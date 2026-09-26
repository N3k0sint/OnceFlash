"""
OnceFlash — Standalone Local Runner
Runs the full OnceFlash application (API + Web Frontend) locally.
Uses built-in atomic in-memory ephemeral storage if Redis is not installed.
"""

import os
import sys
import subprocess

def main():
    print("=" * 60)
    print("⚡ Starting OnceFlash (Local Standalone Mode)")
    print("=" * 60)

    # Check dependencies
    try:
        import fastapi
        import uvicorn
        import slowapi
        import pydantic
    except ImportError:
        print("[*] Installing required backend packages...")
        req_path = os.path.join(os.path.dirname(__file__), "backend", "requirements.txt")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])
        print("[✓] Dependencies installed successfully.\n")

    # Set default local environment
    os.environ.setdefault("REDIS_URL", "memory://")
    os.environ.setdefault("ALLOWED_ORIGINS", "*")
    os.environ.setdefault("LOG_LEVEL", "INFO")

    print("[*] Storage: Built-in Atomic In-Memory (Zero-Knowledge)")
    print("[*] Web UI & API available at: http://localhost:8000")
    print("[*] Press Ctrl+C to stop.\n")

    # Add project root to sys.path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()
