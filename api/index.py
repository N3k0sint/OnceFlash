"""
Vercel Serverless Entrypoint for OnceFlash API
Exposes the FastAPI instance for Vercel's serverless Python runtime.
"""

import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app
