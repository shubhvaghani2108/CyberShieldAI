import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from dashboard.app import app

# Expose app for Render default 'gunicorn app:app' & local runner
if __name__ == "__main__":
    app.run()
