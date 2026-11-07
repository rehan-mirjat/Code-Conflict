"""Production WSGI entrypoint for Code & Conflict.

Usage:
    gunicorn --workers=4 --bind=0.0.0.0:5000 backend.wsgi:application
"""
import os
import sys

# Ensure backend package directory is in sys.path
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from app import create_app

application = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    application.run(host='0.0.0.0', port=port)

