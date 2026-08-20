import sys
import os

dir_path = os.path.dirname(os.path.realpath(__file__))
if dir_path not in sys.path:
    sys.path.insert(0, dir_path)

from backend_app.main import app
