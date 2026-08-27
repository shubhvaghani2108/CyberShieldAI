import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.monitoring_helpers import get_monitored_targets, count_monitored_targets

if __name__ == "__main__":
    targets = get_monitored_targets()
    print("Monitored Targets:", targets)
    print("Total:", count_monitored_targets())
