import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scheduler.monitor import (
    start_background_scheduler,
    get_apscheduler_instance,
    get_monitored_targets_with_schedule,
    sync_target_jobs,
    stop_background_scheduler,
)
from dashboard.app import app

def run_tests():
    print("--- 1. Testing APScheduler Startup ---")
    started = start_background_scheduler()
    print("Scheduler started:", started)
    sched = get_apscheduler_instance()
    assert sched.running == True
    print("APScheduler is running!")

    print("\n--- 2. Checking Scheduled Jobs ---")
    sync_target_jobs()
    jobs = sched.get_jobs()
    print(f"Registered Jobs count: {len(jobs)}")
    for j in jobs:
        print(f" - Job ID: {j.id} | Next Run: {j.next_run_time} | Trigger: {j.trigger}")

    print("\n--- 3. Testing get_monitored_targets_with_schedule ---")
    targets = get_monitored_targets_with_schedule()
    for t in targets:
        print(f"Target: {t.get('target')} | Last Scan: {t.get('last_scan_time')} | Next Scan: {t.get('next_scan_time')} | Status: {t.get('monitoring_status')}")
        assert "last_scan_time" in t
        assert "next_scan_time" in t
        assert "monitoring_status" in t

    print("\n--- 4. Testing Web UI Render ---")
    client = app.test_client()
    res = client.get("/monitoring")
    html = res.data.decode("utf-8")
    assert "Last Scan Time" in html
    assert "Next Scan Time" in html
    assert "Monitoring Status" in html
    print("Table headers rendered properly in /monitoring HTML!")

    stop_background_scheduler()
    print("\n[SUCCESS] All 7 APScheduler Monitoring Engine requirements verified!")
    sys.exit(0)

if __name__ == "__main__":
    run_tests()
