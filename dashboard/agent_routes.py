import threading
from flask import request, jsonify
from dashboard.auth import login_required, get_current_user_id
from database.db_engine import get_db_connection
from database.agent_helpers import (
    register_agent,
    list_agents_for_user,
    get_agent_by_token,
    touch_agent,
    get_pending_jobs_for_user,
    get_agent_job,
    complete_agent_job,
    save_agent_port_results,
)
from dashboard.scan_jobs import resume_ip_scan_after_agent


def register_agent_routes(app):
    """Registers agent token and execution endpoints."""

    @app.route("/agent/generate-token", methods=["POST"])
    @login_required
    def agent_generate_token():
        """Creates and returns a new agent token for the logged-in user."""
        user_id = get_current_user_id()
        data = request.get_json(silent=True) or {}
        name = data.get("name") or request.form.get("name") or "Local Scan Agent"
        agent = register_agent(user_id, name=name.strip())
        return jsonify({"status": "success", "agent": agent})

    @app.route("/agent/list", methods=["GET"])
    @login_required
    def agent_list():
        """Lists all registered agents for the logged-in user."""
        user_id = get_current_user_id()
        agents = list_agents_for_user(user_id)
        return jsonify({"status": "success", "agents": agents})

    @app.route("/api/agent/jobs", methods=["GET"])
    def api_agent_jobs():
        """Agent-facing endpoint: returns pending scan jobs for this agent's user and marks them assigned."""
        token = request.headers.get("X-Agent-Token", "").strip()
        if not token:
            return jsonify({"status": "error", "message": "Missing X-Agent-Token header"}), 401

        agent = get_agent_by_token(token)
        if not agent:
            return jsonify({"status": "error", "message": "Invalid agent token"}), 401

        touch_agent(token)
        pending_jobs = get_pending_jobs_for_user(agent["user_id"])

        if pending_jobs:
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                for job in pending_jobs:
                    cursor.execute(
                        "UPDATE agent_jobs SET status = 'assigned' WHERE job_id = ?",
                        (job["job_id"],),
                    )
                conn.commit()
            finally:
                conn.close()

        return jsonify({"status": "success", "jobs": pending_jobs})

    @app.route("/api/agent/results", methods=["POST"])
    def api_agent_results():
        """Agent-facing endpoint: accepts open port results, saves them, and resumes the scan pipeline."""
        token = request.headers.get("X-Agent-Token", "").strip()
        if not token:
            return jsonify({"status": "error", "message": "Missing X-Agent-Token header"}), 401

        agent = get_agent_by_token(token)
        if not agent:
            return jsonify({"status": "error", "message": "Invalid agent token"}), 401

        touch_agent(token)

        data = request.get_json(silent=True) or {}
        job_id = data.get("job_id", "").strip()
        open_ports = data.get("open_ports", [])

        if not job_id:
            return jsonify({"status": "error", "message": "Missing job_id"}), 400

        job = get_agent_job(job_id)
        if not job:
            return jsonify({"status": "error", "message": "Job not found"}), 404

        if job["user_id"] != agent["user_id"]:
            return jsonify({"status": "error", "message": "Unauthorized for this job"}), 403

        # Save port results & complete job
        save_agent_port_results(job["scan_id"], job["target"], open_ports)
        complete_agent_job(job_id)

        # Resume scan pipeline in background thread
        thread = threading.Thread(
            target=resume_ip_scan_after_agent,
            args=(job["job_id"], job["scan_id"], job["target"], job["user_id"], open_ports),
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "success", "message": "Results received, scan resumed"})

    @app.route("/api/agent/job-status/<job_id>", methods=["GET"])
    def api_agent_job_status(job_id):
        """Returns the current execution status of an agent job."""
        job = get_agent_job(job_id)
        if not job:
            return jsonify({"status": "error", "message": "Job not found"}), 404
        return jsonify({"status": "success", "job": job})
