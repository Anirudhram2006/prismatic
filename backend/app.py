from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import json
import os

try:
    from .digital_twin_sim import get_stage_sequence, load_mock_twin, simulate_stage
    from .simulation import simulate
    from .twin import build_twin
except ImportError:
    from digital_twin_sim import get_stage_sequence, load_mock_twin, simulate_stage
    from simulation import simulate
    from twin import build_twin


BASE_DIR = os.path.dirname(__file__)
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
OUTPUT_FILE = os.path.join(BASE_DIR, "output.json")

app = Flask(__name__)
CORS(app)


def _frontend_file(filename: str):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/", methods=["GET"])
def index():
    return _frontend_file("index.html")


@app.route("/assets/<path:filename>", methods=["GET"])
def frontend_assets(filename: str):
    return _frontend_file(filename)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "TwinShield API running"})


@app.route("/predict", methods=["POST"])
def predict():
    alert = request.get_json(force=True)
    if not alert:
        return jsonify({"error": "No JSON body provided"}), 400

    twin = build_twin()
    result = simulate(alert, twin)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(result, file_handle, indent=2)

    return jsonify(result)


@app.route("/simulate", methods=["POST"])
def simulate_route():
    payload = request.get_json(force=True) or {}
    stage = payload.get("stage", "suspicious_login")
    incident_type = payload.get("incident_type", "Account Compromise")

    try:
        result = simulate_stage(stage, incident_type=incident_type)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@app.route("/twin", methods=["GET"])
def get_twin():
    return jsonify(build_twin())


@app.route("/mock-db", methods=["GET"])
def get_mock_db():
    return jsonify(load_mock_twin())


@app.route("/simulation-stages", methods=["GET"])
def get_simulation_stages():
    return jsonify({"stages": get_stage_sequence()})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
