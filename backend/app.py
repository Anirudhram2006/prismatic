from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os
from simulation import simulate
from twin import build_twin

app = Flask(__name__)
CORS(app)

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "output.json")


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "SmokeStack API running 🔥"})


@app.route("/predict", methods=["POST"])
def predict():
    alert = request.get_json(force=True)
    if not alert:
        return jsonify({"error": "No JSON body provided"}), 400

    twin  = build_twin()
    result = simulate(alert, twin)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    return jsonify(result)


@app.route("/twin", methods=["GET"])
def get_twin():
    """Return the full Digital Twin graph (handy for frontend visualisation)."""
    return jsonify(build_twin())


if __name__ == "__main__":
    app.run(debug=True, port=5000)
