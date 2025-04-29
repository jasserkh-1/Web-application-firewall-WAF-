# main.py  (clean imports)
from flask import Blueprint, render_template, request, jsonify
from flask_cors import CORS

# pull everything you actually need from waf.py in **one** line
from .waf import analyze_request, _events_coll, _mongo_db, MONGO_COUNTER_ID

main = Blueprint("main", __name__)

# If you use CORS here (optional):
# CORS(main)

# ▸──────────────────── routes ────────────────────▸
@main.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        payload = request.form.get("payload", "")
        result  = analyze_request(payload, request_obj=request)
    return render_template("index.html", result=result)

@main.route("/api/analyze", methods=["POST"])
def analyze_api():
    data    = request.get_json() or {}
    payload = data.get("payload", "")
    result  = analyze_request(payload, request_obj=request)
    return {"result": result}

@main.route("/api/logs", methods=["GET"])
def get_logs():
    logs = list(_events_coll.find().sort("timestamp", -1).limit(100))
    for log in logs:
        log["_id"] = str(log["_id"])   # make Mongo ObjectId JSON-safe
    return jsonify(logs)

@main.route("/api/stats", methods=["GET"])
def get_stats():
    doc = _mongo_db.counters.find_one({"_id": MONGO_COUNTER_ID}) or {}

    stats = {
        "total_requests":   doc.get("total_requests",   0),
        "allowed_requests": doc.get("allowed_requests", 0),
        "blocked_requests": doc.get("blocked_requests", 0),
    }
    return jsonify({
        "status":  "success",
        "message": "WAF global statistics",
        "data":    stats
    })
