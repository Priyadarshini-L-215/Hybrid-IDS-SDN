"""
Anti-Gravity IDS – Flask Backend
  • /api/alerts        – real-time ML-classified Suricata flow data
  • /api/nmap/profiles – list available scan profiles
  • /api/nmap/scan     – run an nmap scan (POST)
  • /api/nmap/analyse  – run Gemini AI analysis on nmap output (POST)
"""

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from integration import tail_eve_json
from nmap_runner import run_nmap, analyse_with_gemini, SCAN_PROFILES, NMAP_BIN
import threading, time

app = Flask(__name__)
CORS(app)   # Allow Vite dev-server (port 5173) to call Flask (port 5000)

_cache_lock = threading.Lock()
_cache = {"alerts": [], "last_updated": "never"}

# ------------------------------------------------------------------ #
#  Background IDS refresh                                              #
# ------------------------------------------------------------------ #
def background_refresh():
    """Refresh ML predictions every 3 seconds."""
    while True:
        fresh_alerts = tail_eve_json(50)
        with _cache_lock:
            _cache["alerts"]       = fresh_alerts
            _cache["last_updated"] = time.strftime("%H:%M:%S")
        time.sleep(1)

threading.Thread(target=background_refresh, daemon=True).start()


# ------------------------------------------------------------------ #
#  IDS / Alert routes                                                  #
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    with _cache_lock:
        return jsonify(_cache)

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return summary statistics for the dashboard stat cards."""
    with _cache_lock:
        alerts = _cache["alerts"]
        total   = len(alerts)
        attacks = sum(1 for a in alerts if a.get("prediction") == "Attack")
        normal  = total - attacks
        attack_pct = round((attacks / total) * 100, 1) if total > 0 else 0.0
        return jsonify({
            "total": total,
            "attacks": attacks,
            "normal": normal,
            "attack_pct": attack_pct,
            "last_updated": _cache["last_updated"],
        })

@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    """Clear the accumulated alerts in the cache."""
    with _cache_lock:
        _cache["alerts"] = []
        _cache["last_updated"] = time.strftime("%H:%M:%S")
    open(r"D:\projects\FYP\data\logs\eve.json", "w").close() # truncate file so they don't immediately reload
    return jsonify({"success": True})


# ------------------------------------------------------------------ #
#  Nmap Attack-Lab routes                                              #
# ------------------------------------------------------------------ #
@app.route("/api/nmap/check")
def api_nmap_check():
    """Quick check: is nmap installed and callable?"""
    import shutil, subprocess
    found = shutil.which(NMAP_BIN) is not None
    version = ""
    if found:
        try:
            r = subprocess.run([NMAP_BIN, "--version"], capture_output=True, text=True, timeout=5)
            version = r.stdout.strip().split("\n")[0]
        except Exception:
            pass
    return jsonify({"available": found, "version": version,
                    "install_url": "https://nmap.org/download.html"})


@app.route("/api/nmap/profiles")
def api_nmap_profiles():
    """Return all available scan profiles for the UI dropdown."""
    profiles = [
        {
            "id":     pid,
            "label":  p["label"],
            "danger": p["danger"],
            "flags":  p["flags"],
        }
        for pid, p in SCAN_PROFILES.items()
    ]
    return jsonify({"profiles": profiles})


@app.route("/api/nmap/scan", methods=["POST"])
def api_nmap_scan():
    """
    Body (JSON):
      { "target": "192.168.1.1", "profile": "quick", "extra_flags": "" }
    """
    body        = request.get_json(force=True, silent=True) or {}
    target      = (body.get("target", "") or "").strip()
    profile     = (body.get("profile", "quick") or "quick").strip()
    extra_flags = (body.get("extra_flags", "") or "").strip()

    if not target:
        return jsonify({"success": False, "error": "target is required"}), 400

    result = run_nmap(target, profile, extra_flags or None)
    return jsonify(result)


@app.route("/api/nmap/analyse", methods=["POST"])
def api_nmap_analyse():
    """
    Body (JSON):
      { "nmap_output": "...", "target": "192.168.1.1" }
    Calls Gemini CLI and returns AI analysis.
    """
    body        = request.get_json(force=True, silent=True) or {}
    nmap_output = (body.get("nmap_output", "") or "").strip()
    target      = (body.get("target", "unknown") or "unknown").strip()

    if not nmap_output:
        return jsonify({"success": False, "error": "nmap_output is required"}), 400

    analysis = analyse_with_gemini(nmap_output, target)
    return jsonify({"success": True, "analysis": analysis})


# ------------------------------------------------------------------ #
#  Entry point                                                         #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)