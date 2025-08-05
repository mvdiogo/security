from flask import Flask, render_template, redirect, url_for
from rogue_ap_core import RogueAPDetector

app = Flask(__name__)
detector = RogueAPDetector(interface="wlan0mon")

@app.route("/")
def index():
    aps = detector.get_all_access_points()
    return render_template("index.html", aps=aps)

@app.route("/rogue")
def rogue():
    rogues = detector.get_rogue_detections()
    return render_template("rogue.html", rogues=rogues)

@app.route("/scan")
def scan():
    aps = detector.scan_access_points()
    detector.record_scan_results(aps)
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
