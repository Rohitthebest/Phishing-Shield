from flask import Flask, jsonify, render_template, request

from phishing_model import PhishingURLDetector


app = Flask(__name__)
detector = PhishingURLDetector()


def _read_url():
    payload = request.get_json(silent=True) or request.form
    return (payload.get("url") or "").strip()


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/predict")
def predict():
    url = _read_url()

    if not url:
        return jsonify({"error": "Please enter a URL to analyze."}), 400

    prediction = detector.predict(url)
    return jsonify(prediction)


@app.post("/predict/realtime")
def predict_realtime():
    url = _read_url()
    prediction = detector.predict_realtime(url)
    return jsonify(prediction)


if __name__ == "__main__":
    app.run(debug=True)
