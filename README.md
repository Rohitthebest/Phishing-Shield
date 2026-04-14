# Phishing Shield

Phishing Shield is a small Flask website that uses a machine learning model to
estimate whether a URL looks like a phishing attempt.

## What it does

- Accepts a URL in the browser
- Extracts lexical features from the URL
- Runs a logistic regression classifier trained on bundled examples
- Returns a phishing probability, risk level, and the strongest warning signals

## Tech stack

- Python
- Flask
- scikit-learn
- HTML, CSS, and vanilla JavaScript

## Run locally

1. Create and activate a virtual environment
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the app:

```bash
python app.py
```

4. Open `http://127.0.0.1:5000`

## Chrome extension

To automatically check the website you open in Chrome:

1. Start the Flask app with `python app.py`
2. Open `chrome://extensions/`
3. Turn on `Developer mode`
4. Click `Load unpacked`
5. Select:

```text
browser_extension
```

The extension will show:

- `SAFE` for websites that look safe
- `PHISH` for phishing-style websites
- `BAD` for invalid or non-existing domains
- `OFF` if the Flask app is not running

## Optional Groq review

To add an LLM second opinion for full manual scans, set:

```bash
GROQ_API_KEY=your_api_key
```

You can also override the default model with:

```bash
GROQ_MODEL=llama-3.1-8b-instant
```

## Notes

This is a demo classifier. It uses URL structure only, so it should be treated
as an educational screening tool rather than a production security control.
