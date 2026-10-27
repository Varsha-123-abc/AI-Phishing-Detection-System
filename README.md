# AI-Powered Phishing Detection & Email Threat Analysis System

A defensive cybersecurity project that analyzes suspicious email messages, extracts URLs, identifies threat indicators, and supports SOC investigations.

## Features

- Offline email parsing and header inspection
- Detection of suspicious email indicators, including sender and Reply-To domain mismatches
- URL extraction and suspicious URL pattern analysis
- Evidence-based heuristic risk scoring and severity classification
- Experimental phishing classification using TF-IDF and Logistic Regression
- Flask dashboard displaying risk scores, severity counts, URL and attachment counts, and evidence indicators
- Automated tests for email parsing, URL analysis, machine-learning prediction, threat scoring, and dashboard behavior

## Technology Stack

- Python
- Flask
- scikit-learn
- TF-IDF and Logistic Regression
- joblib
- HTML and CSS
- Python unittest

## Project Structure

```text
AI-Phishing-Detection-System/
├── app/
│   ├── routes/
│   ├── services/
│   ├── static/css/
│   └── templates/
├── core/
│   ├── email_analysis/
│   ├── url_analysis/
│   ├── threat_scoring/
│   └── ml/
├── datasets/
│   └── demo_emails.csv
├── reports/
│   └── ml/
├── tests/
├── run.py
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10 or later
- pip

Developed and tested with Python 3.13.

## Installation

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install Flask scikit-learn joblib
```

## Train the Demonstration Model

From the project root, run:

```bash
python -m core.ml.train_model
```

This creates the model and evaluation report under `reports/ml/`. These generated artifacts are excluded from Git, so train the model locally before using the machine-learning prediction feature.

## Run the Dashboard

Start the application:

```bash
python run.py
```

Open http://127.0.0.1:5000 in your browser. The development server listens on localhost. Stop it with `Ctrl+C`.

Paste an email message into the dashboard to inspect its available headers, URLs, indicators, and risk assessment.

## Run Tests

```bash
python -m unittest discover -v
```

## Machine-Learning Limitations

The demonstration dataset contains only 12 hand-written email samples. The evaluation split contains just 3 samples, making its metrics highly unstable.

Predicted labels and class probabilities are experimental outputs. They are not calibrated threat probabilities and must not be treated as proof that an email is safe or malicious. A larger, representative, independently labeled dataset and thorough validation are necessary before operational use.

## Security and Responsible Use

- Treat suspicious email content as untrusted data.
- Do not execute attachments or automatically open suspicious links.
- Treat automated findings as indicators that require investigation.
- Keep the application local during development.
- Configure secrets and production security settings before deployment.
- Analyze only messages and systems you are authorized to examine.

## Current Status

The project includes offline email parsing, URL analysis, heuristic risk scoring, an experimental machine-learning classifier, a Flask dashboard, and automated tests.

Persistent incident history, investigation notes, and PDF/CSV report exports are not documented as implemented features in this version.
