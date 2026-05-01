# LabMe - Zero-Day Phishing Prevention Framework

LabMe is a comprehensive zero-day phishing prevention framework that leverages machine learning and computer vision to detect and block malicious websites in real-time.

## System Architecture

The project consists of two main components:
1. **Chrome Extension (MV3)**: Captures URL, DOM text, and screenshots to be analyzed.
2. **FastAPI Backend**: Processes the data using various models to compute a final trust score.

### Chrome Extension
- Built using Chrome Manifest V3.
- Extracts DOM content and takes screenshots of web pages.
- Communicates with the FastAPI backend to verify the safety of a page.
- Provides a warning page if a site is determined to be a phishing threat.

### FastAPI Backend
- **NLP Model**: Utilizes DistilBERT to analyze text content for phishing indicators.
- **Visual Model**: Uses MobileNetV2 to detect brand similarity and visual spoofing.
- **Explainable AI (XAI)**: Employs LIME to provide transparency into the model's predictions.
- **Utilities**: Features URL analysis, domain age verification, and WHOIS checks.
- **Database**: Connects to MongoDB Atlas for logging threats and statistics.

## Project Structure

```text
LabMe/
├── extension/          # Chrome MV3 Extension
│   ├── manifest.json
│   ├── popup/
│   ├── background/
│   ├── content/
│   ├── warning/
│   └── options/
└── backend/            # FastAPI Python Backend
    ├── app.py
    ├── requirements.txt
    ├── models/         # DistilBERT, MobileNetV2, LIME
    ├── utils/          # URL analyzer, WHOIS checker
    └── database/       # MongoDB connection
```

## Getting Started

### Backend Setup
1. Navigate to the `backend` directory.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the FastAPI server: `uvicorn app:app --reload`

### Extension Setup
1. Open Google Chrome and go to `chrome://extensions/`.
2. Enable "Developer mode" in the top right.
3. Click "Load unpacked" and select the `extension` folder from this repository.
