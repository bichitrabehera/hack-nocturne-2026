"""
app/services/url_analyzer.py
Loads url_model.pkl from disk — no HuggingFace download at runtime.
"""

import logging
import pickle
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

MODEL_PATH = Path("models/url_model.pkl")
TRUSTED_DOMAINS = {
    "netflix.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "github.com",
    "openai.com",
}


def _is_trusted_domain(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return any(host == domain or host.endswith(f".{domain}") for domain in TRUSTED_DOMAINS)


def _prob_to_score(prob: float) -> int:
    if prob < 0.30:
        return int((prob / 0.30) * 25)
    if prob < 0.70:
        return int(25 + ((prob - 0.30) / 0.40) * 40)
    return int(65 + ((prob - 0.70) / 0.30) * 35)


def _score_to_status(score: int) -> str:
    if score >= 80:
        return "scam"
    if score >= 65:
        return "high_risk"
    if score >= 45:
        return "suspicious"
    if score >= 30:
        return "caution"
    return "safe"


class URLAnalyzer:

    def __init__(self):
        self.model = None
        self.model_loaded = False

    def initialize(self):
        if self.model_loaded:
            return
        try:
            if not MODEL_PATH.exists():
                raise FileNotFoundError(
                    f"{MODEL_PATH} not found. "
                    "Run python download_models.py first."
                )
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            self.model_loaded = True
            logger.info(f"URL model loaded from {MODEL_PATH}")
        except Exception as e:
            logger.warning(f"URL model load failed: {e}")
            self.model_loaded = False

    def analyze(self, url: str) -> Dict:
        if not url or not url.strip():
            return {
                "status": "none",
                "message": "No URL provided",
                "score": 0,
                "signals": [],
                "model_prob": 0.0,
            }

        normalized = url.strip()
        if not normalized.startswith(("http://", "https://")):
            normalized = "http://" + normalized

        if _is_trusted_domain(normalized):
            return {
                "status": "safe",
                "message": "Trusted domain",
                "score": 0,
                "signals": ["trusted_domain"],
                "model_prob": 0.0,
            }

        if not self.model_loaded:
            return {
                "status": "caution",
                "message": "URL model unavailable — manual review recommended",
                "score": 20,
                "signals": ["model_unavailable"],
                "model_prob": 0.0,
            }
        try:
            probs = self.model.predict_proba([normalized])[0]
            phish_prob = float(probs[1])
            score = 0 if phish_prob < 0.35 else _prob_to_score(phish_prob)
            status = _score_to_status(score)
            label = "phishing" if phish_prob >= 0.5 else "legitimate"
            message = (
                f"Malicious URL — {phish_prob*100:.0f}% phishing confidence" if score >= 75 else
                f"High-risk URL — {phish_prob*100:.0f}% phishing confidence" if score >= 55 else
                f"Suspicious URL — {phish_prob*100:.0f}% phishing confidence" if score >= 35 else
                f"Caution — {phish_prob*100:.0f}% phishing confidence" if score >= 15 else
                f"URL appears legitimate — {phish_prob*100:.0f}% phishing confidence"
            )
            return {
                "status": status,
                "message": message,
                "score": score,
                "signals": [f"model: {label} ({phish_prob*100:.0f}% confidence)"],
                "model_prob": round(phish_prob, 4),
            }
        except Exception as e:
            logger.error(f"URL inference error: {e}")
            return {
                "status": "caution",
                "message": "URL analysis error",
                "score": 25,
                "signals": ["inference_error"],
                "model_prob": 0.0,
            }

    def cleanup(self):
        if self.model is not None:
            del self.model
        self.model = None
        self.model_loaded = False


_analyzer = URLAnalyzer()


def initialize_url_analyzer():
    _analyzer.initialize()


def analyze_url(url: str) -> Dict:
    return _analyzer.analyze(url)


def cleanup_url_analyzer():
    _analyzer.cleanup()
