"""
app/services/ai_service.py
Loads both models from disk — no downloads at runtime.

  models/url_model.pkl   — pirocheto/phishing-url-detection (~2MB)
  models/text_model/     — all-MiniLM-L6-v2 folder         (~90MB)
  models/anchors.pkl     — pre-computed anchor embeddings   (~5KB)

Run python download_models.py once on your laptop, commit models/ to git.
Cold start on Render: ~3s (disk load only, no network).
"""

import hashlib
import logging
import pickle
import re
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

from app.services.url_analyzer import (
    analyze_url,
    cleanup_url_analyzer,
    initialize_url_analyzer,
)

logger = logging.getLogger(__name__)

TEXT_MODEL_PATH = Path("models/text_model")
ANCHORS_PATH = Path("models/anchors.pkl")

BOOST_SIGNALS = [
    {
        "name": "personal_data_request",
        "patterns": [
            r"\bpassword\b", r"\bssn\b", r"\bcredit card\b",
            r"\bprivate key\b", r"\bseed phrase\b", r"\bpin\b", r"\bcvv\b",
        ],
        "boost": 15,
    },
    {
        "name": "urgent_threat",
        "patterns": [
            r"\bimmediately\b", r"\burgent\b", r"\bact now\b",
            r"\b(suspended|banned|terminated|deleted)\b",
            r"\bor (you will|your account will|face)\b",
        ],
        "boost": 10,
    },
    {
        "name": "money_transfer",
        "patterns": [
            r"\bsend (money|bitcoin|eth|usdt|gift card)\b",
            r"\bwire transfer\b", r"\bdouble your\b",
            r"\bguaranteed profit\b", r"\bget rich\b",
        ],
        "boost": 12,
    },
]


class AIService:

    def __init__(self):
        self.text_model = None
        self.text_model_loaded = False
        self._initialized = False
        self._scam_embeddings: Dict[str, np.ndarray] = {}
        self._legit_embedding: np.ndarray | None = None

    async def initialize(self):
        if self._initialized:
            return

        initialize_url_analyzer()
        self._load_text_model()
        self._initialized = True

    def _load_text_model(self):
        try:
            if not TEXT_MODEL_PATH.exists():
                raise FileNotFoundError(
                    f"{TEXT_MODEL_PATH} not found. "
                    "Run python download_models.py first."
                )
            if not ANCHORS_PATH.exists():
                raise FileNotFoundError(
                    f"{ANCHORS_PATH} not found. "
                    "Run python download_models.py first."
                )

            from sentence_transformers import SentenceTransformer

            logger.info(f"Loading text model from {TEXT_MODEL_PATH} ...")
            self.text_model = SentenceTransformer(str(TEXT_MODEL_PATH))

            logger.info(f"Loading anchor embeddings from {ANCHORS_PATH} ...")
            with open(ANCHORS_PATH, "rb") as f:
                anchors = pickle.load(f)

            self._scam_embeddings = anchors["scam_embeddings"]
            self._legit_embedding = anchors["legit_embedding"]

            self.text_model_loaded = True
            logger.info(
                f"Text model ready — "
                f"{len(self._scam_embeddings)} scam categories loaded from disk"
            )

        except Exception as e:
            logger.warning(f"Text model load failed: {e}")
            self.text_model_loaded = False

    async def cleanup(self):
        cleanup_url_analyzer()
        if self.text_model is not None:
            del self.text_model
            self.text_model = None
        self._scam_embeddings = {}
        self._legit_embedding = None
        self.text_model_loaded = False
        self._initialized = False
        logger.info("AIService cleaned up")

    async def analyze_message(self, text: str, url: str = "") -> Dict:
        if not self._initialized:
            await self.initialize()

        url_result = analyze_url(url) if url else {
            "status": "none",
            "message": "No URL provided",
            "score": 0,
            "signals": [],
            "model_prob": 0.0,
        }
        url_score = url_result["score"]
        url_phish_prob = url_result.get("model_prob", 0.0)

        text_score, text_cat, text_conf = 0.0, "other", 0.0
        if self.text_model_loaded and text.strip():
            text_score, text_cat, text_conf = self._run_text_model(text)

        boost = min(self._keyword_boost(text), 20)

        if url:
            raw = (text_score * 0.50) + (url_score * 0.50)
        else:
            raw = text_score

        raw = min(100.0, raw + boost)
        final_score = int(max(0.0, min(100.0, raw)))

        if url_phish_prob >= 0.90:
            final_score = max(final_score, 80)
        elif url_phish_prob >= 0.75:
            final_score = max(final_score, 65)
        elif url_phish_prob >= 0.55:
            final_score = max(final_score, 45)

        trusted_domain = "trusted_domain" in url_result.get("signals", [])
        if trusted_domain and boost == 0:
            final_score = min(final_score, 25)

        risk_level = self._risk_level(final_score)

        if trusted_domain and final_score < 30:
            category = "legitimate"
        elif url_phish_prob >= 0.75:
            category = "phishing"
        elif text_cat not in ("other", "legitimate") and text_conf >= 0.35:
            category = text_cat
        elif final_score < 30:
            category = "legitimate"
        else:
            category = "other"

        flagged_keywords = self._extract_keywords(text)
        flagged_urls = [url] if url and url_result["status"] not in ("none", "safe") else []

        confs = [c for c in [text_conf, url_phish_prob] if c > 0]
        ai_confidence = round(sum(confs) / len(confs), 3) if confs else 0.0

        return {
            "scam_score": final_score,
            "risk_level": risk_level,
            "flagged_keywords": flagged_keywords,
            "flagged_urls": flagged_urls,
            "explanation": self._explain(final_score, risk_level, flagged_keywords, url_result),
            "message_hash": self._hash(text, url),
            "url_analysis": url_result,
            "ai_confidence": ai_confidence,
            "category": category,
            "timestamp": str(int(time.time())),
        }

    def _run_text_model(self, text: str) -> Tuple[float, str, float]:
        try:
            emb = self.text_model.encode([text[:512]], convert_to_numpy=True)[0]

            best_sim, best_cat = -1.0, "other"
            for cat, anchor_emb in self._scam_embeddings.items():
                sim = self._cosine(emb, anchor_emb)
                if sim > best_sim:
                    best_sim, best_cat = sim, cat

            legit_sim = self._cosine(emb, self._legit_embedding)
            advantage = float(best_sim) - float(legit_sim)
            score = max(0.0, min(1.0, advantage + 0.5)) * 100
            confidence = max(0.0, min(1.0, float(best_sim)))

            if legit_sim >= best_sim:
                best_cat = "legitimate"

            return float(score), best_cat, confidence

        except Exception as e:
            logger.warning(f"Text model inference failed: {e}")
            return 0.0, "other", 0.0

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        d = np.linalg.norm(a) * np.linalg.norm(b)
        return float(np.dot(a, b) / d) if d else 0.0

    def _keyword_boost(self, text: str) -> float:
        tl = text.lower()
        return sum(
            sig["boost"]
            for sig in BOOST_SIGNALS
            if any(re.search(p, tl) for p in sig["patterns"])
        )

    def _extract_keywords(self, text: str) -> List[str]:
        tl, found = text.lower(), []
        for sig in BOOST_SIGNALS:
            for p in sig["patterns"]:
                m = re.search(p, tl)
                if m:
                    found.append(m.group(0))
        return list(dict.fromkeys(found))[:8]

    def _risk_level(self, s: int) -> str:
        if s >= 80:
            return "SCAM"
        if s >= 60:
            return "HIGH_RISK"
        if s >= 40:
            return "SUSPICIOUS"
        if s >= 20:
            return "LOW_RISK"
        return "SAFE"

    def _explain(self, score, risk, keywords, url_result) -> str:
        level_msg = {
            "SCAM": "High probability scam — do not engage",
            "HIGH_RISK": "High risk — exercise extreme caution",
            "SUSPICIOUS": "Suspicious — verify through official channels",
            "LOW_RISK": "Low risk — minor suspicious elements",
            "SAFE": "Appears legitimate — no major red flags",
        }
        parts = [level_msg.get(risk, "")]
        if url_result.get("status") not in ("none", "safe"):
            parts.append(f"URL: {url_result.get('message', '')}")
        if keywords:
            parts.append(f"Keywords: {', '.join(keywords[:3])}")
        return " | ".join(p for p in parts if p)

    def _hash(self, text: str, url: str = "") -> str:
        return "0x" + hashlib.sha256(f"{text}{url}".encode()).hexdigest()
