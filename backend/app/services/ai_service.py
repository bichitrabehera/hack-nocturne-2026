"""
AIService - Core AI analysis logic.
Provides scam detection using rule-based analysis and an optional fine-tuned
transformer classifier when a local checkpoint is available.
"""

import asyncio
import logging
import math
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class AIService:
    """AI service for scam detection using rule-based analysis and ML models."""

    def __init__(self):
        self.model_loaded = False
        self._initialized = False
        self.model = None
        self.tokenizer = None
        self.model_source = "rules"
        self.base_model_name = os.getenv("SCAM_BASE_MODEL", "distilbert-base-uncased")
        self.model_dir = Path(os.getenv("SCAM_MODEL_DIR", Path("models") / "scam-detector"))
        self.max_length = int(os.getenv("SCAM_MODEL_MAX_LENGTH", "256"))
        self.ml_weight = float(os.getenv("SCAM_MODEL_WEIGHT", "0.45"))
        self.ml_threshold = float(os.getenv("SCAM_MODEL_THRESHOLD", "0.5"))

    async def initialize(self):
        """Initialize the AI service and load models if available."""
        if self._initialized:
            return

        try:
            await asyncio.to_thread(self._load_model_if_available)
        except Exception as e:
            logger.warning(f"Failed to load ML model, falling back to rules: {e}")
            self.model_loaded = False
            self.model = None
            self.tokenizer = None
            self.model_source = "rules"

        self._initialized = True

    async def analyze_message(self, text: str, url: str = "") -> Dict:
        """
        Analyze text and optional URL for scam indicators.

        Returns:
            {
                "scam_score": int (0-100),
                "risk_level": str ("SAFE" | "LOW_RISK" | "SUSPICIOUS" | "HIGH_RISK" | "SCAM"),
                "flagged_keywords": List[str],
                "flagged_urls": List[str],
                "explanation": str,
                "message_hash": str,
                "url_analysis": Dict,
                "ai_confidence": float,
                "timestamp": str
            }
        """
        if not self._initialized:
            await self.initialize()

        message_hash = f"0x{hash(text + url) & 0xffffffffffffffff:016x}"

        scam_keywords = [
            "urgent", "immediate action required", "account suspended",
            "verify now", "click here", "limited time", "act now",
            "congratulations", "winner", "free money", "guaranteed",
            "risk-free", "investment opportunity", "cryptocurrency",
            "bitcoin", "ethereum", "wallet", "private key"
        ]

        flagged_keywords = []
        text_lower = text.lower()
        for keyword in scam_keywords:
            if keyword in text_lower:
                flagged_keywords.append(keyword)

        flagged_urls = []
        url_analysis = {"status": "none", "message": "No URL provided"}

        if url:
            url_analysis = self._analyze_url(url)
            if url_analysis["status"] in ["scam", "suspicious", "caution"]:
                flagged_urls.append(url)

        keyword_score = min(len(flagged_keywords) * 15, 60)

        url_score = 0
        if url_analysis["status"] == "scam":
            url_score = 30
        elif url_analysis["status"] == "suspicious":
            url_score = 20
        elif url_analysis["status"] == "caution":
            url_score = 10

        urgency_patterns = [
            r"\bimmediately\b", r"\burgent\b", r"\blast chance\b",
            r"\blimited time\b", r"\bact now\b", r"\bdon't miss\b"
        ]
        urgency_score = sum(10 for pattern in urgency_patterns if re.search(pattern, text_lower))

        info_patterns = [
            r"\bpassword\b", r"\bssn\b", r"\bsocial security\b",
            r"\bcredit card\b", r"\bbank account\b", r"\bprivate key\b"
        ]
        info_score = sum(15 for pattern in info_patterns if re.search(pattern, text_lower))

        rule_score = min(keyword_score + url_score + urgency_score + info_score, 100)
        ml_score = None
        ml_confidence = None
        if self.model_loaded:
            try:
                ml_score, ml_confidence = await asyncio.to_thread(self._predict_ml_score, text)
            except Exception as e:
                logger.warning(f"ML inference failed, using rules only: {e}")

        if ml_score is not None:
            ml_weight = min(max(self.ml_weight, 0.0), 1.0)
            scam_score = min(round(((1 - ml_weight) * rule_score) + (ml_weight * ml_score)), 100)
        else:
            scam_score = rule_score

        if scam_score >= 80:
            risk_level = "SCAM"
        elif scam_score >= 60:
            risk_level = "HIGH_RISK"
        elif scam_score >= 40:
            risk_level = "SUSPICIOUS"
        elif scam_score >= 20:
            risk_level = "LOW_RISK"
        else:
            risk_level = "SAFE"

        explanation = self._generate_explanation(
            scam_score, risk_level, flagged_keywords, flagged_urls, url_analysis, ml_score
        )

        ai_confidence = ml_confidence if ml_confidence is not None else 0.6

        return {
            "scam_score": scam_score,
            "risk_level": risk_level,
            "flagged_keywords": flagged_keywords,
            "flagged_urls": flagged_urls,
            "explanation": explanation,
            "message_hash": message_hash,
            "url_analysis": url_analysis,
            "ai_confidence": ai_confidence,
            "timestamp": str(int(time.time())),
            "model_loaded": self.model_loaded,
            "model_source": self.model_source,
            "rule_score": rule_score,
            "ml_score": ml_score,
        }

    def _analyze_url(self, url: str) -> Dict:
        """Analyze a URL for suspicious indicators."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            suspicious_patterns = [
                r".*tk$", r".*ml$", r".*ga$",
                r".*\.bit$", r".*onion$",
                r".*secure.*login.*",
                r".*verify.*account.*",
                r".*paypal.*",
                r".*[0-9]{3,}.*",
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, domain):
                    return {
                        "status": "scam" if "paypal" in domain else "suspicious",
                        "message": f"Suspicious domain pattern detected: {domain}"
                    }

            if parsed.scheme != "https":
                return {
                    "status": "caution",
                    "message": "URL does not use HTTPS encryption"
                }

            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
            if any(shortener in domain for shortener in shorteners):
                return {
                    "status": "caution",
                    "message": "URL shortener detected - destination unknown"
                }

            return {
                "status": "safe",
                "message": "No obvious suspicious patterns detected"
            }

        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to analyze URL: {str(e)}"
            }

    def _generate_explanation(
        self,
        scam_score: int,
        risk_level: str,
        flagged_keywords: List[str],
        flagged_urls: List[str],
        url_analysis: Dict,
        ml_score: Optional[int],
    ) -> str:
        """Generate a human-readable explanation of the analysis."""
        if risk_level == "SAFE":
            if ml_score is not None:
                return "This message appears safe based on both the rules engine and the fine-tuned classifier."
            return "This message appears to be safe with no obvious scam indicators."

        explanation_parts = []

        if flagged_keywords:
            explanation_parts.append(f"Found suspicious keywords: {', '.join(flagged_keywords[:3])}")

        if flagged_urls:
            explanation_parts.append(f"Suspicious URL detected: {url_analysis['message']}")

        if ml_score is not None:
            explanation_parts.append(f"Classifier score: {ml_score}/100")

        if scam_score >= 80:
            explanation_parts.append("High probability this is a scam - do not engage!")
        elif scam_score >= 60:
            explanation_parts.append("High risk - exercise extreme caution")
        elif scam_score >= 40:
            explanation_parts.append("Suspicious - verify through official channels")

        return " | ".join(explanation_parts)

    def _load_model_if_available(self) -> None:
        """Load a fine-tuned classifier if a checkpoint directory is present."""
        if not self.model_dir.exists():
            logger.info(f"No fine-tuned model found at {self.model_dir}; using rule-based analysis")
            self.model_loaded = False
            self.model_source = "rules"
            return

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            logger.warning("transformers is not installed; using rule-based analysis")
            raise RuntimeError("transformers dependency is missing") from exc

        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.model_dir))
        self.model.eval()
        self.model_loaded = True
        self.model_source = str(self.model_dir)
        logger.info(f"AIService loaded fine-tuned model from {self.model_dir}")

    def _predict_ml_score(self, text: str) -> Tuple[int, float]:
        """Run local classifier inference and return scam score plus confidence."""
        if not self.model_loaded or self.model is None or self.tokenizer is None:
            raise RuntimeError("ML model is not loaded")

        inputs = self.tokenizer(
            text,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        outputs = self.model(**inputs)
        logits = outputs.logits.detach().cpu().tolist()[0]
        probabilities = self._softmax(logits)

        config = getattr(self.model, "config", None)
        label_map = getattr(config, "id2label", {}) or {}
        positive_index = self._positive_label_index(label_map)
        positive_probability = probabilities[positive_index]

        score = round(positive_probability * 100)
        confidence = max(probabilities)
        return score, round(confidence, 4)

    @staticmethod
    def _softmax(logits: List[float]) -> List[float]:
        if not logits:
            return [0.0, 1.0]
        max_logit = max(logits)
        exps = [math.exp(logit - max_logit) for logit in logits]
        total = sum(exps) or 1.0
        return [value / total for value in exps]

    @staticmethod
    def _positive_label_index(label_map: Dict[int, str]) -> int:
        for index, label in label_map.items():
            normalized = str(label).strip().lower()
            if normalized in {"scam", "fraud", "positive", "label_1"}:
                return int(index)
        return 1 if len(label_map) > 1 else 0

    async def cleanup(self):
        """Clean up resources and unload models."""
        if self.model_loaded:
            logger.info("Cleaning up AIService resources")
        self._initialized = False
        self.model_loaded = False
        self.model = None
        self.tokenizer = None
        self.model_source = "rules"
