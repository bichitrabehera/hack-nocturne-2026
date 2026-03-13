import pytest

from app.services import ai_service as svc
from app.services.ai_service import AIService


@pytest.mark.asyncio
async def test_analyze_message_with_url_model_result(monkeypatch):
    service = AIService()
    service._initialized = True
    service.text_model_loaded = False

    monkeypatch.setattr(
        svc,
        "analyze_url",
        lambda url: {
            "status": "scam",
            "message": "Malicious URL — 95% phishing confidence",
            "score": 90,
            "signals": ["model: phishing (95% confidence)"],
            "model_prob": 0.95,
        },
    )

    result = await service.analyze_message("hi", "http://bad.tk")

    assert result["scam_score"] >= 80
    assert result["risk_level"] in {"HIGH_RISK", "SCAM"}
    assert result["category"] == "phishing"
    assert result["flagged_urls"] == ["http://bad.tk"]


@pytest.mark.asyncio
async def test_analyze_message_no_url_uses_text_only(monkeypatch):
    service = AIService()
    service._initialized = True
    service.text_model_loaded = True

    monkeypatch.setattr(service, "_run_text_model", lambda text: (20.0, "legitimate", 0.7))

    result = await service.analyze_message("normal reminder", "")

    assert result["scam_score"] == 20
    assert result["risk_level"] == "LOW_RISK"
    assert result["flagged_urls"] == []


@pytest.mark.asyncio
async def test_keyword_boost_affects_score(monkeypatch):
    service = AIService()
    service._initialized = True
    service.text_model_loaded = False

    monkeypatch.setattr(
        svc,
        "analyze_url",
        lambda url: {
            "status": "safe",
            "message": "URL appears legitimate",
            "score": 0,
            "signals": [],
            "model_prob": 0.0,
        },
    )

    result = await service.analyze_message("urgent send bitcoin now", "http://example.com")

    assert result["scam_score"] >= 10


@pytest.mark.asyncio
async def test_trusted_domain_caps_score(monkeypatch):
    service = AIService()
    service._initialized = True
    service.text_model_loaded = True

    monkeypatch.setattr(
        svc,
        "analyze_url",
        lambda url: {
            "status": "safe",
            "message": "Trusted domain",
            "score": 0,
            "signals": ["trusted_domain"],
            "model_prob": 0.0,
        },
    )
    monkeypatch.setattr(service, "_run_text_model", lambda text: (92.0, "phishing", 0.9))

    result = await service.analyze_message("verify account", "https://www.netflix.com")

    assert result["scam_score"] <= 25
    assert result["risk_level"] in {"SAFE", "LOW_RISK"}
    assert result["category"] == "legitimate"


def test_risk_level_thresholds():
    service = AIService()
    assert service._risk_level(85) == "SCAM"
    assert service._risk_level(65) == "HIGH_RISK"
    assert service._risk_level(45) == "SUSPICIOUS"
    assert service._risk_level(25) == "LOW_RISK"
    assert service._risk_level(5) == "SAFE"
