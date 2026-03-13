import pytest

from app.services.ai_service import AIService


@pytest.mark.asyncio
async def test_initialize_without_model_dir_uses_rules(tmp_path):
    service = AIService()
    service.model_dir = tmp_path / "missing-model"

    await service.initialize()

    assert service.model_loaded is False
    assert service.model_source == "rules"


@pytest.mark.asyncio
async def test_analyze_message_uses_rule_score_when_model_unavailable():
    service = AIService()
    await service.initialize()

    result = await service.analyze_message(
        "Urgent, verify now and share your private key to claim free money",
        "http://bad.tk",
    )

    assert result["scam_score"] >= 70
    assert result["risk_level"] in {"HIGH_RISK", "SCAM"}
    assert result["rule_score"] == result["scam_score"]
    assert result["ml_score"] is None


@pytest.mark.asyncio
async def test_analyze_message_blends_ml_score(monkeypatch):
    service = AIService()
    service._initialized = True
    service.model_loaded = True
    service.ml_weight = 0.5
    service.model = object()
    service.tokenizer = object()
    monkeypatch.setattr(service, "_predict_ml_score", lambda text: (90, 0.93))

    result = await service.analyze_message("hello there", "")

    assert result["rule_score"] == 0
    assert result["ml_score"] == 90
    assert result["scam_score"] == 45
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["ai_confidence"] == 0.93


def test_positive_label_index_prefers_scam_labels():
    assert AIService._positive_label_index({0: "legitimate", 1: "scam"}) == 1
    assert AIService._positive_label_index({0: "safe", 1: "fraud"}) == 1
    assert AIService._positive_label_index({0: "only"}) == 0
