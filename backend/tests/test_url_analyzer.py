from app.services.url_analyzer import URLAnalyzer


class _Model:
    def __init__(self, phish_prob):
        self.phish_prob = phish_prob

    def predict_proba(self, _):
        return [[1 - self.phish_prob, self.phish_prob]]


def test_trusted_domain_is_safe():
    analyzer = URLAnalyzer()
    analyzer.model_loaded = True
    analyzer.model = _Model(0.95)

    result = analyzer.analyze("https://www.netflix.com/login")

    assert result["status"] == "safe"
    assert result["score"] == 0
    assert "trusted_domain" in result["signals"]


def test_low_probability_maps_to_safe_score_zero():
    analyzer = URLAnalyzer()
    analyzer.model_loaded = True
    analyzer.model = _Model(0.28)

    result = analyzer.analyze("https://example.com")

    assert result["status"] == "safe"
    assert result["score"] == 0
    assert result["model_prob"] == 0.28


def test_high_probability_maps_to_scam():
    analyzer = URLAnalyzer()
    analyzer.model_loaded = True
    analyzer.model = _Model(0.95)

    result = analyzer.analyze("https://secure-wallet-verification.weeblysite.com/login")

    assert result["status"] == "scam"
    assert result["score"] >= 80
