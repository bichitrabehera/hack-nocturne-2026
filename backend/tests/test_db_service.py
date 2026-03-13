from pathlib import Path

import db_service


def test_save_lookup_and_enrich_reports(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")

    db_service.init_db()
    hash_hex = db_service.save_url_hash("https://bad.example")

    assert db_service.lookup_url(hash_hex) == "https://bad.example"
    assert db_service.enrich_report({"textHash": hash_hex, "riskScore": 90}) == {
        "textHash": hash_hex,
        "riskScore": 90,
        "url": "https://bad.example",
    }


def test_enrich_reports_handles_missing_urls(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(db_service, "DB_PATH", tmp_path / "reports.db")

    db_service.init_db()
    first_hash = db_service.save_url_hash("https://bad.example")

    reports = db_service.enrich_reports(
        [
            {"textHash": first_hash, "riskScore": 99},
            {"textHash": "0xmissing", "riskScore": 1},
        ]
    )

    assert reports == [
        {"textHash": first_hash, "riskScore": 99, "url": "https://bad.example"},
        {"textHash": "0xmissing", "riskScore": 1, "url": None},
    ]