import os
import sqlite3
from pathlib import Path

from web3 import Web3


DB_PATH = Path(os.getenv("SCAMSHIELD_DB_PATH") or Path(__file__).with_name("scam_reports.db"))


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS url_hashes (
                hash TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def hash_url(url: str) -> str:
    normalized = url.strip()
    if not normalized:
        raise ValueError("url must not be empty")
    return "0x" + Web3.keccak(text=normalized).hex()


def save_url_hash(url: str) -> str:
    normalized = url.strip()
    hash_hex = hash_url(normalized)

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO url_hashes(hash, url)
            VALUES(?, ?)
            ON CONFLICT(hash) DO UPDATE SET url = excluded.url
            """,
            (hash_hex, normalized),
        )

    return hash_hex


def lookup_url(hash_hex: str) -> str | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT url FROM url_hashes WHERE hash = ?",
            (hash_hex,),
        ).fetchone()

    return row["url"] if row else None


def enrich_report(report: dict | None) -> dict | None:
    if not report:
        return report

    enriched = dict(report)
    enriched["url"] = lookup_url(report.get("textHash", ""))
    return enriched


def enrich_reports(reports: list[dict]) -> list[dict]:
    if not reports:
        return []

    hashes = [report.get("textHash") for report in reports if report.get("textHash")]
    if not hashes:
        return [dict(report, url=None) for report in reports]

    placeholders = ",".join("?" for _ in hashes)
    with _connect() as connection:
        rows = connection.execute(
            f"SELECT hash, url FROM url_hashes WHERE hash IN ({placeholders})",
            hashes,
        ).fetchall()

    urls_by_hash = {row["hash"]: row["url"] for row in rows}
    return [dict(report, url=urls_by_hash.get(report.get("textHash"))) for report in reports]