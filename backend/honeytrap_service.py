"""
honeytrap_bot.py
Honeytrap Scammer Interaction Bot — upgraded version.

Key improvements over v1:
  1. AI-driven victim persona that actually sends messages
  2. Form filling + POST destination harvesting
  3. Multi-stage Telegram / chat widget interaction loop
  4. Scammer response analysis — extracts new wallets/IDs from replies
  5. Screenshot evidence at each stage
  6. Structured ScamIntelligence report at the end
"""

import binascii
import re
import time
import json
import base64
import hashlib
import logging
import subprocess
import sys
from typing import Any
from urllib.parse import unquote, urlparse, urljoin

import requests

from app.services.url_analyzer import analyze_url
from pg_db_service import get_honeytrap_network_stats

logger = logging.getLogger(__name__)

PLAYWRIGHT_NAV_TIMEOUT_MS = 12_000
PLAYWRIGHT_POST_LOAD_WAIT_MS = 800
PLAYWRIGHT_DEEP_SCROLL_STEPS = 4
PLAYWRIGHT_DEEP_SCROLL_WAIT_MS = 450
PLAYWRIGHT_INTERACTION_MAX_CLICKS = 4
CHAT_MAX_EXCHANGES = 2
CHAT_REPLY_WAIT_MS = 1_200
REQUEST_CONNECT_TIMEOUT_S = 4
REQUEST_READ_TIMEOUT_S = 6
MAX_REQUEST_CANDIDATES = 2
PLAYWRIGHT_INSTALL_TIMEOUT_S = 180

# ─── Regexes ──────────────────────────────────────────────────────────────────

ETH_REGEX      = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_REGEX      = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
TRON_REGEX     = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
TELEGRAM_LINK_REGEX = re.compile(r"(?:t\.me/|telegram\.me/)([A-Za-z][A-Za-z0-9_]{4,31})", re.IGNORECASE)
TELEGRAM_AT_REGEX = re.compile(r"(?:^|[^\w])@([A-Za-z][A-Za-z0-9_]{4,31})(?=\b)")
EMAIL_REGEX    = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_REGEX    = re.compile(r"\+?[1-9]\d{7,14}")
WHATSAPP_REGEX = re.compile(r"(?:wa\.me/|whatsapp\.com/send\?phone=)(\d{7,15})")

TELEGRAM_NOISE_TERMS = {
    "keyframes", "supports", "media", "hover", "before", "after", "root", "webkit",
}

BTC_LEGACY_REGEX = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BTC_BECH32_REGEX = re.compile(r"\bbc1[ac-hj-np-z02-9]{11,71}\b", re.IGNORECASE)
WALLET_CONTEXT_HINTS = (
    "wallet", "address", "deposit", "send", "receive", "payment", "transfer", "btc", "bitcoin", "eth", "usdt", "tron",
)

SUSPICIOUS_TLDS = {
    ".tk", ".xyz", ".ru", ".top", ".click", ".gq", ".cf", ".ml", ".ga", ".pw",
}

SUSPICIOUS_URL_HINTS: dict[str, int] = {
    "airdrop": 12, "claim": 10, "wallet": 10, "verify": 9,
    "secure": 8, "connect": 8, "bonus": 8, "reward": 8,
    "whitelist": 7, "presale": 7, "seed": 14, "mnemonic": 16,
    "private-key": 16, "passphrase": 14,
}

PAYMENT_LINE_HINTS = (
    "send", "transfer", "deposit", "pay", "wallet", "verify",
    "fee", "eth", "usdt", "btc", "address", "claim",
)

NOTABLE_TEXT_HINTS = (
    "connect wallet", "claim reward", "claim", "approve", "verify", "bonus", "airdrop", "lottery", "draw",
    "hourly", "ranking", "pool", "reward", "send", "deposit", "wallet", "address",
)

PHONE_CONTEXT_HINTS = (
    "phone", "whatsapp", "contact", "call", "telegram", "support", "helpdesk", "reach us", "customer care",
)

# ─── Personas ─────────────────────────────────────────────────────────────────

DEFAULT_PERSONAS = {
    "elderly_victim": {
        "name": "Margaret Chen",
        "backstory": "Retired teacher, 67. Recently widowed. Heard about crypto from her son. Has $15,000 in savings she wants to invest. Not very tech-savvy.",
        "messages": [
            "Hello, I saw your website. I am interested in investing. How does this work?",
            "My son told me about crypto. I have some savings I would like to invest safely.",
            "How much do I need to start? I want to be careful with my money.",
            "OK that sounds good. What wallet do I send to? I want to do a small test first.",
            "I can do $500 first to see how it works. What is the address?",
        ],
        "responses_to": {
            "fee": "I did not know there would be a fee. How much exactly?",
            "verify": "How do I verify? I am not very good with technology.",
            "profit": "That sounds wonderful! My friend made good money too. OK I will try.",
            "urgent": "Oh dear, I don't want to miss out. Let me get my card.",
        }
    },
    "crypto_curious": {
        "name": "Raj Patel",
        "backstory": "28-year-old software engineer. Saw the site on Twitter. Has disposable income. Skeptical but curious.",
        "messages": [
            "Hey, saw this on Twitter. What's the ROI on this?",
            "What's the minimum? Any lock-up period?",
            "Seems legit. Where do I send the funds?",
            "What's the contract address? I want to verify on Etherscan.",
            "OK sending 0.1 ETH. What wallet?",
        ],
        "responses_to": {
            "fee": "Why is there a fee? That's a red flag.",
            "verify": "Sure I can verify. What do I need to do?",
            "profit": "200% returns? That's wild. How is that sustainable?",
        }
    },
}

AUTO_PERSONA_ALIASES = {
    "",
    "auto",
    "dynamic",
    "adaptive",
    "default",
    "i'm new to crypto and want to claim the airdrop",
}


def _is_auto_persona_request(persona_key: str, persona_prompt: str) -> bool:
    requested = (persona_prompt or persona_key or "").strip().lower()
    return requested in AUTO_PERSONA_ALIASES


def _select_persona_for_target(url: str, domain: str) -> tuple[str, str, list[str]]:
    ll = f"{url}\n{domain}".lower()
    reasons: list[str] = []

    if any(k in ll for k in ("airdrop", "claim", "reward", "bonus", "lottery", "draw", "winner")):
        reasons.append("promo_lure_terms")
        return "crypto_curious", "User chasing rewards; asks payout and wallet destination questions.", reasons

    if any(k in ll for k in ("connect", "wallet", "approve", "swap", "stake", "mint")):
        reasons.append("wallet_action_terms")
        return "crypto_curious", "User is wallet-active and asks contract/address validation before sending funds.", reasons

    if any(k in ll for k in ("login", "verify", "secure", "account", "password", "recovery")):
        reasons.append("credential_lure_terms")
        return "elderly_victim", "User is confused by account verification flow and asks for safe step-by-step guidance.", reasons

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("suspicious_tld")
        return "elderly_victim", "User is cautious but vulnerable, asks basic trust and payment questions.", reasons

    reasons.append("default_profile")
    return "crypto_curious", "User is curious and probes minimum deposit, ROI, and receiving wallet.", reasons

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for item in items:
        n = item.strip()
        if n and n.lower() not in seen:
            seen.add(n.lower()); out.append(n)
    return out


def _extract_all_indicators(text: str, links: list[str]) -> dict[str, list[str]]:
    decoded_text = unquote(text or "")
    full = f"{decoded_text}\n" + "\n".join(links)
    wallets  = _extract_wallets(full)
    telegram = _extract_telegram_ids(full)
    emails   = EMAIL_REGEX.findall(full)
    phones   = _extract_phone_contacts(full)
    payments = _extract_payment_instructions(full)
    behavior = _extract_behavior_signals(full)
    return {
        "wallets":             _dedupe(wallets),
        "telegramIds":         _dedupe(telegram),
        "emails":              _dedupe(emails),
        "phones":              _dedupe(phones),
        "paymentInstructions": payments,
        "behaviorSignals":     _dedupe(behavior),
    }


def _extract_payment_instructions(text: str) -> list[str]:
    script_noise_tokens = (
        "function ", "xhr.", "xmlhttprequest", "window.", "document.",
        "setrequestheader", "content-type", "application/x-www-form-urlencoded",
        "<script", "</script>", "onload=", "onclick=", "=>", "{", "}",
    )

    def _clean_line(line: str) -> str:
        cleaned = re.sub(r"<[^>]+>", " ", line)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def _is_human_instruction(candidate: str) -> bool:
        ll = candidate.lower()
        if len(candidate) < 12:
            return False
        if any(tok in ll for tok in script_noise_tokens):
            return False
        if candidate.count(";") >= 2:
            return False
        if re.search(r"\b(var|const|let|return|if|else)\b", ll):
            return False
        return any(h in ll for h in PAYMENT_LINE_HINTS)

    hits: list[str] = []
    candidates = text.splitlines() + re.split(r"(?<=[.!?])\s+", text)
    for line in candidates:
        clean_line = _clean_line(line)
        if not _is_human_instruction(clean_line):
            continue
        hits.append(clean_line[:180])
    return _dedupe(hits)[:8]


def _extract_phone_contacts(text: str) -> list[str]:
    out: list[str] = []

    for wa in WHATSAPP_REGEX.findall(text):
        if 7 <= len(wa) <= 15:
            out.append(wa)

    for match in PHONE_REGEX.finditer(text):
        candidate = match.group(0)
        digits_only = re.sub(r"\D", "", candidate)

        if len(digits_only) < 10 or len(digits_only) > 15:
            continue
        if candidate.startswith("+") is False and len(digits_only) >= 13:
            continue

        left = max(0, match.start() - 32)
        right = min(len(text), match.end() + 32)
        context = text[left:right].lower()
        if not any(hint in context for hint in PHONE_CONTEXT_HINTS):
            continue

        out.append(candidate)

    return _dedupe(out)


def _extract_behavior_signals(text: str) -> list[str]:
    ll = text.lower()
    signals: list[str] = []

    if "xmlhttprequest" in ll and "event.type" in ll:
        signals.append("Tracks user interaction events and posts them via XHR")
    if "window.location.href" in ll and ("xhr.open(" in ll or "fetch(" in ll):
        signals.append("Posts telemetry back to current page endpoint")
    if re.search(r"addEventListener\((['\"])(mousemove|keydown|touchstart|click)\1", text, re.IGNORECASE):
        signals.append("Registers event listeners to monitor user actions")
    if any(k in ll for k in ("connect wallet", "walletconnect", "ethereum.request", "eth_requestaccounts")):
        signals.append("Contains wallet connection trigger logic")
    if any(k in ll for k in ("approve", "setapprovalforall", "allowance", "permit(")):
        signals.append("Contains token approval / allowance interaction logic")
    if any(k in ll for k in ("private key", "seed phrase", "mnemonic", "recovery phrase")):
        signals.append("Contains seed/private-key credential capture language")
    if any(k in ll for k in ("countdown", "expires", "limited time", "claim now")):
        signals.append("Uses urgency language to pressure immediate action")
    if any(k in ll for k in ("your ip:", "ip address", "geolocation", "timezone")):
        signals.append("Collects or exposes device/network fingerprinting context")

    return _dedupe(signals)[:8]


def _extract_notable_page_text(page_text: str) -> list[str]:
    candidates = page_text.splitlines() + re.split(r"(?<=[.!?])\s+", page_text)
    out: list[str] = []

    for raw in candidates:
        line = re.sub(r"\s+", " ", raw).strip()
        ll = line.lower()
        if len(line) < 10 or len(line) > 180:
            continue
        if any(token in ll for token in ("function ", "xmlhttprequest", "xhr.", "window.", "document.")):
            continue
        if re.search(r"[{};]{2,}", line):
            continue
        if not any(h in ll for h in NOTABLE_TEXT_HINTS):
            continue
        out.append(line)

    return _dedupe(out)[:10]


def _extract_notable_script_text(script_text: str) -> list[str]:
    out: list[str] = []

    phrase_patterns = [
        r"connect\s+wallet",
        r"claim\s+reward",
        r"claim\s+now",
        r"no\s+rewards\s+yet",
        r"hourly\s+(?:prize|reward|ranking)",
        r"weekly\s+rankings?",
        r"monthly\s+rankings?",
        r"bonus\s+pool",
        r"lottery\s+draw",
        r"join\s+lucky\s+hash",
    ]

    for pattern in phrase_patterns:
        for m in re.finditer(pattern, script_text, re.IGNORECASE):
            phrase = re.sub(r"\s+", " ", m.group(0)).strip()
            if phrase:
                out.append(phrase.title())

    string_matches = re.findall(r"['\"]([^'\"]{6,220})['\"]", script_text)
    for raw in string_matches:
        normalized = re.sub(r"\s+", " ", raw).strip()
        segments = re.split(r"[|•·,:/]|\s{2,}", normalized)
        if not segments:
            segments = [normalized]

        for segment in segments:
            line = re.sub(r"\s+", " ", segment).strip()
            ll = line.lower()
            if len(line) < 8 or len(line) > 120:
                continue
            if any(token in ll for token in ("xmlhttprequest", "application/x-www-form-urlencoded", "function ", "window.", "document.", "xhr.send", "xhr.open")):
                continue
            if re.search(r"[{};<>]{2,}", line):
                continue
            if not any(h in ll for h in NOTABLE_TEXT_HINTS):
                continue
            out.append(line)

    return _dedupe(out)[:10]


def _extract_telegram_ids(text: str) -> list[str]:
    matches = TELEGRAM_LINK_REGEX.findall(text) + TELEGRAM_AT_REGEX.findall(text)
    out: list[str] = []
    for candidate in matches:
        lowered = candidate.lower()
        if lowered in TELEGRAM_NOISE_TERMS:
            continue
        if lowered.startswith(("http", "www")):
            continue
        out.append(f"@{candidate}")
    return _dedupe(out)


def _near_wallet_context(text: str, start: int, end: int, window: int = 48) -> bool:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].lower()
    return any(hint in snippet for hint in WALLET_CONTEXT_HINTS)


def _extract_wallets(text: str) -> list[str]:
    wallets: list[str] = []

    wallets.extend(ETH_REGEX.findall(text))
    wallets.extend(TRON_REGEX.findall(text))
    wallets.extend(BTC_BECH32_REGEX.findall(text))

    for match in BTC_LEGACY_REGEX.finditer(text):
        value = match.group(0)
        if _near_wallet_context(text, match.start(), match.end()):
            wallets.append(value)

    filtered = [w for w in wallets if len(w) <= 80]
    return _dedupe(filtered)


def _extract_decoded_blob_text(text: str) -> str:
    chunks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    decoded_parts: list[str] = []
    for chunk in chunks[:30]:
        if len(chunk) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(chunk, validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if sum(ch.isprintable() for ch in decoded) < max(10, int(len(decoded) * 0.6)):
            continue
        decoded_parts.append(decoded)
    return "\n".join(decoded_parts)


def _extract_external_domains(crawl: dict[str, Any], base_domain: str) -> list[str]:
    domains: list[str] = []

    def _collect(url_candidate: str):
        if not url_candidate:
            return
        parsed = urlparse(url_candidate)
        host = parsed.netloc.lower().removeprefix("www.")
        if host and host != base_domain:
            domains.append(host)

    for link in crawl.get("links", []):
        _collect(link)
    for redir in crawl.get("redirects", []):
        _collect(redir)
    for form in crawl.get("formIntel", []):
        _collect(str(form.get("action") or ""))

    return _dedupe(domains)


def _url_candidates(url: str) -> list[str]:
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    suffix = f"{path}{query}"

    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    else:
        hosts.append(f"www.{host}")

    schemes = [parsed.scheme] if parsed.scheme else []
    for scheme in ("https", "http"):
        if scheme not in schemes:
            schemes.append(scheme)

    candidates: list[str] = []
    for scheme in schemes:
        for candidate_host in hosts:
            candidates.append(f"{scheme}://{candidate_host}{suffix}")

    return _dedupe(candidates)


def _merge_indicators(*dicts) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for d in dicts:
        for k, v in d.items():
            merged[k] = _dedupe(merged.get(k, []) + v)
    if "paymentInstructions" in merged:
        merged["paymentInstructions"] = merged["paymentInstructions"][:8]
    return merged


def _build_crawl_diagnostics(crawl_method: str, crawl_failures: list[str]) -> dict[str, Any]:
    text = "\n".join(crawl_failures).lower()
    playwright_missing = "no module named 'playwright'" in text
    playwright_browser_missing = (
        "browsertype.launch: executable doesn't exist" in text
        or "please run the following command to download new browsers" in text
        or "playwright install" in text and "chrome-linux" in text
    )
    playwright_host_deps_missing = (
        "host system is missing dependencies to run browsers" in text
        or "missing libraries:" in text
        or "libglib-2.0.so.0" in text
    )
    playwright_asyncio_conflict = "playwright sync api inside the asyncio loop" in text
    dns_failure = (
        "nameresolutionerror" in text
        or "failed to resolve" in text
        or "getaddrinfo failed" in text
    )
    timeout_failure = "timed out" in text or "connect timeout" in text
    unreachable = crawl_method == "url_fallback"

    likely_cause = "none"
    if playwright_missing and dns_failure:
        likely_cause = "playwright_missing_and_dns_failure"
    elif playwright_missing:
        likely_cause = "playwright_missing"
    elif playwright_host_deps_missing:
        likely_cause = "playwright_host_dependencies_missing"
    elif playwright_browser_missing:
        likely_cause = "playwright_browser_missing"
    elif playwright_asyncio_conflict:
        likely_cause = "playwright_asyncio_conflict"
    elif dns_failure:
        likely_cause = "dns_resolution_failed"
    elif timeout_failure:
        likely_cause = "target_timeout"
    elif unreachable:
        likely_cause = "target_unreachable"

    recommendations: list[str] = []
    if playwright_missing:
        recommendations.append("Install Playwright in backend venv and run 'python -m playwright install chromium'")
    if playwright_host_deps_missing:
        recommendations.append(
            "Host OS is missing Chromium runtime libraries; run 'python -m playwright install-deps chromium' in the backend runtime (Linux container/VM) or install required apt packages, then restart backend"
        )
    if playwright_browser_missing:
        recommendations.append(
            "Playwright browser binary is missing in the runtime environment; run 'python -m playwright install chromium' where the backend process actually runs (container/VM/server), then restart backend"
        )
    if playwright_asyncio_conflict:
        recommendations.append("Playwright Sync API cannot run inside an asyncio loop; wrap the call with asyncio.to_thread()")
    if dns_failure:
        recommendations.append("Verify domain spelling and DNS availability; try opening the URL in browser")
    if timeout_failure:
        recommendations.append("Target timed out; retry later or use an alternate mirror/domain")
    if unreachable and not recommendations:
        recommendations.append("Target was unreachable for active crawl; rely on URL/history intel fallback")

    return {
        "method": crawl_method,
        "unreachable": unreachable,
        "playwrightMissing": playwright_missing,
        "playwrightHostDepsMissing": playwright_host_deps_missing,
        "playwrightBrowserMissing": playwright_browser_missing,
        "playwrightAsyncioConflict": playwright_asyncio_conflict,
        "dnsFailure": dns_failure,
        "timeout": timeout_failure,
        "likelyCause": likely_cause,
        "recommendations": recommendations,
    }


def _heuristic_url_risk(url: str, domain: str) -> tuple[int, list[str]]:
    score, signals = 0, []
    ll = url.lower()
    tld = f".{domain.rsplit('.', 1)[-1]}" if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:        score += 18; signals.append(f"suspicious_tld:{tld}")
    if domain.count("-") >= 2:         score += 8;  signals.append("many_hyphens")
    if len(domain) > 30:               score += 6;  signals.append("long_domain")
    if re.search(r"\d", domain):       score += 4;  signals.append("domain_contains_digits")
    kw_score = 0
    for kw, w in SUSPICIOUS_URL_HINTS.items():
        if kw in ll: kw_score += w; signals.append(f"url_keyword:{kw}")
    score += min(35, kw_score)
    return min(60, score), _dedupe(signals)


def _screenshot_b64(page) -> str | None:
    """Capture a screenshot and return base64 string."""
    try:
        return base64.b64encode(page.screenshot(type="png")).decode()
    except Exception:
        return None

# ─── Form interaction ─────────────────────────────────────────────────────────

FAKE_CREDENTIALS = {
    "email":    "margaret.chen1957@gmail.com",
    "password": "Sunshine2024!",
    "name":     "Margaret Chen",
    "phone":    "+1-555-0142",
    "address":  "142 Oak Street, Portland OR 97201",
    "amount":   "500",
    "wallet":   "0x742d35Cc6634C0532925a3b8D4C9B8a8eB8e7777",  # fake honeytrap wallet
}

def _fill_and_analyze_forms(page, base_url: str) -> list[dict]:
    """
    Find all forms, fill with fake data, intercept the POST destination.
    Returns list of {action, method, fields, postDestination}.
    """
    form_intel = []
    try:
        forms = page.query_selector_all("form")
        for form in forms:
            action = form.get_attribute("action") or ""
            method = (form.get_attribute("method") or "GET").upper()
            full_action = urljoin(base_url, action) if action else base_url

            fields_found = []
            inputs = form.query_selector_all("input, textarea, select")
            for inp in inputs:
                itype = (inp.get_attribute("type") or "text").lower()
                iname = inp.get_attribute("name") or inp.get_attribute("id") or ""
                iname_lower = iname.lower()

                value = None
                for key, val in FAKE_CREDENTIALS.items():
                    if key in iname_lower:
                        value = val
                        break

                if value and itype not in ("submit", "button", "hidden", "checkbox", "radio"):
                    try:
                        inp.fill(value)
                        fields_found.append({"field": iname, "type": itype, "filled_with": key})
                    except Exception:
                        pass

            form_intel.append({
                "action":          full_action,
                "method":          method,
                "fieldsInteracted": fields_found,
                "suspicious":      method == "POST" and bool(fields_found),
            })
    except Exception as e:
        logger.warning(f"Form analysis failed: {e}")
    return form_intel


# ─── Chat / Telegram interaction ──────────────────────────────────────────────

def _interact_with_chat_widget(page, persona: dict, max_exchanges: int = CHAT_MAX_EXCHANGES) -> list[dict]:
    """
    Detect live chat widgets (Tawk, Intercom, Crisp, custom) and send
    persona messages. Capture each scammer reply.
    """
    exchanges = []
    CHAT_SELECTORS = [
        "iframe[src*='tawk']", "iframe[src*='intercom']",
        "iframe[src*='crisp']", "iframe[src*='livechat']",
        "[id*='chat-widget']", "[class*='chat-widget']",
        "button[class*='chat']", "#chat-input", ".chat-input",
        "textarea[placeholder*='message']", "textarea[placeholder*='Message']",
    ]

    chat_input = None
    for sel in CHAT_SELECTORS:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                # If it's an iframe, try to switch into it
                tag = el.get_attribute("tagName") or el.evaluate("e => e.tagName")
                if str(tag).lower() == "iframe":
                    frame = page.frame_locator(sel)
                    chat_input = frame.locator("textarea, input[type='text']").first
                else:
                    chat_input = el
                break
        except Exception:
            continue

    if not chat_input:
        return exchanges

    messages = persona.get("messages", [])[:max_exchanges]
    for msg in messages:
        try:
            chat_input.fill(msg)
            page.wait_for_timeout(300 + int(len(msg) * 12))  # realistic typing delay
            chat_input.press("Enter")
            page.wait_for_timeout(CHAT_REPLY_WAIT_MS)  # wait for reply

            # Scrape latest reply
            reply_text = ""
            for reply_sel in [".chat-message", ".message-text", "[class*='incoming']", "[class*='bot-message']"]:
                try:
                    msgs = page.query_selector_all(reply_sel)
                    if msgs:
                        reply_text = msgs[-1].inner_text()
                        break
                except Exception:
                    pass

            exchange = {
                "sent":     msg,
                "received": reply_text,
                "newIndicators": _extract_all_indicators(reply_text, []),
            }
            exchanges.append(exchange)

        except Exception as e:
            logger.warning(f"Chat interaction failed: {e}")
            break

    return exchanges


def _interact_via_telegram(telegram_id: str, persona: dict) -> list[dict]:
    """
    If a Telegram bot username is found, interact via Telegram Bot API
    using a disposable test token. Falls back to noting the contact point.
    """
    # In production: use python-telegram-bot with a dedicated honeytrap account.
    # For now, return the contact point as intelligence.
    return [{
        "contactPoint": telegram_id,
        "method": "telegram",
        "note": "Telegram contact identified — use dedicated honeytrap account to engage",
        "suggestedOpener": persona["messages"][0] if persona.get("messages") else "",
    }]


def _deep_interact_page(page) -> list[str]:
    interactions: list[str] = []

    for idx in range(PLAYWRIGHT_DEEP_SCROLL_STEPS):
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(PLAYWRIGHT_DEEP_SCROLL_WAIT_MS)
            interactions.append(f"scroll_step:{idx + 1}")
        except Exception:
            break

    click_selectors = [
        "button:has-text('Connect Wallet')",
        "button:has-text('Connect')",
        "button:has-text('Claim')",
        "button:has-text('Claim Reward')",
        "button:has-text('Join')",
        "a:has-text('Connect Wallet')",
        "a:has-text('Claim')",
        "[role='button']:has-text('Connect')",
    ]

    clicks = 0
    for selector in click_selectors:
        if clicks >= PLAYWRIGHT_INTERACTION_MAX_CLICKS:
            break
        try:
            target = page.locator(selector).first
            if target.count() and target.is_visible():
                target.click(timeout=1_500)
                page.wait_for_timeout(650)
                interactions.append(f"clicked:{selector}")
                clicks += 1
        except Exception:
            continue

    return interactions


def _collect_page_artifacts(page, url: str) -> tuple[list[str], str, str]:
    links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
    form_actions = page.eval_on_selector_all("form[action]", "els => els.map(e => e.action)")
    iframe_sources = page.eval_on_selector_all("iframe[src]", "els => els.map(e => e.src)")
    script_sources = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
    ui_hints = page.eval_on_selector_all(
        "[data-tooltip],[data-title],[title]",
        "els => els.map(e => e.getAttribute('data-tooltip') || e.getAttribute('data-title') || e.getAttribute('title') || '')",
    )

    text_chunks = [
        page.inner_text("body"),
        "\n".join(ui_hints),
        page.content(),
    ]

    script_text = "\n".join(page.eval_on_selector_all("script", "els => els.map(e => e.innerText || '').slice(0, 120)"))
    script_text += "\n" + "\n".join(script_sources)

    combined_links = _dedupe(links + form_actions + iframe_sources + script_sources + [url])
    combined_text = "\n".join(chunk for chunk in text_chunks if chunk)
    return combined_links, combined_text, script_text


# ─── Playwright crawl (upgraded) ─────────────────────────────────────────────

def _is_playwright_browser_missing_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "browsertype.launch: executable doesn't exist" in text
        or "please run the following command to download new browsers" in text
    )


def _install_playwright_chromium_runtime() -> None:
    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=PLAYWRIGHT_INSTALL_TIMEOUT_S,
        check=False,
    )
    if completed.returncode != 0:
        tail = "\n".join((completed.stderr or completed.stdout or "").splitlines()[-8:])
        raise RuntimeError(f"Playwright chromium install failed in runtime env (code {completed.returncode}): {tail}")


def _launch_chromium_with_recovery(playwright):
    launch_args = {
        "headless": True,
        "args": ["--disable-blink-features=AutomationControlled"],
    }
    try:
        return playwright.chromium.launch(**launch_args)
    except Exception as exc:
        if not _is_playwright_browser_missing_error(exc):
            raise
        logger.warning("Playwright chromium executable missing in runtime; attempting in-process install and retry")
        _install_playwright_chromium_runtime()
        return playwright.chromium.launch(**launch_args)

def _crawl_with_playwright(url: str, persona: dict) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium_with_recovery(p)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = context.new_page()

        # Block obvious bot-detection scripts
        page.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")

        redirects = []
        page.on("response", lambda r: redirects.append(r.url) if r.status in (301, 302, 303, 307, 308) else None)

        page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_NAV_TIMEOUT_MS)
        page.wait_for_timeout(PLAYWRIGHT_POST_LOAD_WAIT_MS)
        try:
            page.wait_for_load_state("networkidle", timeout=4_000)
        except Exception:
            pass

        deep_interactions = _deep_interact_page(page)

        screenshot_initial = _screenshot_b64(page)

        links, text, script_text = _collect_page_artifacts(page, url)
        title = page.title()

        # Form interaction
        form_intel = _fill_and_analyze_forms(page, url)

        # Chat widget interaction
        chat_exchanges = _interact_with_chat_widget(page, persona)

        screenshot_after = _screenshot_b64(page)

        chat_widgets = page.eval_on_selector_all(
            "[id*='chat'],[class*='chat'],iframe[src*='tawk'],iframe[src*='intercom']",
            "els => els.map(e=>e.id||e.className||e.tagName)",
        )

        browser.close()

    return {
        "pageText":         text,
        "scriptText":       script_text,
        "title":            title,
        "links":            _dedupe(links),
        "formIntel":        form_intel,
        "chatExchanges":    chat_exchanges,
        "chatWidgets":      chat_widgets,
        "redirects":        redirects,
        "screenshotInitial": screenshot_initial,
        "screenshotAfter":   screenshot_after,
        "evidence": [
            f"Page title: {title}",
            f"Links detected: {len(links)}",
            f"Forms analyzed: {len(form_intel)}",
            f"Form POSTs intercepted: {sum(1 for f in form_intel if f.get('suspicious'))}",
            f"Chat exchanges: {len(chat_exchanges)}",
            f"Chat widgets: {len(chat_widgets)}",
            f"Deep interactions: {len(deep_interactions)}",
            f"Redirects: {len(redirects)}",
        ],
    }


def _crawl_with_requests(url: str) -> dict[str, Any]:
    last_error: Exception | None = None
    attempted = 0
    for candidate in _url_candidates(url)[:MAX_REQUEST_CANDIDATES]:
        attempted += 1
        try:
            r = requests.get(
                candidate,
                timeout=(REQUEST_CONNECT_TIMEOUT_S, REQUEST_READ_TIMEOUT_S),
                headers={"User-Agent": "Mozilla/5.0"},
            )
            html = r.text or ""
            links = re.findall(r"href=[\"']([^\"'#]+)", html, re.IGNORECASE)
            scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, flags=re.IGNORECASE)
            script_text = "\n".join(scripts)
            text  = re.sub(r"<[^>]+>", " ", re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE))
            text  = re.sub(r"\s+", " ", text).strip()
            return {
                "pageText": text, "title": "", "links": _dedupe(links),
                "scriptText": script_text,
                "formIntel": [], "chatExchanges": [], "chatWidgets": [],
                "redirects": [], "screenshotInitial": None, "screenshotAfter": None,
                "evidence": [
                    f"HTTP {r.status_code}",
                    f"Requested URL: {candidate}",
                    f"Final URL: {r.url}",
                    f"Request attempts: {attempted}/{MAX_REQUEST_CANDIDATES}",
                    f"Links: {len(links)}",
                ],
            }
        except Exception as exc:
            last_error = exc

    raise RuntimeError(f"All URL candidates failed: {last_error}")


def _empty_crawl(evidence=None) -> dict[str, Any]:
    return {
        "pageText": "", "scriptText": "", "title": "", "links": [], "formIntel": [],
        "chatExchanges": [], "chatWidgets": [], "redirects": [],
        "screenshotInitial": None, "screenshotAfter": None,
        "evidence": evidence or [],
    }


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_honeytrap_bot(url: str, persona_key: str = "elderly_victim", persona_prompt: str = "") -> dict:
    """
    Run the full honeytrap pipeline against a URL.

    Args:
        url:            Target URL to investigate
        persona_key:    Which built-in persona to use ("elderly_victim" | "crypto_curious")
        persona_prompt: Optional custom persona description (overrides persona_key backstory)

    Returns:
        Full ScamIntelligence report dict
    """
    normalized = url.strip()
    if not normalized.startswith(("http://", "https://")):
        normalized = f"https://{normalized}"

    parsed = urlparse(normalized)
    domain = parsed.netloc.lower().removeprefix("www.")

    persona_mode = "manual"
    persona_reasons: list[str] = []

    if _is_auto_persona_request(persona_key, persona_prompt):
        selected_key, adaptive_backstory, persona_reasons = _select_persona_for_target(normalized, domain)
        persona = {**DEFAULT_PERSONAS[selected_key], "backstory": adaptive_backstory}
        persona_key = selected_key
        persona_prompt = ""
        persona_mode = "auto"
    else:
        if persona_key and persona_key not in DEFAULT_PERSONAS and not persona_prompt:
            persona_prompt = persona_key
            persona_key = "elderly_victim"

        persona = DEFAULT_PERSONAS.get(persona_key, DEFAULT_PERSONAS["elderly_victim"])
        if persona_prompt:
            persona = {**persona, "backstory": persona_prompt}

    # ── Crawl ──────────────────────────────────────────────────────────────────
    crawl_method = "playwright"
    crawl_failures: list[str] = []
    try:
        crawl = _crawl_with_playwright(normalized, persona)
    except Exception as exc:
        crawl_failures.append(f"Playwright failed: {exc}")
        crawl_method = "requests"
        try:
            crawl = _crawl_with_requests(normalized)
        except Exception as req_exc:
            crawl_failures.append(f"Requests failed: {req_exc}")
            crawl_method = "url_fallback"
            crawl = _empty_crawl(crawl_failures)

    # ── Extract indicators from all sources ────────────────────────────────────
    page_indicators = _extract_all_indicators(crawl["pageText"], crawl["links"])
    script_indicators = _extract_all_indicators(crawl.get("scriptText", ""), crawl["links"])
    blob_indicators = _extract_all_indicators(_extract_decoded_blob_text(crawl.get("scriptText", "")), [])
    form_action_indicators = _extract_all_indicators(
        "\n".join(str(f.get("action") or "") for f in crawl.get("formIntel", [])),
        [],
    )

    # Also extract from chat exchange replies
    chat_indicators = _extract_all_indicators(
        "\n".join(e.get("received", "") for e in crawl["chatExchanges"]), []
    )

    # Also extract from URL itself (fallback always useful)
    url_indicators = _extract_all_indicators(
        unquote(f"{normalized}\n{domain}\n{parsed.path}\n{parsed.query}"), []
    )

    indicators = _merge_indicators(
        page_indicators,
        script_indicators,
        blob_indicators,
        form_action_indicators,
        chat_indicators,
        url_indicators,
    )

    notable_page_text = _extract_notable_page_text(crawl.get("pageText", ""))
    notable_script_text = _extract_notable_script_text(crawl.get("scriptText", ""))
    notable_text = _dedupe(notable_page_text + notable_script_text)[:12]

    # Telegram interactions (identified but not yet engaged)
    telegram_contacts = []
    for tg in indicators.get("telegramIds", []):
        telegram_contacts.extend(_interact_via_telegram(tg, persona))

    # ── Risk scoring ───────────────────────────────────────────────────────────
    url_result         = analyze_url(normalized)
    heuristic_risk, heuristic_signals = _heuristic_url_risk(normalized, domain)

    base           = max(int(url_result.get("score", 0)), heuristic_risk)
    indicator_bonus = min(35,
        len(indicators["wallets"])             * 10 +
        len(indicators["telegramIds"])         * 5  +
        len(indicators["emails"])              * 3  +
        len(indicators["phones"])              * 4  +
        len(indicators["paymentInstructions"]) * 4  +
        len(indicators.get("behaviorSignals", [])) * 3 +
        len(crawl["chatExchanges"])            * 6  +  # live chat = strong signal
        sum(1 for f in crawl["formIntel"] if f.get("suspicious")) * 8  # POST form = strong signal
    )
    domain_risk = min(100, base + indicator_bonus)

    if crawl_method == "url_fallback":
        domain_risk = max(domain_risk, max(20, heuristic_risk))

    network = get_honeytrap_network_stats(
        indicators["wallets"], indicators["telegramIds"], domain
    )
    external_domains = _extract_external_domains(crawl, domain)
    connected_domains = max(int(network.get("connectedDomains", 0)), len(external_domains))
    active_campaign = bool(network.get("activeCampaign") or external_domains)
    shared_wallets = int(network.get("sharedWallets", 0))

    scam_network_risk = min(100,
        domain_risk +
        min(25,
            connected_domains * 2 +
            shared_wallets    * 3 +
            (15 if active_campaign else 0)
        )
    )

    # ── Build evidence log ─────────────────────────────────────────────────────
    evidence = list(crawl.get("evidence", []))
    evidence.append(f"Crawler: {crawl_method}")
    evidence.append(f"Persona mode: {persona_mode}")
    if persona_mode == "auto":
        evidence.append(f"Persona selected: {persona_key}")
        if persona_reasons:
            evidence.append(f"Persona reasons: {', '.join(persona_reasons[:4])}")
    if heuristic_signals:
        evidence.append(f"URL signals: {', '.join(heuristic_signals[:6])}")
    if notable_text:
        evidence.append(f"Notable page text lines: {len(notable_text)}")
    if external_domains:
        evidence.append(f"External domains observed: {', '.join(external_domains[:6])}")
    if crawl_failures and crawl_method != "url_fallback":
        evidence.extend(crawl_failures)
    if crawl_method == "url_fallback":
        evidence.append("Target unreachable for active crawl; risk includes unreachable-target baseline")
    if persona_prompt:
        evidence.append(f"Custom persona: {persona_prompt[:120]}")

    crawl_diagnostics = _build_crawl_diagnostics(crawl_method, crawl_failures)

    # ── Session hash (for deduplication + DB storage) ──────────────────────────
    session_id = hashlib.sha256(f"{normalized}{time.time()}".encode()).hexdigest()[:16]

    result = {
        "sessionId":         session_id,
        "url":               normalized,
        "domain":            domain,
        "pageTitle":         crawl.get("title", ""),

        # Risk
        "domainRisk":        domain_risk,
        "scamNetworkRisk":   scam_network_risk,
        "urlModelScore":     url_result.get("score", 0),
        "urlModelStatus":    url_result.get("status", "unknown"),

        # Network graph
        "connectedDomains":  connected_domains,
        "sharedWallets":     shared_wallets,
        "activeCampaign":    active_campaign,

        # Indicators (what we extracted)
        "wallets":             indicators["wallets"],
        "telegramIds":         indicators["telegramIds"],
        "emails":              indicators["emails"],
        "phones":              indicators["phones"],
        "paymentInstructions": indicators["paymentInstructions"],
        "behaviorSignals":     indicators.get("behaviorSignals", []),
        "notablePageText":     notable_text,

        # Interaction intel (what the bot actually did)
        "formIntel":           crawl["formIntel"],
        "chatExchanges":       crawl["chatExchanges"],
        "telegramContacts":    telegram_contacts,
        "chatWidgetsFound":    crawl["chatWidgets"],
        "redirectsDetected":   crawl["redirects"],

        # Screenshots (base64 PNG — strip for storage, keep for UI)
        "screenshotInitial":   crawl.get("screenshotInitial"),
        "screenshotAfter":     crawl.get("screenshotAfter"),

        # Meta
        "persona":             persona["name"],
        "evidence":            evidence,
        "crawlDiagnostics":    crawl_diagnostics,
        "urlAnalysis":         url_result,
    }

    return result