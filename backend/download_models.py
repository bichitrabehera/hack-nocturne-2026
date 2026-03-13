"""
download_models.py
Run this ONCE on your laptop before deploying to Render.

  python download_models.py

What it does:
  1. Downloads pirocheto/phishing-url-detection → saves as models/url_model.pkl  (~2MB)
  2. Downloads all-MiniLM-L6-v2               → saves as models/text_model/     (~90MB)
  3. Pre-computes scam anchor embeddings       → saves as models/anchors.pkl     (~5KB)

After running, commit the entire models/ folder to your repo.
Render loads from disk — zero download on cold start.
"""

import json
import pickle
from datetime import datetime
from pathlib import Path

MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

SCAM_ANCHORS = {
    "phishing": [
        "Your account has been suspended. Verify your identity immediately to avoid permanent ban.",
        "Click here to confirm your email address or your account will be deleted.",
        "We detected unusual activity. Update your password now to secure your account.",
        "Your PayPal account is limited. Please verify your information immediately.",
        "Security alert: unauthorized login detected. Confirm your details to restore access.",
        "Your account will be closed unless you verify your information within 24 hours.",
    ],
    "prize_scam": [
        "Congratulations! You have been selected as our lucky winner. Claim your prize now.",
        "You won $5,000 in our lottery. Send your details to receive your cash reward.",
        "You are the chosen winner of our sweepstakes. Click to claim your free gift.",
        "Your phone number has won our monthly prize draw. Claim your reward today.",
    ],
    "crypto_scam": [
        "Send 0.1 ETH to receive 1 ETH back. Double your crypto guaranteed.",
        "Exclusive airdrop for early investors. Send your wallet address to claim tokens.",
        "Investment opportunity: guaranteed 200% returns on your Bitcoin in 24 hours.",
        "Enter your seed phrase to verify your wallet and receive your crypto reward.",
        "Connect your MetaMask wallet to claim your free NFT airdrop today.",
    ],
    "romance_scam": [
        "I have strong feelings for you. I need money urgently for my flight to meet you.",
        "My darling, I am stuck abroad and need you to send me money via wire transfer.",
        "I love you deeply. Please help me with this emergency. I will pay you back soon.",
    ],
    "investment_fraud": [
        "Risk-free investment with guaranteed returns. Get rich quick with our system.",
        "Work from home and earn $5,000 per week. No experience needed. Start today.",
        "Our trading algorithm has 99% success rate. Invest now for guaranteed profits.",
        "Exclusive investment opportunity. Double your money in 30 days guaranteed.",
    ],
    "tech_support": [
        "Your computer has a virus. Call our toll-free number immediately for support.",
        "Microsoft has detected malware on your device. Click here to fix it now.",
        "Your Windows license has expired. Call us to renew and avoid data loss.",
        "Warning: your device is infected. Download our security tool immediately.",
    ],
    "impersonation": [
        "This is the IRS. You owe back taxes. Pay immediately or face arrest.",
        "Your Social Security number has been suspended due to suspicious activity.",
        "This is Amazon customer service. Your account shows unauthorized purchases.",
        "This is your bank. We have detected fraud on your account. Call us now.",
    ],
}

LEGIT_ANCHORS = [
    "Hi, just wanted to confirm our meeting scheduled for tomorrow at 3pm.",
    "Your order has been shipped and will arrive within 3-5 business days.",
    "Thank you for your purchase. Your receipt is attached to this email.",
    "Please find the project report attached as requested in our last meeting.",
    "The quarterly review is scheduled for next Friday. Please confirm attendance.",
    "Your subscription has been renewed successfully. No action required.",
    "Looking forward to catching up with you at the conference next week.",
    "Here are the notes from today's standup meeting. Let me know if I missed anything.",
]


def download_url_model():
    print("\n── URL model ─────────────────────────────────────────────")
    print("Downloading pirocheto/phishing-url-detection ...")

    from huggingface_hub import hf_hub_download

    model_path = hf_hub_download(
        repo_id="pirocheto/phishing-url-detection",
        filename="model.pkl",
    )

    with open(model_path, "rb") as f:
        url_model = pickle.load(f)

    test_urls = ["http://paypa1-secure-login.tk", "https://amazon.com/orders"]
    probs = url_model.predict_proba(test_urls)
    print(f"  Verification — paypa1.tk:  phishing={probs[0][1]:.3f}")
    print(f"  Verification — amazon.com: phishing={probs[1][1]:.3f}")

    out_path = MODELS_DIR / "url_model.pkl"
    with open(out_path, "wb") as f:
        pickle.dump(url_model, f)

    size_mb = out_path.stat().st_size / 1_000_000
    print(f"  Saved → {out_path}  ({size_mb:.1f} MB)")


def download_text_model():
    print("\n── Text model ────────────────────────────────────────────")
    print("Downloading sentence-transformers/all-MiniLM-L6-v2 ...")

    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    out_path = MODELS_DIR / "text_model"
    model.save(str(out_path))

    total = sum(f.stat().st_size for f in out_path.rglob("*") if f.is_file())
    print(f"  Saved → {out_path}/  ({total / 1_000_000:.1f} MB)")
    return model


def precompute_anchors(text_model):
    print("\n── Anchor embeddings ─────────────────────────────────────")
    print("Pre-computing scam anchor embeddings ...")

    scam_embeddings = {}
    for category, sentences in SCAM_ANCHORS.items():
        embs = text_model.encode(sentences, convert_to_numpy=True)
        scam_embeddings[category] = embs.mean(axis=0)
        print(f"  {category}: {len(sentences)} sentences → mean embedding shape {embs.shape[1]}")

    legit_embs = text_model.encode(LEGIT_ANCHORS, convert_to_numpy=True)
    legit_embedding = legit_embs.mean(axis=0)
    print(f"  legitimate: {len(LEGIT_ANCHORS)} sentences → mean embedding shape {legit_embs.shape[1]}")

    anchors = {
        "scam_embeddings": scam_embeddings,
        "legit_embedding": legit_embedding,
    }

    out_path = MODELS_DIR / "anchors.pkl"
    with open(out_path, "wb") as f:
        pickle.dump(anchors, f)

    size_kb = out_path.stat().st_size / 1_000
    print(f"  Saved → {out_path}  ({size_kb:.1f} KB)")


def write_manifest():
    manifest = {
        "url_model": "pirocheto/phishing-url-detection",
        "text_model": "sentence-transformers/all-MiniLM-L6-v2",
        "downloaded": datetime.utcnow().isoformat() + "Z",
        "files": {
            "url_model": "models/url_model.pkl",
            "text_model": "models/text_model/",
            "anchors": "models/anchors.pkl",
        },
    }

    out_path = MODELS_DIR / "manifest.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n  Manifest → {out_path}")


if __name__ == "__main__":
    print("=" * 60)
    print("  ScamShield — Model Download Script")
    print("  Run once on your laptop, commit models/ to repo")
    print("=" * 60)

    download_url_model()
    text_model = download_text_model()
    precompute_anchors(text_model)
    write_manifest()

    print("\n✓ All models saved to models/")
    print("✓ Next step: git add models/ && git commit -m 'add pretrained models'")
    print("✓ Render will load from disk — no download on cold start")
