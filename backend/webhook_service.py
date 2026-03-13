import os
import json
import logging
import httpx
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class DiscordWebhookService:
    def __init__(self):
        self.webhook_url = os.getenv("webhook_url")
        self.enabled = bool(self.webhook_url)
        
    async def send_alert(self, 
                    title: str, 
                    description: str, 
                    color: int = 0xFF0000,
                    fields: Optional[Dict[str, Any]] = None,
                    url: Optional[str] = None):
        """Send alert to Discord webhook"""
        
        if not self.enabled:
            logger.warning("Discord webhook not configured")
            return False
            
        try:
            embed = {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": "ScamShield Real-time Alert"
                }
            }
            
            if fields:
                embed["fields"] = [
                    {"name": k, "value": str(v), "inline": True} 
                    for k, v in fields.items()
                ]
                
            if url:
                embed["url"] = url
            
            payload = {
                "embeds": [embed],
                "username": "ScamShield Bot",
                "avatar_url": "https://i.imgur.com/3Z4j2rM.png"  # Shield icon
            }
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(self.webhook_url, json=payload)
                response.raise_for_status()
                
            logger.info(f"Discord alert sent: {title}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")
            return False
    
    async def scam_reported(self, url: str, category: str, risk_score: int, reporter: str = "System"):
        """Alert when new scam is reported"""
        
        color = self._risk_color(risk_score)
        
        return await self.send_alert(
            title="🚨 New Scam Reported",
            description=f"A new suspicious URL has been detected and reported",
            color=color,
            fields={
                "URL": url[:100] + "..." if len(url) > 100 else url,
                "Category": category,
                "Risk Score": f"{risk_score}/100",
                "Reporter": reporter
            },
            url=url
        )
    
    async def honeytrap_alert(self, url: str, intel: Dict[str, Any]):
        """Alert when honeytrap finds high-value intel"""
        
        wallets = intel.get("wallets", [])
        telegram = intel.get("telegramIds", [])
        emails = intel.get("emails", [])
        
        if not (wallets or telegram or emails):
            return False
            
        return await self.send_alert(
            title="🕵️ Honeytrap Intel Captured",
            description=f"High-value intelligence extracted from scam page",
            color=0x00FF00,
            fields={
                "URL": url[:80] + "..." if len(url) > 80 else url,
                "Wallets": f"{len(wallets)} found" if wallets else "None",
                "Telegram": f"{len(telegram)} found" if telegram else "None", 
                "Emails": f"{len(emails)} found" if emails else "None",
                "Domain Risk": f"{intel.get('domainRisk', 0)}/100",
                "Network Risk": f"{intel.get('scamNetworkRisk', 0)}/100"
            },
            url=url
        )
    
    async def ai_analysis_alert(self, url: str, attack_type: str, risk_score: int, confidence: int, indicators: list):
        """Alert when AI detects high-risk scam"""
        
        if risk_score < 70:
            return False  # Only alert for high-risk detections
            
        return await self.send_alert(
            title="⚡ AI High-Risk Detection",
            description=f"AI-powered analysis detected a dangerous scam",
            color=self._risk_color(risk_score),
            fields={
                "URL": url[:80] + "..." if len(url) > 80 else url,
                "Attack Type": attack_type,
                "Risk Score": f"{risk_score}/100",
                "Confidence": f"{confidence}%",
                "Indicators": "\n".join(indicators[:3])  # First 3 indicators
            },
            url=url
        )
    
    async def wallet_blockchain_reported(self, wallets: list, tx_hash: str):
        """Alert when scam wallets are reported to blockchain"""
        
        return await self.send_alert(
            title="⛓️ Wallets Reported to Blockchain",
            description=f"Scam wallet addresses have been submitted to blockchain",
            color=0xFF6600,
            fields={
                "Wallets Reported": str(len(wallets)),
                "Transaction": tx_hash[:20] + "..." if len(tx_hash) > 20 else tx_hash,
                "Network": "Polygon Amoy"
            },
            url=f"https://amoy.polygonscan.com/tx/{tx_hash}"
        )
    
    def _risk_color(self, risk_score: int) -> int:
        """Get Discord embed color based on risk score"""
        if risk_score >= 80:
            return 0xFF0000  # Red
        elif risk_score >= 60:
            return 0xFF6600  # Orange  
        elif risk_score >= 40:
            return 0xFFFF00  # Yellow
        else:
            return 0x00FF00  # Green

# Global webhook service instance
webhook_service = DiscordWebhookService()
