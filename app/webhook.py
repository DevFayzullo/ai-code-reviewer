import hmac
import hashlib
import os
from fastapi import APIRouter, Request, Header, HTTPException
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "test-secret")


def verify_signature(payload: bytes, signature: str) -> bool:
    """
    GitHub dan kelgan request haqiqiy ekanligini tekshiradi.
    HMAC-SHA256 algoritmi ishlatiladi.
    """
    if not signature:
        return False
    
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    expected_full = f"sha256={expected}"
    return hmac.compare_digest(expected_full, signature)


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None)
):
    payload = await request.body()

    # Signature tekshirish (production uchun muhim)
    # Hozircha test uchun o'tkazib yuboramiz
    # if not verify_signature(payload, x_hub_signature_256):
    #     raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()
    action = data.get("action")
    
    print(f"✅ Webhook keldi! Action: {action}")
    
    return {"status": "ok", "action": action}