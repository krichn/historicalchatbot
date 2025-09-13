import os
import hmac
import base64
import hashlib
import logging
from typing import Dict, Any

import httpx
from fastapi import APIRouter, Header, HTTPException, Request

# ---------- Logging ----------
LOG_FILE = "line_chatbot.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ---------- Router ----------
router = APIRouter(tags=["line"])

LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")

DIFY_BASE_URL = os.getenv("DIFY_BASE_URL", "").rstrip("/")
DIFY_API_KEY = os.getenv("DIFY_API_KEY", "")


# ---------- Utils ----------
def _calc_signature(body: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("utf-8")


def _verify_line_signature(body: bytes, x_line_signature: str) -> bool:
    computed = _calc_signature(body, LINE_CHANNEL_SECRET)
    # DEBUG: แสดงลายเซ็น (ตัดให้สั้น) และท้าย secret
    logger.debug(f"X-Line-Signature header : {x_line_signature}")
    logger.debug(f"Computed signature      : {computed}")
    logger.debug(f"Using Channel Secret ***{LINE_CHANNEL_SECRET[-6:]} (masked)")
    return hmac.compare_digest(computed, x_line_signature)


async def _call_dify_chat(
    user_id: str, query: str, conversation_id: str | None = None
) -> Dict[str, Any]:
    if not DIFY_BASE_URL or not DIFY_API_KEY:
        raise RuntimeError("DIFY_BASE_URL / DIFY_API_KEY is missing")

    url = f"{DIFY_BASE_URL}/chat-messages"
    payload = {
        "inputs": {},
        "query": query,
        "response_mode": "blocking",
        "user": user_id,
    }
    if conversation_id:
        payload["conversation_id"] = conversation_id

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, json=payload, headers=headers)
        logger.debug(f"Dify raw response {r.status_code}: {r.text}")
        if r.status_code >= 400:
            raise RuntimeError(f"Dify error {r.status_code}: {r.text}")
        return r.json()


async def _reply_line(reply_token: str, text: str):
    url = "https://api.line.me/v2/bot/message/reply"
    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    body = {
        "replyToken": reply_token,
        "messages": [{"type": "text", "text": text[:4900]}],
    }
    logger.debug(f"Sending reply to LINE: {body}")

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, json=body, headers=headers)
        logger.debug(f"LINE reply response {r.status_code}: {r.text}")
        if r.status_code >= 400:
            raise RuntimeError(f"LINE reply error {r.status_code}: {r.text}")


# ---------- Core handler ----------
async def _handle(
    request: Request,
    x_line_signature: str | None,
    verify_signature: bool = True,
):
    body = await request.body()

    if verify_signature:
        if not x_line_signature:
            logger.error("Missing X-Line-Signature header")
            raise HTTPException(status_code=400, detail="Missing X-Line-Signature")
        if not _verify_line_signature(body, x_line_signature):
            logger.error("Invalid LINE signature")
            raise HTTPException(status_code=403, detail="Invalid LINE signature")
    else:
        logger.warning("** Signature verification is DISABLED for this request **")

    data = await request.json()
    logger.debug(f"Incoming LINE payload: {data}")

    for ev in data.get("events", []):
        if ev.get("type") != "message":
            continue

        message = ev.get("message", {})
        if message.get("type") != "text":
            continue

        user_id = ev.get("source", {}).get("userId", "unknown")
        user_text = message.get("text", "")
        reply_token = ev.get("replyToken", "")

        logger.debug(f"User ID: {user_id}")
        logger.debug(f"User Text: {user_text}")
        logger.debug(f"Reply Token: {reply_token}")

        try:
            dify_res = await _call_dify_chat(user_id=user_id, query=user_text)
            logger.debug(f"Dify response JSON: {dify_res}")
            answer = dify_res.get("answer") or "ขออภัย ระบบไม่มีคำตอบในขณะนี้"
        except Exception as e:
            answer = f"เกิดข้อผิดพลาดในการเชื่อม Dify: {e}"
            logger.error(answer)

        try:
            await _reply_line(reply_token, answer)
        except Exception as e:
            logger.error(f"LINE reply error: {e}")

    return {"status": "ok"}


# ---------- Routes ----------
# Webhook จริง (มีการ verify signature) — ใช้กับ URL /message ที่คุณตั้งอยู่
@router.post("/message")
async def line_message(
    request: Request,
    x_line_signature: str = Header(None, alias="X-Line-Signature"),
):
    return await _handle(request, x_line_signature, verify_signature=True)


# สำรอง: เส้นทางมาตรฐาน /line/webhook (เผื่อย้ายในอนาคต)
@router.post("/line/webhook")
async def line_webhook(
    request: Request,
    x_line_signature: str = Header(None, alias="X-Line-Signature"),
):
    return await _handle(request, x_line_signature, verify_signature=True)


# เส้นทางทดสอบ (ข้ามการ verify) — ใช้ทดสอบ Dify และการ reply อย่างเดียว
@router.post("/message/nosig")
async def line_message_nosig(request: Request):
    return await _handle(request, x_line_signature=None, verify_signature=False)
