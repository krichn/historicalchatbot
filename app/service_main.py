import os
import tempfile
from datetime import datetime

#import ffmpeg
from aift import setting
from aift.multimodal import audioqa, textqa, vqa
from fastapi import APIRouter, Request
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import AudioMessage, ImageMessage, MessageEvent, TextMessage, TextSendMessage

from app.configs import Configs

router = APIRouter(tags=["Main"], prefix="/messagexx")

cfg = Configs()

setting.set_api_key(cfg.AIFORTHAI_APIKEY)  # AIFORTHAI_APIKEY
line_bot_api = LineBotApi(cfg.LINE_CHANNEL_ACCESS_TOKEN)  # CHANNEL_ACCESS_TOKEN
handler = WebhookHandler(cfg.LINE_CHANNEL_SECRET)  # CHANNEL_SECRET

text_for_audio_append = (
    "คุณต้องการให้ฉันทำอะไรกับเสียงนี้ ? รับเฉพาะข้อความเท่านั้น\n\nยกเลิกให้พิมพ์ /cancel หรือ /ยกเลิก"
)
mp3_file = []

text_for_visual_append = (
    "คุณต้องการให้ฉันทำอะไรกับภาพนี้ ? รับเฉพาะข้อความเท่านั้น\n\nยกเลิกให้พิมพ์ /cancel หรือ /ยกเลิก"
)
image_file = []


@router.post("")
async def multimodal_demo(request: Request):
    """
    Line Webhook endpoint สำหรับรับข้อความจาก Line Messaging API และประมวลผลข้อความด้วย AI FOR THAI

    ฟังก์ชันนี้ทำหน้าที่:
    1. รับ HTTP POST Request จาก Line Webhook
    2. ตรวจสอบลายเซ็น (X-Line-Signature) เพื่อยืนยันความถูกต้องของข้อความ
    3. ส่งข้อความไปยัง handler เพื่อประมวลผลอีเวนต์ที่ได้รับ
    4. เมื่อได้รับข้อความ (MessageEvent) ที่เป็นข้อความ (TextMessage):
        - สร้าง session id โดยใช้วัน, เดือน, ชั่วโมง, และนาทีที่ปรับให้ลงตัวกับเลข 10
        - ส่งข้อความไปยัง API Text QA ของ AI FOR THAI (ซึ่งใช้ Pathumma LLM) เพื่อประมวลผล
        - ส่งข้อความตอบกลับ (response) กลับไปยังผู้ใช้ผ่าน Line Messaging API
    """
    signature = request.headers["X-Line-Signature"]
    body = await request.body()
    try:
        handler.handle(body.decode("UTF-8"), signature)
    except InvalidSignatureError:
        print("Invalid signature. Please check your channel access token or channel secret.")
    return "OK"


@handler.add(MessageEvent, message=TextMessage)
def handle_text_message(event):
    user_text = event.message.text.strip()
    text = None
    res = None

    # ถ้า user ส่ง /cancel หรือ /ยกเลิก ให้ reset mp3_file และ image_file
    if user_text in ["/cancel", "/ยกเลิก"]:
        # ลบไฟล์ mp3 ทั้งหมดที่ค้างอยู่
        for mp3_path in mp3_file:
            if os.path.exists(mp3_path):
                os.remove(mp3_path)
        mp3_file.clear()
        # ลบไฟล์รูปทั้งหมดที่ค้างอยู่
        for img_path in image_file:
            if os.path.exists(img_path):
                os.remove(img_path)
        image_file.clear()
        send_message(event, "ล้างความจำก่อนหน้านี้แล้ว")
        return

    # ถ้ามี mp3 ใน mp3_file ให้ประมวลผล audioqa.generate
    if len(mp3_file) > 0:
        mp3_path = mp3_file[0]
        res = audioqa.generate(
            mp3_path,
            user_text,
            return_json=True,
        )

    # ถ้ามีรูปใน image_file ให้ประมวลผล vqa.generate
    elif len(image_file) > 0:
        img_path = image_file[0]
        res = vqa.generate(
            img_path,
            user_text,
            return_json=True,
        )

    else:
        current_time = datetime.now()
        # extract day, month, hour, and minute
        day, month = current_time.day, current_time.month
        hour, minute = current_time.hour, current_time.minute
        # adjust the minute to the nearest lower number divisible by 10
        adjusted_minute = minute - (minute % 10)
        result = f"{day:02}{month:02}{hour:02}{adjusted_minute:02}"
        res = textqa.chat(user_text, result + cfg.AIFORTHAI_APIKEY, temperature=0.6)

    if res and "content" in res and res["content"]:
        text = res["content"] if isinstance(res["content"], str) else res["content"][0]
    elif res and "response" in res:
        text = res["response"] if isinstance(res["response"], str) else res["response"][0]
    else:
        text = "ไม่สามารถประมวลผลข้อความนี้ได้"

    send_message(event, text)


@handler.add(MessageEvent, message=AudioMessage)
def handle_voice_message(event):
    message_content = line_bot_api.get_message_content(event.message.id)

    # Save the incoming audio (m4a) to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".m4a") as tmp_in:
        for chunk in message_content.iter_content():
            tmp_in.write(chunk)
        tmp_in_path = tmp_in.name

    # Prepare a temporary file for the mp3 output
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as tmp_out:
        tmp_out_path = tmp_out.name

    try:
        # Convert m4a to mp3 using ffmpeg-python
        (
            ffmpeg.input(tmp_in_path)
            .output(tmp_out_path, format="mp3", acodec="libmp3lame")
            .run(quiet=True, overwrite_output=True)
        )
        # ลบไฟล์ต้นฉบับ m4a
        if os.path.exists(tmp_in_path):
            os.remove(tmp_in_path)
        # เก็บ path mp3 ไว้ใน array
        mp3_file.append(tmp_out_path)
        # ส่งข้อความแจ้ง user
        send_message(event, text_for_audio_append)
    except Exception as e:
        send_message(event, f"เกิดข้อผิดพลาดในการแปลงไฟล์เสียง: {e}")
        # ลบไฟล์หากมีปัญหา
        if os.path.exists(tmp_in_path):
            os.remove(tmp_in_path)
        if os.path.exists(tmp_out_path):
            os.remove(tmp_out_path)


@handler.add(MessageEvent, message=ImageMessage)
def handle_image_message(event):
    message_id = event.message.id
    image_content = line_bot_api.get_message_content(message_id)

    suffix = ".jpg"

    if event.message.content_provider.type == "external":
        url = event.message.content_provider.original_content_url
        ext = os.path.splitext(url)[1]
        suffix = ext if ext else ".img"

    # สร้างไฟล์ชั่วคราวเพื่อเก็บรูป
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_img:
        for chunk in image_content.iter_content():
            tmp_img.write(chunk)
        tmp_img_path = tmp_img.name

    # เก็บ path ของรูปไว้ใน array
    image_file.append(tmp_img_path)

    # ส่งข้อความแจ้ง user
    send_message(event, text_for_visual_append)


def echo(event):
    line_bot_api.reply_message(event.reply_token, TextSendMessage(text=event.message.text))


# function for sending message
def send_message(event, message):
    line_bot_api.reply_message(event.reply_token, TextSendMessage(text=message))
