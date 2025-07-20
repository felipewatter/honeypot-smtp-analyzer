from aiosmtpd.handlers import Message
import logging
from utils.analyzer import analyze_message
from utils.logger import log_attempt

class HoneypotHandler(Message):
    async def handle_message(self, message):
        log_attempt(message)
        analysis = analyze_message(message)
        logging.info(f"Analysis: {analysis}")
        return "250 Message received"