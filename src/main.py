import asyncio
from aiosmtpd.controller import Controller
from core.handler import HoneypotHandler

if __name__ == "__main__":
    controller = Controller(HoneypotHandler(), hostname="0.0.0.0", port=25)
    controller.start()
    print("SMTP Honeypot is running on port 25...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()