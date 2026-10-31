"""Non-relaying SMTP server built with aiosmtpd and asyncio; loopback by default."""

import argparse
import asyncio
import ipaddress
import logging
import signal
import sys
from pathlib import Path

from aiosmtpd.smtp import SMTP
from core.handler import HoneypotHandler
from utils.logger import DEFAULT_LOG_FILE

LOG = logging.getLogger(__name__)


def is_loopback(host):
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_parser():
    parser = argparse.ArgumentParser(
        prog="smtp-honeypot",
        description="SMTP capture and offline heuristic analysis; no relay or delivery.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--max-message-bytes", type=int, default=262144)
    parser.add_argument("--allow-public-bind", action="store_true")
    return parser


def make_smtp_protocol(handler, max_message_bytes):
    """Use the same protocol factory in production and integration tests."""
    return SMTP(
        handler,
        data_size_limit=max_message_bytes,
        decode_data=False,
        enable_SMTPUTF8=False,
        command_call_limit=100,
        timeout=60,
    )


async def serve(args):
    loop = asyncio.get_running_loop()
    shutdown = asyncio.Event()
    handler = HoneypotHandler(args.log_file, args.max_message_bytes)
    server = await loop.create_server(
        lambda: make_smtp_protocol(handler, args.max_message_bytes),
        host=args.host,
        port=args.port,
    )
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, shutdown.set)
        except (NotImplementedError, RuntimeError):
            # Windows does not support loop.add_signal_handler.
            signal.signal(signum, lambda _sig, _frame: loop.call_soon_threadsafe(shutdown.set))
    LOG.info("Honeypot listening at %s:%d; relay disabled", args.host, args.port)
    async with server:
        await shutdown.wait()


def main(argv=None):
    args = make_parser().parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")
    if not 1024 <= args.max_message_bytes <= 10485760:
        raise SystemExit("Message limit must be between 1024 and 10485760 bytes")
    if not is_loopback(args.host) and not args.allow_public_bind:
        raise SystemExit("Public binding requires --allow-public-bind and isolated deployment")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
