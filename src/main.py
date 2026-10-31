"""Run a non-relaying SMTP honeypot; loopback by default."""

import argparse
import ipaddress
import logging
import signal
import sys
import threading
from pathlib import Path
from aiosmtpd.controller import Controller
from core.handler import HoneypotHandler
from utils.logger import DEFAULT_LOG_FILE


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


def main(argv=None):
    args = make_parser().parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")
    if not 1024 <= args.max_message_bytes <= 10485760:
        raise SystemExit("Message limit must be between 1024 and 10485760 bytes")
    if not is_loopback(args.host) and not args.allow_public_bind:
        raise SystemExit("Public binding requires --allow-public-bind and isolated deployment")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    controller = Controller(
        HoneypotHandler(args.log_file, args.max_message_bytes),
        hostname=args.host,
        port=args.port,
        data_size_limit=args.max_message_bytes,
        decode_data=False,
        enable_SMTPUTF8=False,
        command_call_limit=100,
        timeout=60,
    )
    shutdown = threading.Event()
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(signum, lambda _sig, _frame: shutdown.set())
            except (OSError, ValueError):
                pass
    started = False
    try:
        controller.start()
        started = True
        logging.info("Honeypot listening at %s:%d; relay disabled", args.host, args.port)
        shutdown.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if started:
            controller.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
