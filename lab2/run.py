#!/usr/bin/env python3
"""Entry point for the MeridianPay vulnerable lab (multi-service).

Usage:
    python3 run.py            # run all services
    python3 run.py --reset    # wipe + reseed the database and regenerate
                               # backup/statement files, then run
"""
import sys
import threading

from app import config, db, core
from services import backup_relay, ops_console, health_probe


def main():
    db.init_db(force="--reset" in sys.argv)
    if "--reset" in sys.argv:
        print("Database reset and reseeded.")

    threading.Thread(target=backup_relay.run, daemon=True).start()
    threading.Thread(target=ops_console.run, daemon=True).start()
    threading.Thread(target=health_probe.run, daemon=True).start()

    print("=" * 72)
    print("MeridianPay lab -- services starting on 127.0.0.1:")
    print(f"  Web app (banking portal)   http://{config.HOST}:{config.WEB_PORT}")
    print(f"  Ops console                http://{config.HOST}:{config.OPS_CONSOLE_PORT}")
    print(f"  Ops backup relay (FTP)     ftp://{config.HOST}:{config.BACKUP_RELAY_PORT}")
    print(f"  Health probe (banner)      tcp://{config.HOST}:{config.HEALTH_PROBE_PORT}")
    print("=" * 72)

    core.run()


if __name__ == "__main__":
    main()
