#!/usr/bin/env python3
"""Entry point for the NovaFreight vulnerable lab app.

Usage:
    python3 run.py            # run the server
    python3 run.py --reset    # wipe and reseed the database, then run
"""
import sys

from app import config, db, core


def main():
    if "--reset" in sys.argv:
        db.init_db(force=True)
        print("Database reset and reseeded.")
    core.run()


if __name__ == "__main__":
    main()
