#!/usr/bin/env python3
"""Code & Conflict Backend Management CLI.

Commands:
    stats          - Show database record counts and system status
    prune-resets   - Invalidate or purge expired password reset tokens
    list-messages  - View recent contact messages submitted to the portal
    vacuum         - Optimize SQLite database file size and rebuild indexes

Usage:
    python3 backend/cli.py stats
    python3 backend/cli.py prune-resets
    python3 backend/cli.py list-messages
    python3 backend/cli.py vacuum
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('CC_DB') or os.path.join(HERE, 'data.db')


def get_conn():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database file does not exist at: {DB_PATH}")
        sys.exit(1)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def cmd_stats():
    con = get_conn()
    try:
        users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        messages = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        resets_active = con.execute(
            "SELECT COUNT(*) FROM password_resets WHERE used = 0 AND expires_at > ?",
            (datetime.now(timezone.utc).isoformat(),)
        ).fetchone()[0]
        size_kb = os.path.getsize(DB_PATH) / 1024

        print("=" * 45)
        print("  Code & Conflict Database Statistics")
        print("=" * 45)
        print(f" Database Path:         {DB_PATH}")
        print(f" Database Size:         {size_kb:.2f} KB")
        print(f" Registered Accounts:   {users}")
        print(f" Contact Inquiries:     {messages}")
        print(f" Active Reset Tokens:   {resets_active}")
        print("=" * 45)
    finally:
        con.close()


def cmd_prune_resets():
    con = get_conn()
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        cur = con.execute("DELETE FROM password_resets WHERE used = 1 OR expires_at <= ?", (now_iso,))
        con.commit()
        print(f"[*] Pruned {cur.rowcount} expired/consumed password reset records.")
    finally:
        con.close()


def cmd_list_messages(limit=10):
    con = get_conn()
    try:
        rows = con.execute(
            "SELECT id, name, email, subject, message, created FROM messages ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        if not rows:
            print("[i] No contact messages stored.")
            return

        print(f"Showing last {len(rows)} contact message(s):\n")
        for r in rows:
            print(f"ID #{r['id']} | Date: {r['created']}")
            print(f"From: {r['name']} <{r['email']}>")
            print(f"Subject: {r['subject']}")
            print(f"Message: {r['message']}")
            print("-" * 45)
    finally:
        con.close()


def cmd_vacuum():
    con = get_conn()
    try:
        before = os.path.getsize(DB_PATH) / 1024
        con.execute("VACUUM;")
        con.execute("REINDEX;")
        after = os.path.getsize(DB_PATH) / 1024
        print(f"[*] SQLite VACUUM complete: {before:.2f} KB -> {after:.2f} KB.")
    finally:
        con.close()


def main():
    parser = argparse.ArgumentParser(description="Code & Conflict Senior Backend Admin CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("stats", help="Display database records count and size")
    subparsers.add_parser("prune-resets", help="Delete expired or used reset tokens")
    subparsers.add_parser("vacuum", help="Defragment and optimize SQLite database")
    
    msg_parser = subparsers.add_parser("list-messages", help="Display recent contact inbox messages")
    msg_parser.add_argument("--limit", type=int, default=10, help="Number of records to display")

    args = parser.parse_args()
    if args.command == "stats":
        cmd_stats()
    elif args.command == "prune-resets":
        cmd_prune_resets()
    elif args.command == "list-messages":
        cmd_list_messages(args.limit)
    elif args.command == "vacuum":
        cmd_vacuum()


if __name__ == "__main__":
    main()

