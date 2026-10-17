#!/usr/bin/env python3
"""Handle one home's verified statistics request, with Cloud stopped."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate request fields")
    return value


def handle_request(database, request, output, erase=False):
    info = request.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 4096:
        raise ValueError("request file must be private and at most 4096 bytes")
    case = json.loads(request.read_text(), object_pairs_hook=unique_object)
    if set(case) != {"case_id", "home", "identity_checked", "verified_by", "verified_at"}:
        raise ValueError("unexpected request fields")
    if any(not isinstance(case[key], str) for key in ("case_id", "home", "verified_by", "verified_at")):
        raise ValueError("request identifiers and timestamp must be text")
    uuid.UUID(case["case_id"])
    if not re.fullmatch(r"[a-z2-7]{26}", case["home"]) or case["identity_checked"] is not True:
        raise ValueError("a verified request for one home is required")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", case["verified_by"]):
        raise ValueError("a staff identifier is required")
    checked = dt.datetime.fromisoformat(case["verified_at"].replace("Z", "+00:00"))
    age = dt.datetime.now(dt.timezone.utc) - checked
    if not dt.timedelta(minutes=-5) <= age <= dt.timedelta(days=7):
        raise ValueError("identity check must be recent")

    db = sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True, timeout=0)
    try:
        # EXCLUSIVE locking mode also excludes existing WAL readers. Stop and
        # drain Cloud first; a normal WAL write transaction alone is not enough.
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA locking_mode=EXCLUSIVE")
        db.execute("BEGIN EXCLUSIVE")
        home = case["home"]
        if not db.execute("SELECT 1 FROM homes WHERE home=?", (home,)).fetchone():
            raise ValueError("home not found; do not guess another identifier")
        if erase:
            # Keep the hold across reconnects and policy changes. Only a
            # resolved rights case may remove it; an old box cannot do so.
            db.execute("PRAGMA secure_delete=ON")
            db.execute("INSERT OR IGNORE INTO statistics_restrictions(home) VALUES(?)", (home,))
            count = db.execute("DELETE FROM statistics_hours WHERE home=?", (home,)).rowcount
            db.execute("DELETE FROM statistics_grants WHERE home=?", (home,))
            db.commit()
            if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                raise sqlite3.OperationalError("WAL checkpoint incomplete")
            return {"case_id": case["case_id"], "erased_rows": count, "restricted": True}
        grant = db.execute("SELECT stats_id,since_ms,policy FROM statistics_grants WHERE home=?", (home,)).fetchone()
        hours = db.execute("SELECT hour_ms,metrics FROM statistics_hours WHERE home=? ORDER BY hour_ms", (home,)).fetchall()
        body = {"schema": "ftw.statistics-subject-export/1", "case_id": case["case_id"],
                "home": home, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "grant": {"statistics_id": grant[0].hex(), "since_ms": grant[1], "policy": grant[2]} if grant else None,
                "hours": [{"hour_ms": hour, "metrics": json.loads(metrics)} for hour, metrics in hours]}
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as dest:
                json.dump(body, dest, ensure_ascii=False, indent=2)
                dest.write("\n")
                dest.flush()
                os.fsync(dest.fileno())
        except BaseException:
            os.unlink(output)
            raise
        return {"case_id": case["case_id"], "rows": len(hours), "output": str(output)}
    finally:
        db.rollback()
        db.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--request", type=Path, required=True)
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--erase", action="store_true", help="erase statistics and restrict this home's Cloud pending the rights case")
    a = p.parse_args()
    try:
        print(json.dumps(handle_request(a.database, a.request, a.output, a.erase)))
    except (OSError, ValueError, TypeError, sqlite3.Error) as error:
        print("Request incomplete: " + type(error).__name__ + ". Check the request and database state before retrying; keep Cloud stopped.", file=sys.stderr)
        sys.exit(1)
