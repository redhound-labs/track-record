#!/usr/bin/env python3
"""Verify a Redhound track-record snapshot against its published chain head.

    python3 verify.py ledger-2026-08-13.csv manifest.json

Exit status is 0 only if every row's digest reproduces, every link holds back
to genesis, and the resulting head equals the one in the manifest.

WHAT THIS PROVES
----------------
Each ledger row's hash is sha256(previous_row_hash || canonical_json(payload)),
starting from a 64-zero genesis. The final hash therefore binds the *entire
ordered history*: edit a price, reorder two rows, or delete an unfavourable
one, and every hash from that point forward changes.

`manifest.json` — carrying only the head, never the rows — is committed daily
to a public repository and timestamped (OpenTimestamps, anchored in Bitcoin;
and Rekor). So the head for any given day can be shown to have existed on that
day. When the CSV is disclosed later, this script re-derives the chain from the
raw rows and checks it against a head that was fixed before those outcomes were
known. That ordering is the entire guarantee.

For that to mean anything, the *algorithm* must also be pinned in advance —
otherwise a convenient hash function could be chosen at disclosure time. This
file is committed once, at genesis, before any head is published, and its git
history is public. Check it.

WHAT THIS DOES NOT PROVE
------------------------
The chain constrains the rows that exist. It says nothing about rows that were
never written. Declining to grade an unfavourable signal is outside the
guarantee, and no hash chain can close that gap.

Two things narrow it. `epochs` in the manifest publishes every distinct
`rules_hash` with its row count, so a change to the rule surface — which
restarts the track record — is visible on the day it happens rather than
discovered afterwards. And `sequence` is contiguous and gap-free in an honest
snapshot: a gap means rows were written and then withheld. This script checks
both, but neither is a cryptographic guarantee, and they are not claimed as one.

STANDARD LIBRARY ONLY — no installs required, on purpose. It is a copy of the
production hashing path (`backend/services/outcome_ledger.py` +
`backend/services/rules_epoch.py`); `tests/scripts/test_verify_vendored.py` in
the Redhound repository re-derives whole chains through both copies to keep
them identical.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import uuid
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

# Column order of ledger-<date>.csv. `sequence` first so a human diff reads in
# chain order.
SNAPSHOT_COLUMNS = [
    "sequence",
    "signal_id",
    "symbol",
    "action",
    "rules_hash",
    "horizon",
    "entry_date",
    "exit_date",
    "entry_price",
    "exit_price",
    "adjusted",
    "gross_return",
    "spy_return",
    "sector_return",
    "sector_etf",
    "dollar_volume",
    "dollar_volume_median_20d",
    "reason",
    "graded_at",
    "prev_hash",
    "entry_hash",
]

# The fields that go INTO the digest: everything except the two chain columns
# (a row cannot hash its own hash). The database's surrogate `id` is excluded
# too, and is not exported at all.
PAYLOAD_COLUMNS = [c for c in SNAPSHOT_COLUMNS if c not in ("prev_hash", "entry_hash")]

# Declared scale of each NUMERIC column in the database. Postgres rounds any
# value to its column's scale at write time, so the digest is computed over the
# rounded value — see `quantize()`.
NUMERIC_SCALES = {
    "entry_price": 6,
    "exit_price": 6,
    "gross_return": 6,
    "spy_return": 6,
    "sector_return": 6,
    "dollar_volume": 2,
    "dollar_volume_median_20d": 2,
}

# Booleans are stored as booleans (not 0/1) and serialize as JSON true/false.
BOOLEAN_COLUMNS = frozenset({"adjusted"})

INTEGER_COLUMNS = frozenset({"sequence"})

# Nullable columns. Everything else must carry a value; an empty field in one
# of them is a malformed export, not a NULL.
NULLABLE_COLUMNS = frozenset(
    {
        "spy_return",
        "sector_return",
        "sector_etf",
        "dollar_volume",
        "dollar_volume_median_20d",
    }
)

_FLOAT_PRECISION = 6


# ---------------------------------------------------------------------------
# Canonical JSON — the exact bytes that get hashed.
# ---------------------------------------------------------------------------


def normalize_for_hash(value: Any) -> Any:
    """Render a value into a form that serializes identically everywhere.

    Floats become fixed-precision strings so 0.1 + 0.2 and 0.3 cannot disagree.
    `bool` is tested before `int` because in Python `bool` IS an `int`, and
    `True` must serialize as `true`, not `1`.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        return f"{value:.{_FLOAT_PRECISION}f}"
    if isinstance(value, dict):
        return {str(k): normalize_for_hash(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_for_hash(v) for v in value]
    return value


def canonical_json(payload: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace, ASCII-escaped."""
    return json.dumps(
        normalize_for_hash(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def quantize(entry: dict[str, Any]) -> dict[str, Any]:
    """Round every NUMERIC field to its column's declared scale.

    Postgres rounds half-away-from-zero when storing into NUMERIC(p, s), so
    the value the database holds — and therefore the value that was hashed —
    is the rounded one. Applying the same rounding here means a CSV carrying
    unrounded digits still reproduces the digest.
    """
    out = dict(entry)
    for key, scale in NUMERIC_SCALES.items():
        value = out.get(key)
        if value is None:
            continue
        as_decimal = value if isinstance(value, Decimal) else Decimal(str(value))
        out[key] = as_decimal.quantize(Decimal(1).scaleb(-scale), rounding=ROUND_HALF_UP)
    return out


def coerce_payload(entry: dict[str, Any]) -> dict[str, Any]:
    """Collapse every value to one canonical shape per type.

    A row read from this CSV arrives as text and Decimals; the same row read
    out of the database arrives as Decimal/date/datetime/UUID. Both must hash
    identically, so dates and timestamps are rendered with `.isoformat()` —
    NOT `str()`, which separates date and time with a space instead of a 'T'.
    Values that are already ISO strings (the CSV path) pass through unchanged,
    since that is the same text.
    """
    out: dict[str, Any] = {}
    for key, value in entry.items():
        if isinstance(value, Decimal):
            out[key] = float(value)
        elif isinstance(value, (datetime, date)):
            out[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            out[key] = str(value)
        else:
            out[key] = value
    return out


def compute_entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """sha256(prev_hash || canonical_json(payload)).

    Order is load-bearing: quantize (match what the database stores), then
    coerce (one shape per value), then canonical_json (fixed float precision).
    """
    payload = {k: v for k, v in coerce_payload(quantize(entry)).items() if k in PAYLOAD_COLUMNS}
    return hashlib.sha256((prev_hash + canonical_json(payload)).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# CSV -> typed payload.
# ---------------------------------------------------------------------------


def parse_row(raw: dict[str, str]) -> dict[str, Any]:
    """Turn one CSV row of text back into the typed payload that was hashed.

    Every field in a CSV is a string; the digest is computed over ints, bools,
    Decimals and None. Getting any of these wrong changes the JSON shape and
    so the hash — which would look exactly like tampering. Anything
    unrecognised raises rather than defaulting, because a silent coercion here
    could let an altered file verify.
    """
    row: dict[str, Any] = {}
    for column in PAYLOAD_COLUMNS:
        if column not in raw:
            raise ValueError(f"missing column {column!r} — not a Redhound ledger export")
        text = raw[column]
        text = "" if text is None else text.strip()

        if text == "":
            if column not in NULLABLE_COLUMNS:
                raise ValueError(f"empty value in non-nullable column {column!r}")
            row[column] = None
        elif column in INTEGER_COLUMNS:
            row[column] = int(text)
        elif column in BOOLEAN_COLUMNS:
            if text not in ("True", "False"):
                raise ValueError(f"column {column!r} is not a boolean: {text!r}")
            row[column] = text == "True"
        elif column in NUMERIC_SCALES:
            row[column] = Decimal(text)
        else:
            row[column] = text
    return row


def read_rows(csv_path: Path) -> list[tuple[dict[str, Any], str, str]]:
    """(payload, prev_hash, entry_hash) per CSV row, in file order.

    Rows are NOT re-sorted. The published order is part of what the chain
    commits to, so a reordered file must fail verification rather than be
    quietly repaired.
    """
    with Path(csv_path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [
            (parse_row(raw), raw["prev_hash"].strip(), raw["entry_hash"].strip()) for raw in reader
        ]


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------


def verify_csv(csv_path: Path) -> dict[str, Any]:
    """Replay the chain forward from genesis. Returns the outcome as a dict.

    Stops at the first failure and reports its `sequence`: everything after a
    break is unverifiable anyway, so a list of downstream failures would only
    obscure where the history was actually altered.
    """
    rows = read_rows(csv_path)

    expected_prev = GENESIS_HASH
    expected_sequence = 1
    first_bad: int | None = None
    problems: list[str] = []
    epochs: list[dict[str, Any]] = []
    epoch_index: dict[str, int] = {}

    for payload, prev_hash, entry_hash in rows:
        sequence = payload["sequence"]

        rules_hash = payload["rules_hash"]
        if rules_hash in epoch_index:
            epochs[epoch_index[rules_hash]]["row_count"] += 1
        else:
            epoch_index[rules_hash] = len(epochs)
            epochs.append({"rules_hash": rules_hash, "row_count": 1})

        if first_bad is not None:
            continue

        if sequence != expected_sequence:
            problems.append(
                f"sequence gap: expected {expected_sequence}, found {sequence}. "
                "The ledger is contiguous when complete — a gap means rows are missing."
            )
            first_bad = sequence
            continue
        if prev_hash != expected_prev:
            problems.append(
                f"sequence {sequence}: prev_hash does not link to the previous row "
                f"(expected {expected_prev}, found {prev_hash})"
            )
            first_bad = sequence
            continue
        if compute_entry_hash(expected_prev, payload) != entry_hash:
            problems.append(
                f"sequence {sequence}: row content does not reproduce its own entry_hash "
                "— this row was altered after it was written"
            )
            first_bad = sequence
            continue

        expected_prev = entry_hash
        expected_sequence = sequence + 1

    return {
        "chain_ok": first_bad is None,
        "first_bad_sequence": first_bad,
        "chain_head": expected_prev if rows and first_bad is None else None,
        "row_count": len(rows),
        "epochs": epochs,
        "problems": problems,
    }


def check_manifest(manifest: dict[str, Any], result: dict[str, Any]) -> list[str]:
    """Compare a verified CSV against the head that was published for it.

    A chain that verifies internally is not enough. Anyone can rewrite the
    whole history and re-hash it; what they cannot do is reproduce the head
    that was timestamped before those outcomes were known. This comparison is
    where the timestamp does its work.
    """
    problems: list[str] = []

    published_head = manifest.get("chain_head")
    if published_head != result["chain_head"]:
        problems.append(
            f"chain_head mismatch: the CSV derives {result['chain_head']}, but the "
            f"published manifest committed to {published_head}. The rows do not match "
            "what was timestamped."
        )

    published_count = manifest.get("row_count")
    if published_count != result["row_count"]:
        problems.append(
            f"row_count mismatch: CSV has {result['row_count']} rows, "
            f"manifest published {published_count}."
        )

    published_epochs = manifest.get("epochs")
    if published_epochs is not None and published_epochs != result["epochs"]:
        problems.append(
            f"epochs mismatch: CSV shows {result['epochs']}, manifest published {published_epochs}."
        )

    if manifest.get("chain_ok") is False:
        problems.append(
            "the publisher's own manifest recorded chain_ok=false"
            f" (first_bad_sequence={manifest.get('first_bad_sequence')}) — the chain was "
            "already known to be broken when this snapshot was published."
        )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Redhound track-record snapshot.",
        epilog="Exit status 0 means the chain verifies and matches the published head.",
    )
    parser.add_argument("csv", type=Path, help="ledger-<date>.csv")
    parser.add_argument(
        "manifest",
        type=Path,
        nargs="?",
        help="manifest.json holding the published chain head. Omit to check only "
        "that the CSV is internally consistent.",
    )
    args = parser.parse_args(argv)

    result = verify_csv(args.csv)

    print(f"rows:       {result['row_count']}")
    print(f"chain head: {result['chain_head']}")
    for epoch in result["epochs"]:
        print(f"epoch:      {epoch['rules_hash']}  ({epoch['row_count']} rows)")

    problems = list(result["problems"])
    if args.manifest is None:
        print(
            "\nNOTE: no manifest given. This checks only that the CSV is internally "
            "consistent — it does NOT check the rows against a published, timestamped "
            "head, which is the part that proves the record was not written after the "
            "fact."
        )
    else:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        problems.extend(check_manifest(manifest, result))
        print(f"manifest:   {args.manifest} (snapshot_date={manifest.get('snapshot_date')})")

    if problems:
        print("\nFAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        "\nOK — chain verifies from genesis"
        + ("" if args.manifest is None else " and matches the published head")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
