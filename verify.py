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

RE-BASELINING — READ THIS BEFORE TRUSTING `chain_ok`
----------------------------------------------------
A manifest may carry `rebaseline_sequence`. When it does, the publisher is
saying: verification of the live record starts HERE, anchored on this row's
stored `prev_hash`, and I no longer claim that everything before it verifies
from genesis. This script honours that split and then does the thing that
keeps it honest — it replays the discarded prefix from genesis anyway and
prints the result next to the headline one. A re-baseline can narrow the
claim; it cannot make the old rows go unchecked.

Understand what it costs. Inside the re-baselined prefix, an altered row no
longer fails the headline check. Cryptography does not constrain that; only
publication does. The boundary and its stated reason are committed and
timestamped daily alongside the head, so a boundary that moves — or one that
appears the same week an unfavourable row was written — is visible in the
public repository's git history. That history is the check. Read it.

A boundary at or before the first row in the file is rejected outright: it
would re-derive the entire history onto itself and prove nothing. So is one
that names a row the file does not contain, and one with no stated reason.

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


def _replay(
    rows: list[tuple[dict[str, Any], str, str]],
    *,
    anchor: str,
    label: str,
) -> dict[str, Any]:
    """Replay one contiguous run of rows against a starting hash.

    `anchor` is GENESIS_HASH for a full walk, or — for a re-baselined segment —
    the first row's own stored `prev_hash`, accepted as given rather than
    re-derived. That acceptance is the entire cost of a re-baseline, and it is
    why `verify_csv` never runs a segment walk without also running the full
    one and reporting both.

    Stops at the first failure and reports its `sequence`: everything after a
    break is unverifiable anyway, so a list of downstream failures would only
    obscure where the history was actually altered.
    """
    expected_prev = anchor
    expected_sequence = rows[0][0]["sequence"] if rows else 1
    first_bad: int | None = None
    problems: list[str] = []

    for payload, prev_hash, entry_hash in rows:
        if first_bad is not None:
            break
        sequence = payload["sequence"]

        if sequence != expected_sequence:
            problems.append(
                f"{label}sequence gap: expected {expected_sequence}, found {sequence}. "
                "The ledger is contiguous when complete — a gap means rows are missing."
            )
            first_bad = sequence
            continue
        if prev_hash != expected_prev:
            problems.append(
                f"{label}sequence {sequence}: prev_hash does not link to the previous row "
                f"(expected {expected_prev}, found {prev_hash})"
            )
            first_bad = sequence
            continue
        if compute_entry_hash(expected_prev, payload) != entry_hash:
            problems.append(
                f"{label}sequence {sequence}: row content does not reproduce its own "
                "entry_hash — this row was altered after it was written"
            )
            first_bad = sequence
            continue

        expected_prev = entry_hash
        expected_sequence = sequence + 1

    return {
        "chain_ok": first_bad is None,
        "first_bad_sequence": first_bad,
        "chain_head": expected_prev if rows and first_bad is None else None,
        "problems": problems,
    }


def _collect_epochs(rows: list[tuple[dict[str, Any], str, str]]) -> list[dict[str, Any]]:
    """Distinct `rules_hash` values with row counts, in first-appearance order.

    Counted over EVERY row, including ones before a re-baseline boundary and
    ones after a break. An epoch census that silently stopped at the first bad
    row would under-report a rule change that happened later in the file.
    """
    epochs: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for payload, _prev, _entry in rows:
        rules_hash = payload["rules_hash"]
        if rules_hash in index:
            epochs[index[rules_hash]]["row_count"] += 1
        else:
            index[rules_hash] = len(epochs)
            epochs.append({"rules_hash": rules_hash, "row_count": 1})
    return epochs


def verify_csv(csv_path: Path, *, rebaseline_sequence: int | None = None) -> dict[str, Any]:
    """Replay the chain and report what verifies. Returns the outcome as a dict.

    With no `rebaseline_sequence` this is a single walk from genesis and
    `chain_ok` means what it has always meant.

    With one, the file is split at that sequence and BOTH halves are replayed:
    the prefix from genesis (reported as `legacy_*`) and the segment from the
    boundary row's own stored `prev_hash` (reported as `chain_ok`). The prefix
    walk is not optional and its result is never suppressed — a re-baseline is
    a publisher declaring which rows it still stands behind, and the only thing
    that keeps that honest is that the rows it no longer stands behind are
    checked and reported anyway.

    ⚠️ Read `chain_ok` together with `rebaseline_sequence`. On a re-baselined
    snapshot it is a claim about the segment, not about the history.
    """
    rows = read_rows(csv_path)
    epochs = _collect_epochs(rows)
    problems: list[str] = []

    legacy = _replay(rows, anchor=GENESIS_HASH, label="")

    if rebaseline_sequence is None:
        result = dict(legacy)
        result.update(
            {
                "row_count": len(rows),
                "epochs": epochs,
                "rebaseline_sequence": None,
                "legacy_chain_ok": legacy["chain_ok"],
                "legacy_first_bad_sequence": legacy["first_bad_sequence"],
                "problems": list(legacy["problems"]),
            }
        )
        return result

    sequences = [payload["sequence"] for payload, _p, _e in rows]
    if rebaseline_sequence <= (sequences[0] if sequences else 1):
        # A boundary at or before the first row is a re-genesis of the whole
        # file: it would verify any history at all, including one written this
        # morning. Refuse rather than print a reassuring line about it.
        problems.append(
            f"rebaseline_sequence {rebaseline_sequence} is at or before the first row "
            "in this file, which would re-baseline the entire history onto itself. "
            "That verifies nothing."
        )
    elif rebaseline_sequence not in sequences:
        problems.append(
            f"rebaseline_sequence {rebaseline_sequence} names a row that is not in this "
            "file, so the segment it claims to verify cannot be located."
        )

    if problems:
        return {
            "chain_ok": False,
            "first_bad_sequence": rebaseline_sequence,
            "chain_head": None,
            "row_count": len(rows),
            "epochs": epochs,
            "rebaseline_sequence": rebaseline_sequence,
            "legacy_chain_ok": legacy["chain_ok"],
            "legacy_first_bad_sequence": legacy["first_bad_sequence"],
            "problems": problems + list(legacy["problems"]),
        }

    split = sequences.index(rebaseline_sequence)
    segment = rows[split:]
    segment_result = _replay(segment, anchor=segment[0][1], label="")

    return {
        "chain_ok": segment_result["chain_ok"],
        "first_bad_sequence": segment_result["first_bad_sequence"],
        "chain_head": segment_result["chain_head"],
        "row_count": len(rows),
        "epochs": epochs,
        "rebaseline_sequence": rebaseline_sequence,
        "legacy_chain_ok": legacy["chain_ok"],
        "legacy_first_bad_sequence": legacy["first_bad_sequence"],
        "problems": list(segment_result["problems"]),
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

    rebaseline = manifest.get("rebaseline_sequence")
    if rebaseline is not None:
        if not str(manifest.get("rebaseline_reason") or "").strip():
            problems.append(
                f"the manifest declares rebaseline_sequence={rebaseline} but gives no "
                "rebaseline_reason. A boundary with no stated reason is not "
                "distinguishable from one placed to skip an inconvenient row."
            )
        for field in ("legacy_chain_ok", "legacy_first_bad_sequence"):
            if field not in manifest:
                problems.append(
                    f"the manifest declares a re-baseline but omits {field!r}. A "
                    "re-baselined snapshot must publish what it no longer claims, "
                    "not only what it still does."
                )
        published_legacy = manifest.get("legacy_chain_ok")
        if "legacy_chain_ok" in manifest and published_legacy != result["legacy_chain_ok"]:
            problems.append(
                f"legacy_chain_ok mismatch: this file derives {result['legacy_chain_ok']}, "
                f"the manifest published {published_legacy}."
            )
        published_legacy_bad = manifest.get("legacy_first_bad_sequence")
        if (
            "legacy_first_bad_sequence" in manifest
            and published_legacy_bad != result["legacy_first_bad_sequence"]
        ):
            problems.append(
                "legacy_first_bad_sequence mismatch: this file derives "
                f"{result['legacy_first_bad_sequence']}, the manifest published "
                f"{published_legacy_bad}. The frozen prefix is not the one that was "
                "frozen."
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
    parser.add_argument(
        "--rebaseline",
        type=int,
        default=None,
        metavar="SEQUENCE",
        help="Verify the segment from SEQUENCE onward, anchored on that row's own "
        "prev_hash, instead of requiring the whole file to verify from genesis. "
        "Normally read from the manifest; pass it here to check a claimed boundary "
        "without one. The from-genesis walk still runs and is still reported.",
    )
    args = parser.parse_args(argv)

    # The manifest is read BEFORE verification, because it is what declares
    # whether a re-baseline is in force — and therefore what `chain_ok` is even
    # a claim about. `--rebaseline` exists so the CSV can still be checked
    # against a claimed boundary when no manifest is to hand; it cannot silence
    # one, since the from-genesis walk runs either way.
    manifest: dict[str, Any] | None = None
    if args.manifest is not None:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    rebaseline = args.rebaseline
    if rebaseline is None and manifest is not None:
        rebaseline = manifest.get("rebaseline_sequence")

    result = verify_csv(args.csv, rebaseline_sequence=rebaseline)

    print(f"rows:       {result['row_count']}")
    print(f"chain head: {result['chain_head']}")
    for epoch in result["epochs"]:
        print(f"epoch:      {epoch['rules_hash']}  ({epoch['row_count']} rows)")

    problems = list(result["problems"])

    if rebaseline is not None:
        reason = str((manifest or {}).get("rebaseline_reason") or "").strip()
        print(
            f"\n{'=' * 70}\n"
            f"RE-BASELINED SNAPSHOT — verification restarts at sequence {rebaseline}.\n"
            f"{'=' * 70}\n"
            f"'chain head' and the OK/FAIL below describe sequences {rebaseline} and\n"
            "onward ONLY. Rows before that boundary are replayed from genesis too,\n"
            "and reported here, but the publisher no longer claims they verify:\n"
            f"\n  rows before {rebaseline}: "
            + ("verify from genesis" if result["legacy_chain_ok"] else "DO NOT verify")
            + (
                ""
                if result["legacy_chain_ok"]
                else f" (first failure at sequence {result['legacy_first_bad_sequence']})"
            )
            + "\n\nA re-baseline weakens the guarantee over everything before the boundary:\n"
            "a row altered there would no longer fail the headline check. What limits\n"
            "that is publication, not cryptography — the boundary and its reason are\n"
            "committed and timestamped daily, so moving the boundary later is itself\n"
            "visible in the public repository's history. Check it.\n"
            + (f"\nStated reason:\n  {reason}\n" if reason else "")
        )

    if args.manifest is None:
        print(
            "\nNOTE: no manifest given. This checks only that the CSV is internally "
            "consistent — it does NOT check the rows against a published, timestamped "
            "head, which is the part that proves the record was not written after the "
            "fact."
        )
    else:
        assert manifest is not None
        problems.extend(check_manifest(manifest, result))
        print(f"manifest:   {args.manifest} (snapshot_date={manifest.get('snapshot_date')})")

    if problems:
        print("\nFAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    # The scope of the claim is stated in the success line itself. "verifies
    # from genesis" on a re-baselined snapshot would be false in exactly the
    # way this whole mechanism exists to avoid.
    scope = (
        "from genesis"
        if rebaseline is None
        else f"from the re-baseline at sequence {rebaseline} (NOT from genesis)"
    )
    print(
        f"\nOK — chain verifies {scope}"
        + ("" if args.manifest is None else " and matches the published head")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
