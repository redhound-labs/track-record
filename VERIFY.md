# Verifying the Redhound track record

This repository publishes one thing daily: the **head of a hash chain** over
every graded trading signal we have recorded. Not the trades — the head.

That is deliberate, and this document explains exactly what it does and does
not let you check.

## The short version

Every graded outcome is appended to a ledger as a row whose hash includes the
hash of the row before it:

```
entry_hash = sha256( prev_hash ‖ canonical_json(row) )
```

starting from a genesis of 64 zeros. The last row's hash — the **chain head** —
therefore depends on every row, in order. Change a price, reorder two rows, or
delete an unfavourable one, and the head changes.

`manifest.json` in this repository contains that head. It is committed daily and
timestamped with [OpenTimestamps](https://opentimestamps.org), which anchors it
in the Bitcoin blockchain. So a given head can be shown to have existed on a
given date, by something we do not control.

When the underlying rows are disclosed, you re-derive the chain from them and
check it against a head that was fixed **before those outcomes were known**.
That ordering is the entire guarantee.

## What is in this repository

| File | What it is |
|---|---|
| `manifest.json` | Today's chain head, row count, and epoch boundaries |
| `manifest.json.ots` | OpenTimestamps proof for the manifest |
| `rekor.json` | Sigstore Rekor log entry (only if enabled) |
| `verify.py` | The verifier — dependency-free, stdlib only |
| `VERIFY.md` | This file |

`verify.py` was committed **before the first chain head**. Check its git
history: a head only commits us to a set of rows if the hashing algorithm was
pinned at the same time. Otherwise a convenient algorithm could be chosen later.

## What `manifest.json` says

```json
{
  "snapshot_date": "2026-08-13",
  "row_count": 214,
  "chain_head": "…64 hex chars…",
  "chain_ok": true,
  "first_bad_sequence": null,
  "columns": ["sequence", "signal_id", "…"],
  "epochs": [{"rules_hash": "…", "row_count": 214}]
}
```

- **`chain_ok`** — whether the ledger verified from genesis when the snapshot was
  taken. If this is ever `false`, it is published as `false`. A snapshot that
  hid a verification failure would defeat the point of having a chain.
- **`epochs`** — the record is scoped to one *rule surface*. Changing the rules
  (thresholds, the analyst set, how confidence is computed) starts a new epoch
  with a new `rules_hash`, and the statistics restart. Publishing the epoch
  boundaries daily means a rules change is visible on the day it happens rather
  than discovered afterwards, when it would look like cherry-picking.
- **`snapshot_date`** — part of the manifest, so its bytes change every day even
  when the ledger does not. A missing daily commit is therefore unambiguously a
  failure, not a quiet day.

## Checking a disclosed CSV

When we disclose a `ledger-<date>.csv`:

```bash
python3 verify.py ledger-2026-08-13.csv manifest.json
```

Nothing to install — Python 3.9+ and the standard library.

It re-derives every row's hash, walks the links back to genesis, and compares
the result against the head this repository published. Exit status 0 means it
verified **and** matched. Anything else prints what failed and where.

To check a head against a specific date rather than today's:

```bash
git log --oneline manifest.json          # find the day
git show <commit>:manifest.json > m.json
python3 verify.py ledger-2026-08-13.csv m.json
```

## Checking the timestamp

The git commit alone proves little — a repository owner could rewrite history.
The OpenTimestamps proof is the part that does not rely on trusting us:

```bash
pip install opentimestamps-client
ots verify manifest.json.ots            # needs manifest.json alongside it
```

It reports the Bitcoin block whose timestamp bounds when that exact manifest
existed. A proof for a recent day may still be *pending* — attestations take a
few hours to be included in a block, and each day's run upgrades any proofs
that have since completed.

## What this does not prove

Being precise about this matters more than the guarantee itself.

**It does not prove no signal was omitted.** The chain constrains the rows that
exist. It cannot speak about a signal that was never graded and never written.
Declining to record an unfavourable outcome sits outside what any hash chain can
detect. Two things narrow the gap and neither closes it:

- `sequence` is contiguous in an honest snapshot, so rows written and then
  withheld leave a gap — `verify.py` checks this.
- `epochs` makes a rules rotation visible the day it happens.

Beyond that it is a process commitment, not a cryptographic one, and we do not
claim otherwise.

**It does not prove the trades were profitable, or that you would have got the
same fills.** It proves the record was not edited after the fact. What the
record *says* is a separate question, answerable from the disclosed rows.

**It does not prove the rules were not tuned.** It proves that if they were, the
`rules_hash` changed and the epoch boundary is in the public record.

## Reporting a problem

If `verify.py` fails on data we published, that is significant regardless of
the cause — a verifier that rejects honest data is as serious as one that
accepts tampered data. Open an issue here with the command you ran and its
output.
