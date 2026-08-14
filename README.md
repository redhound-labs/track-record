# Redhound track record

A daily, publicly timestamped commitment to the trading signals Redhound has
graded — published so the record can be checked rather than believed.

**Status: publishing.** The genesis commit published the verifier and nothing
else. That ordering is deliberate: a chain head only commits us to a set of rows
if the hashing algorithm was pinned *before* the head existed. Otherwise a
convenient algorithm could be chosen later. Every commit since is one day's
chain head.

## What gets published here

Every graded outcome is appended to a hash-chained ledger, where each row's
hash includes the hash of the row before it. The last row's hash — the **chain
head** — therefore depends on every row, in order. Edit a price, reorder two
rows, or delete an unfavourable one, and the head changes.

Only that head is published, daily, and timestamped with
[OpenTimestamps](https://opentimestamps.org) (anchored in Bitcoin). The rows
themselves stay private. When they are disclosed, anyone can re-derive the
chain and check it against a head that was fixed months earlier, before those
outcomes were known.

| File | What it is |
|---|---|
| `verify.py` | The verifier. Standard library only — nothing to install. |
| `VERIFY.md` | How to check a disclosed ledger, and what this does not prove. |
| `heads/manifest-<date>.json` | That day's chain head, row count, and epoch boundaries. Written once, never modified. |
| `heads/manifest-<date>.json.ots` | OpenTimestamps proof for that day's head. |
| `manifest.json` | A copy of the most recent head, for convenience. Rewritten daily. |

Each day gets its own head file and its own proof. Verify the **dated** pair —
`manifest.json` is rewritten daily, so it stops matching any older proof by
design.

## Start here

**[VERIFY.md](VERIFY.md)** — including an honest account of the limits. The
chain constrains the rows that exist; it cannot speak about a row that was
never written. That gap is narrowed by publishing epoch boundaries and by
`sequence` being gap-free, and it is not claimed to be closed.
