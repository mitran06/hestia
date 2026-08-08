---
name: notes
description: "Use when you worked something out and it will still matter next week — a command sequence that finally worked, why a choice was made, how a system on this box actually behaves. Also use when MEMORY.md refuses a write for size, and before answering a question about how this box is set up."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [notes, vault, runbook, decisions, memory]
    related_skills: [obsidian]
---

# Operational notes

`$HESTIA_VAULT_RUNBOOK` is where **hard-won** things live: what you had to work out, and what would
cost you real effort to work out again.

Three stores, three jobs:

| Store | Holds |
|---|---|
| `MEMORY.md` | what is salient right now |
| Hindsight | what you and the owner have said to each other |
| **`notes/`** | **what you worked out, and what was decided** |

Hindsight already has every conversation. It has never seen a command you ran, its output, or the
fix you found on the third attempt — that is the gap `notes/` fills.

## Write a note when

- **A procedure worked**, especially after it failed first. The failures are the value.
- **Something was decided** — by you or the owner — that changes how this box runs.
- **A system behaved differently from its documentation**, and you confirmed how it really behaves.
- **MEMORY.md refuses a write for size.** That content moves here rather than being dropped.

Things you were simply told, and things you can look up in one command, stay in the other two
stores.

## Before writing: read `index.md`

`index.md` lists every note. Read it first and find the note this belongs in — a system already
has a page, a decision already has neighbours. Add to that note and bump its `updated`.

Start a new note when nothing in the index covers the subject. Then add its line to `index.md` and
append one line to `log.md`:

```
## [2026-08-06] update — systems/hindsight.md — recorded the port and the health command
```

## The note contract

Every note carries five keys:

```yaml
---
title: Restart the Hindsight server
type: how-to          # how-to | system | decision
updated: 2026-08-06
source: verified-by-doing   # verified-by-doing | told-by-owner | researched
status: current
---
```

`source` decides who wins when a note and a recall disagree: **`verified-by-doing` wins.**

**A `how-to` needs `## Steps` and `## Verify`.** Steps are the literal commands. Verify is the
command that proved it worked, with the output that means success. Write a `how-to` only for
something you actually ran — if you cannot fill `## Verify`, record it as a `system` note instead.

Keep a note under 200 lines. Past that, split it by subject.

## Research dumps

Long research output goes to `_raw/YYYY-MM-DD-topic.md` — the whole thing, written once and left
alone. This is the archive, and it is separate from the notes on purpose: the last vault died
because dumps and curated notes shared a folder.

Anything worth acting on later earns its own `how-to`, `system` or `decision` note. The dump is
where you go back for the detail those notes leave out.

Search `_raw/` with grep. Hindsight indexes conversations, not files, so it will not surface these.

## Reading and writing files

Use the `obsidian` skill for the file mechanics — it resolves the vault path from
`OBSIDIAN_VAULT_PATH` and handles the file tools correctly.
