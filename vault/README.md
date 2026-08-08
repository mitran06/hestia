# Vaults (memory layer 3)

Plain markdown in folders. No database, no new tools — the agent's existing file tools and its
`obsidian` skill handle the mechanics.

Two vaults, different owners and different jobs:

| | Owner vault | Runbook vault |
|---|---|---|
| Written by | agent, from the owner's messages | agent, about its own work |
| Read by | **the owner**, on their phone | the agent |
| Holds | journal, people, projects, courses, lists, resources | verified procedures, decisions |
| Trigger | the owner texts something | none reliable — see below |

## The spine: Current and History

Every note about something that changes carries `## Current` (what is true now) and `## History`
(what it replaced, dated). Answers come from `## Current`; the daily journal is evidence.

This applies to lines the owner wrote too: update the fact, move the old line to History. Nothing is
deleted, so a wrong correction is recoverable. Their own prose — journal entries, reflections — is
the artifact; add alongside it.

## Extensibility

`_conventions.example.md` names each note type in a few lines. A new type is a new section there,
not new code. New types inherit Current/History, which is what keeps the file short.

Prefer a new note in an existing folder over a new folder. **A folder earns its place by volume.**

## Capture safety

Each incoming message is written to `_inbox/` as its own uniquely-named file, never edited after.
Two devices cannot collide on a file that only one of them creates — this removes sync conflicts
structurally rather than trying to merge them.

## Monitoring

`vault-digest.sh` (weekly) and `vault-alarm.sh` (daily) run as plain scripts with **no LLM**. The
digest **sends even when every number is zero** — a vault dies by going quiet, and a missing message
is far harder to notice than one reading `0 new, last write 34d ago`.

## Known limitation

The runbook vault has **no reliable write trigger**. Tested directly: given content that matched
existing notes, the agent wrote to `MEMORY.md` and to Hindsight and left the vault untouched — a
skill instructing otherwise changed nothing. It considers the job done once the other layers have
it. The owner vault does not have this problem because the owner initiates every write.

Treat the runbook vault as an experiment. If the weekly digest still reports `0 new` after a month,
delete it rather than nurse it.
