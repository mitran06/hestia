# Conventions — the ownerVault

the owner reads and edits this vault on his phone. Write so it is useful to him, not to a machine.

## The spine: Current and History

Every note about a **thing that changes** — a person, a project, a course, a goal — carries two
sections:

```markdown
## Current
- <name> — <what they own>

## History
- 2026-06-20 → 2026-07-04: <name> — <old role> (reassigned to <name>)
```

`## Current` answers the question. `## History` keeps the trail. When a fact changes, move the old
line down to History with the date it stopped being true, and put the new fact in Current.

**This applies to facts the owner wrote too.** If he wrote something that is now out of date, update
Current and move his line to History. Nothing is deleted, so a wrong correction is always
recoverable. Keep his wording in his own reflective writing — journal prose, affirmations, anything
in his voice is the artifact itself.

Answers come from `## Current`. `Journal/` and `_inbox/` are evidence and chronology.

## Front matter

```yaml
---
type: person
created: 2026-08-07
updated: 2026-08-07
---
```

## Note types

Each type says: where it lives, what the filename looks like, and how to write it.

**inbox** — `_inbox/YYYY-MM-DDTHHMM--slug.md`. Every incoming message, verbatim, one file each.
Create it and leave it alone. Unique names mean two devices can never collide on the same file.

**journal** — `Journal/YYYY-MM-DD.md`. The day's log, first person, as the owner would write it.
Append under `## Log` as `- HH:MM — what happened`. Corrections are appended as new lines with the
time, so the day reads in order.

**person** — `People/<Name>.md`. Use the fullest name known; add other names under `## Also known as`
so a search finds them. Candid impressions live here and are quoted as the owner said them.

**project** — `Projects/<Name>.md`. Anything with people, resources and plans — a club, a build, a
trip. `## Current` carries who owns what and what is booked; `## Plan` carries intent; `## History`
carries what changed.

**course** — `Courses/<CODE>.md`. Materials, deadlines and quiz dates for one subject.

**list** — `Lists/<slug>.md`. Anything he keeps as a list: todos, reading, affirmations, and his
goals in `Lists/goals.md`. One line per item. A goal that grows its own deadlines, drafts and
sub-tasks has become a project — move it to `Projects/`.

**resource** — `Resources/<topic>.md`. Links he sends with a takeaway, grouped by topic. Write the
takeaway in his words; the link alone is not useful later.

## Dates

Resolve "friday" or "the 14th" to a full date and write the resolved date. When the year or month
was not stated, add the date he said it: `Seminar hall — 2026-07-14 (said 2026-06-21)`. If it cannot
be resolved, ask him.

## Adding a new type

When something arrives that fits no type above, add a section here first — where it lives, the
filename, how to write it — then write the note. New types inherit Current and History; that is what
keeps this file short and the vault consistent.

Prefer a new note in an existing folder over a new folder. A folder earns its place by volume: make
one when a type has enough notes that the existing folder is hard to scan.
