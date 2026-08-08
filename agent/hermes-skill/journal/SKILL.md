---
name: journal
description: "Use when the owner tells you something about his own life — what he did, someone he met, a plan, a decision, a resource worth keeping, something to remember. Also use when he asks what, who, when or how-am-I-doing about his own life, club, courses or goals."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [journal, vault, obsidian, people, projects, goals]
    related_skills: [obsidian]
---

# the owner's vault

`$HESTIA_VAULT_OWNER` is the owner's own Obsidian vault. He reads and edits it on his phone. It is
his; you keep it useful.

**Read `_conventions.md` in that folder before you write.** It names every note type — where it
lives, the filename, how to write it — and it is the file that grows when something new comes along.
Read it every time; it changes.

## Capturing

When the owner tells you something about his life, do two things:

1. **Write the message to `_inbox/` unchanged**, one file per message. This is the receipt, and it
   is what makes his phone edits and your writes safe to happen at once.
2. **File it** into the note it belongs to, following `_conventions.md`.

Then tell him where it went, in one short line. He is on his phone and needs to know where to look.

## Keeping facts current

Things change — who owns a task, how much budget is left, when a quiz is. Put what is true now under
`## Current` and move the line it replaced into `## History` with the date it stopped being true.

This holds for lines the owner wrote as well as your own. Update his outdated facts and keep the old
line in History, so a wrong correction is always recoverable. His journal prose, reflections and
affirmations are his voice — add alongside them rather than rewriting them.

## Answering

Answer from `## Current` in the note that owns the fact. `Journal/` and `_inbox/` are the trail, not
the answer.

When you have looked and the vault does not say, tell him it does not say. If you answer from
memory of a conversation instead, say so — he edits this vault, so the file is right and your
recollection may be stale.

## Reading and writing files

The `obsidian` skill handles the file mechanics.
