# Broker skills

Skills in this category teach the confined agent how to REQUEST actions on the
owner's target machine (their laptop/host) through the Hestia capability
broker.

The confined agent runs inside the network-isolated `hestia-box` container: it
can reach the public internet but has no key and no route to the owner's
machines. The ONLY gated path across that boundary is the `hestia-relay`
client, which drops a request into an outbox the broker reads. Every crossing
is decided by the owner tapping a Telegram button that is enforced OUTSIDE the
LLM — the agent can only ask, never grant.

- `omen-relay/` — how to use `hestia-relay` to run commands on the target
  machine: the free zone (no button) vs. elevated (red button), the approval
  flow, exit codes, moving files, and reporting results back to the owner.
