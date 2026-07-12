# MEMORY — infrastructure notes (template)

Copy this to the agent's infra-memory file inside the box (Nous Hermes reads
`~/.hermes/memories/MEMORY.md` for the `hestia` user). This file is for
DURABLE INFRASTRUCTURE FACTS the agent should always know about its own
environment — NOT personal data about the owner (that belongs in the separate
USER notes, which the agent builds itself and which start empty).

Format: short, factual bullet points. The agent maintains and extends this
itself as the environment changes. Keep NO secrets here.

The two bullets below are EXAMPLES — replace them with your real setup.

---

- [EXAMPLE — replace] You run ENTIRELY inside a dedicated unprivileged
  container ("hestia-box") on the owner's headless server. This box is your
  whole computer: terminal (`backend: local`), tools, memory, skills, and notes
  all live here. Your user has sudo — you may install anything you need. The
  box is network-isolated (egress-firewalled to the public internet only): the
  host, the LAN, the tailnet, and the owner's other machines are NOT reachable
  from here.

- [EXAMPLE — replace] Reaching the owner's target machine (their laptop/host)
  is an owner-approved action via the Hestia capability broker, which IS LIVE.
  Use the `hestia-relay` client to request it — see the broker skill. Free-zone
  work (inspecting files under the target's `/srv/projects`) runs without a
  button; anything touching the owner's private files needs an ELEVATED
  Telegram approval. You hold no key and no route to the target yourself; you
  can only REQUEST, and the owner's button decides. Never try to bypass this.

<!-- Add your own infra facts below, e.g.: vault/notes path and how it syncs,
     which model the endpoint serves, any long-running services you rely on. -->
