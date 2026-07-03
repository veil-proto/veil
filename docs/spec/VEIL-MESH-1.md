# VEIL-MESH-1

**Status:** DRAFT (milestone-1 scope). This is a *new* workstream, not a v0
appendix to an existing target doc (see `VEIL-CONTROL-1.md`,
`VEIL-TOKENS-1.md` for that pattern) — there is no prior "target v1" mesh
design in `VEIL_FINAL_DEVELOPMENT_SPEC.md` to reconcile against. Written
before any mesh-specific wire-shape code, per this project's rule that the
implementation must not move faster than the specs (`docs/ROADMAP.md` §9).

Cross-refs: `docs/ROADMAP.md` §9 (mesh workstream tracking, sync matrix),
`VEIL-CONTROL-1.md` (why `MESH_INTRO` is a narrow one-off frame and not part
of the general control-frame layer), `VEIL-TOKENS-1.md` (rendezvous-token
target concept — not used here, see Non-goals), `VEIL-INVARIANTS-1.md`
(invariants this design must not violate).

## 1. Scope

Today's topology is strictly static point-to-point / hand-configured star:
one config file, a static peer list, each peer with one fixed `Endpoint` (or
none — server-side, responder-only) and static `AllowedIPs`. No discovery, no
relay, no P2P.

Target for this milestone: **star + opportunistic P2P**. The existing
server-with-many-peers pattern becomes the hub. Two clients already connected
to the same hub attempt a direct P2P link when NAT allows; when it doesn't,
traffic between them continues to flow through the hub exactly as it does
today (relay, not a failure state).

This document covers three pieces end to end:

1. `MESH_INTRO` — the frame the hub uses to introduce two of its clients to
   each other.
2. NAT traversal milestone-1 — simultaneous-open UDP hole punching using the
   existing 2-message handshake, unmodified.
3. Hub relay fallback — how the hub forwards data between two clients that
   haven't (yet, or ever) established a direct path.

## 2. Non-goals (explicitly deferred beyond milestone-1)

- **Symmetric NAT traversal.** Milestone-1's hole punch works for
  full-cone/restricted-cone/port-restricted-cone NATs on both sides (the
  common case for home/mobile routers). Two peers behind symmetric NAT (or
  one symmetric + one restricted, depending on direction) will not converge
  on a shared observed port and will simply never confirm a direct path —
  see §4.5. This is a correct, expected fallback outcome (hub relay), not an
  error condition, and not something milestone-1 tries to detect or work
  around.
- **Full ICE (STUN/TURN/ICE-style candidate pairing, srflx/relay
  candidates, priority-ordered checklists).** Milestone-1 has exactly one
  candidate pair per peer (the hub's observed address for each side) and one
  strategy (simultaneous open). No STUN server, no TURN relay server distinct
  from the hub itself.
- **Multi-hop relay chains.** The hub is the only relay. A client can never
  relay for another client. If the hub itself cannot reach a client, that
  client is unreachable in this milestone — no relay-of-relay.
- **Mesh-wide route gossip / propagation.** The hub decides, unilaterally and
  from its own peer table, which pairs of clients to introduce (or is told to
  by an operator/future control-plane — the trigger policy itself is out of
  scope for this doc, see §3.4). There is no protocol for clients to
  advertise routes to each other or to a third party; `AllowedIPs` remain
  exactly what each side's local config/`AddPeer` call says.
- **Rendezvous tokens** (`VEIL-TOKENS-1.md`'s target scheme). `MESH_INTRO` is
  authenticated implicitly by riding inside an already-established hub<->
  client transport session (see §3.2) — it needs no separate cryptographic
  gate of its own for milestone-1.
- Full `VEIL-CANON-1` control-capsule encoding. `MESH_INTRO` keeps its compact
  `VMI1` payload for milestone-1, but it is now carried inside encrypted
  record/v1 `CONTROL` frames.

## 3. `MESH_INTRO`

### 3.1 Framing convention

VEIL's Go data plane now uses record/v1 typed inner frames. `MESH_INTRO` is
engine control data, never a fragment and never meant to reach the TUN device,
so it is carried as the body of a record/v1 `CONTROL` frame. The control
payload itself retains the compact milestone-1 magic:

```go
var meshIntroMagic = [4]byte{'V', 'M', 'I', '1'}
```

The `VMI1` prefix is a payload discriminator inside `CONTROL`, not a top-level
record discriminator.

### 3.2 Transport: how `MESH_INTRO` reaches a client

`MESH_INTRO` is sent as an encrypted record/v1 `CONTROL` frame on the
**existing, already-established hub<->client session**. This is deliberate:

- No new handshake, no new session type, no new authentication mechanism:
  the frame is already encrypted+authenticated by the same AEAD/session that
  protects all of that client's traffic, so a `MESH_INTRO` cannot be forged
  by an outside attacker without breaking that session's AEAD.
- It rides the existing per-peer session and uses `sendControlOnSession`, the
  same helper used by PMTU probe/ack control payloads.
- It costs nothing when unused: a leaf-only engine (`IsHub() == false`) never
  constructs one.

Only a hub-role engine ever sends `MESH_INTRO` (see §5, `EnableMeshHub`). A
hub itself ignores an inbound `MESH_INTRO` from one of its clients —
`handleMeshIntro` returns immediately when `IsHub()` is true, enforced inside
`handleMeshIntro` itself (not just at the `udpToTun` call site) precisely so
this invariant has one place to hold and can't be silently bypassed by a
future call site that forgets the check (see `engine/mesh_test.go`'s
`TestEngine_HubIgnoresInboundMeshIntro`).

**Residual trust-boundary note, milestone-1**: "authenticated" here means
"the sender holds valid session keys with the receiver," not "the sender is
specifically the receiver's hub." A leaf-role engine (`IsHub() == false`)
accepts a `MESH_INTRO` from *any* peer it has a live session with, not only
from a peer it has independently confirmed to be its hub — there is no
per-leaf "this is my trusted introducer" concept yet (see §7). For a leaf
whose only live session is with its actual hub (today's only realistic
topology, since `sendMeshIntro` — see below — has no caller yet and nothing
else drives clients into sessions with each other), this is not currently
exploitable in practice. It becomes a real gap the moment two things are
both true: (a) something calls `sendMeshIntro` outside of a hub context
(nothing does yet — it's `Engine`-method-gated but not further restricted at
compile time), or (b) a leaf ends up with a live P2P session to another leaf
(the very thing milestone-1's hole-punch produces) — at that point the other
leaf could send it a crafted `MESH_INTRO` too. Closing this fully needs a
per-peer "trusted introducer" marker (e.g. restricting it to config-time/
static peers only, never a dynamically mesh-added one) threaded through to
`handleMeshIntro`'s caller — tracked as follow-up work in §7, required
before wiring up §3.4's trigger policy for real.

### 3.3 Byte layout

Fixed-size, matching `fragmentHeaderLen`'s style (no variable-length TLV
machinery — every field has a fixed offset/size):

```
Offset  Size  Field
0       4     magic              = "VMI1" (meshIntroMagic)
4       32    peer_pubkey        introduced peer's static X25519 public key
36      1     addr_family        0x04 = IPv4, 0x06 = IPv6
37      16    addr               hub-observed IP of the introduced peer;
                                  IPv4 uses the first 4 bytes, remaining
                                  12 are zero-padded
53      2     port               hub-observed UDP port, big-endian (network
                                  byte order, matching net.UDPAddr semantics)
55      1     allowed_ip_count   N, number of CIDR entries that follow (0-8)
56      N*5   allowed_ips[N]     N entries, each 5 bytes:
                                   4 bytes IPv4 address + 1 byte prefix length
                                   (0-32). IPv6 AllowedIPs are out of scope
                                   for milestone-1 — see §3.5.
56+N*5  2     window_seconds     rendezvous attempt window, big-endian
                                  uint16 seconds (see §4.2 for the
                                  milestone-1 constant actually used)
```

Total length: `58 + N*5` bytes (N in 0..8; `meshIntroHeaderLen = 58` for the
fixed part). N is capped at 8 (a client's `AllowedIPs` list in practice is a
handful of routes at most; 8 is generous headroom without inviting an
oversized frame) — a `MESH_INTRO` claiming more is rejected as malformed,
silently dropped per `VEIL-INVARIANTS-1.md` invariant 12 (parser failures
are silent on the wire), same as a malformed record/v1 inner frame.

Rationale for each field:

- **`peer_pubkey`** — required so the receiving client can `Engine.AddPeer` a
  full `config.PeerConfig` for the introduced peer (peer identity in VEIL is
  always the static X25519 key, never the transient endpoint).
- **`addr`/`port`** — the hub-observed `(IP,port)` for the introduced peer.
  The hub already has this for every connected client (it's exactly
  `Peer.Path()`, populated by `NotePath` on every valid inbound packet — see
  `peer.go`) so **no new discovery mechanism is needed to learn it**; the hub
  is simply telling client A what it already knows about client B's observed
  address, and vice versa in a second, symmetric `MESH_INTRO` to B about A.
  Fixed 16-byte address field (rather than a variable-length one) keeps the
  frame fixed-size for a given N, at the cost of 12 wasted bytes for the
  IPv4 case — judged acceptable given frame sizes here are tiny (~60-100
  bytes) compared to the padding buckets (`lengthBuckets`,
  `engine.go`) traffic already rounds up to.
- **`allowed_ips`** — the introduced peer's `AllowedIPs`, so the receiving
  client can install routes for it via the same `installPeer` path
  config-time peers use, letting it originate traffic to that peer's subnet
  the moment the direct (or relayed) path is confirmed, not just receive
  from it.
- **`window_seconds`** — bounds how long the receiving client should attempt
  the hole punch before giving up and falling back to relay-only for that
  peer pair (see §4). Sent by the hub rather than hardcoded so a future hub
  could tune it (e.g. shorter on a congested hub) without a client-side
  protocol change; milestone-1's hub implementation always sends a fixed
  constant (§4.2).

### 3.4 Trigger policy (hub-side "when to introduce")

Out of scope for this document to fully specify — milestone-1's
implementation triggers a `MESH_INTRO` pair opportunistically whenever the
hub relays a data packet between two of its own peers (see §5.2) and has not
already introduced that pair recently (a simple per-pair cooldown, to avoid
re-sending `MESH_INTRO` on every relayed packet of an ongoing flow). This
piggybacks introduction on demonstrated traffic demand rather than
introducing every peer to every other peer eagerly, which would be wasteful
for a hub with many mutually-uninterested clients. A future milestone may
want an explicit operator-driven or gossip-driven trigger instead; that
policy question is deliberately left open here.

### 3.5 IPv6 `AllowedIPs`

Milestone-1's `MESH_INTRO` only carries IPv4 `AllowedIPs` entries (§3.3). A
peer with only IPv6 `AllowedIPs` can still be introduced (empty
`allowed_ips`, `addr_family` can still be 0x06 for the endpoint itself if the
hub's observed path to that peer is IPv6) but the receiving client won't get
routes installed for it. Extending the `allowed_ips` entry encoding to a
variable-length family-tagged form is deferred — not needed for milestone-1's
own test/dev environment (IPv4 overlay), and better done once real demand
for IPv6-in-mesh shows up rather than speculatively.

## 4. NAT traversal milestone-1: simultaneous-open UDP hole punch

### 4.1 Why the existing handshake replays unmodified

A hole-punch attempt between two leaf clients A and B is, cryptographically,
exactly the same handshake either of them already runs against the hub: a
2-message Noise-style exchange (`ConstructMsg1`/`ProcessMsg1`,
`ConstructMsg2`/`ProcessMsg2`, `core/handshake_machine.go`) authenticated by
each side's static key. Once the hub's `MESH_INTRO` has told A about B's
pubkey (and vice versa), both `NewHandshakeMachine(...)` calls need nothing
that isn't already available:

- `kNet`/`NID` — same VEIL network, already known locally (`e.cfg.Interface`).
- `localPriv` — already known locally.
- `remotePub` — just learned from `MESH_INTRO`.

So milestone-1 does not invent a new lighter-weight punch-specific
handshake; it reuses `startInitiatorHandshake`'s `ConstructMsg1`/send path
and `handleHandshake`'s existing `ProcessMsg1`/`ProcessMsg2` dispatch
unmodified, pointed at the peer's `MESH_INTRO`-supplied observed endpoint
instead of a config-file `Endpoint`. This is the same reasoning
`VEIL-CONTROL-1.md` gives for not inventing a new frame type where an
existing mechanism already does the job.

### 4.2 Simultaneous open procedure

Both A and B independently receive a `MESH_INTRO` for each other (from the
hub) at roughly the same time (the hub sends both in immediate succession
when triggering an introduction, §3.4). On receipt, each side:

1. `Engine.AddPeer` the introduced peer if not already known (idempotent —
   `AddPeer` itself already returns an error, ignored here, if the peer was
   somehow already registered by an earlier `MESH_INTRO` or static config;
   see §5.1).
2. Records the `MESH_INTRO`-supplied `(IP,port)` as that peer's `endpoint`
   (`Peer.SetPath`), so the ordinary `startInitiatorHandshake` machinery
   sends there.
3. For a bounded attempt window, repeatedly sends `ConstructMsg1` at that
   endpoint:

   - **5 attempts**, spaced **600ms apart** (5 x 600ms = 3s total window),
     matching the prompt's suggested "~5 attempts over ~3s." Chosen because
     it's long enough to cover the handful of round trips simultaneous-open
     typically needs on cone NATs (the punch either converges within the
     first 1-2 exchanges once both sides' NAT bindings are open, or it never
     will within any bounded window because the NAT type doesn't allow it)
     while staying short enough that a client isn't left in a half-punched
     state for long before falling back to relay.
   - Each attempt is a fresh `ConstructMsg1` (fresh ephemeral key, per
     `core/handshake_machine.go`'s existing behavior) rather than a
     retransmit of the same one, so a late response to an earlier attempt is
     never confused with a response to a later one — this falls out of
     reusing the unmodified handshake machinery, not a new invariant.
   - The attempt loop stops early the moment `ProcessMsg2` succeeds (see
     4.3) or the peer's session is otherwise already established (e.g. B's
     Msg1 arrived first and completed before A's own attempt loop finished).

4. Both `MESH_INTRO`s use the same `window_seconds` value from the hub (a
   symmetric window for both directions), so neither side gives up
   meaningfully earlier than the other.

### 4.3 Confirmation

Exactly as with the hub today: a `ProcessMsg2` response received from the
attempted address, passing `mac1` and `confirm` verification
(`handshake_machine.go`), confirms the direct path. `establishSession` /
`Peer.Promote` install the new session precisely as `handleHandshake`
already does for a hub<->client handshake — no mesh-specific session logic
exists.

From that point on, the existing endpoint-roaming logic
(`Peer.NotePath`, called from `udpToTun`'s phase-3 commit step) takes over:
every subsequent valid packet from that peer updates `Peer.endpoint` to
wherever it's actually arriving from, exactly like today's roaming behavior
for any other peer. Milestone-1 adds no special-casing here — a punched
direct P2P peer is, after the handshake completes, indistinguishable in the
engine's data structures from a statically-configured peer with a fixed
`Endpoint`.

### 4.4 Why simultaneous open works for cone NATs without a coordination
    message

Both sides send their `ConstructMsg1` at (approximately) the same time,
independently, as soon as they each get their own `MESH_INTRO`. Neither
waits for an explicit "go" signal from the other over the wire — the
`MESH_INTRO` delivery itself (both sent by the hub within the same short
window) is the only synchronization needed. This is standard simultaneous-open
UDP hole punching: each side's own outbound Msg1 opens a NAT binding at
(local_port -> peer's_observed_addr) at roughly the moment the peer's own
outbound Msg1 is heading the other way; on a cone NAT (full/restricted/
port-restricted) that binding then admits the peer's inbound packet even
though it wasn't itself the first packet on that 5-tuple.

### 4.5 Explicit non-failure: staying on relay

If no `ProcessMsg2` is confirmed within the attempt window (symmetric NAT on
one or both sides, a firewall blocking UDP inbound entirely, one peer
offline, etc.), the client simply stops attempting and the peer stays
relay-only: `Peer.endpoint` remains whatever `MESH_INTRO` set it to (the
hub-observed address, which is *not* actually reachable peer-to-peer in this
case), so if `tunToUDP` were to try sending directly, it would silently fail
into the void. To prevent that from happening, milestone-1 does **not**
attempt to send peer-destined data plane traffic to a mesh peer at all until
that peer's handshake has actually succeeded — i.e. `Peer.SendSession()`
returns non-nil only after the punch (or a future direct handshake) confirms
a session. Until then, `RoutingTable.Lookup` for that peer's `AllowedIPs`
would find the peer, but with no confirmed session; the relay path (§5)
continues to carry traffic through the hub regardless of what a leaf client's
own `RoutingTable` says, because the leaf's own outbound packets are always
addressed to the peer's tunnel IP and go wherever *that peer's local routing
table* sends them, which for the hub-relay case is simply "send to the hub as
usual" — a leaf client has no relay concept of its own (§6, gating). In other
words: a leaf whose punch fails keeps working exactly as it does today,
sending everything to the hub, and the hub (§5) relays it. No special
"give up and mark relay-only" state is needed on the leaf side; "no confirmed
direct session" already *is* that state, by the pre-existing meaning of
`Peer.SendSession() == nil` / no route.

This is a correct, expected fallback — not a failure state requiring
detection, retry-with-backoff, or user-visible error reporting in
milestone-1.

## 5. Hub relay fallback

### 5.1 Gating: hub-role only

The relay branch described below only ever executes when `Engine.IsHub()` is
true (§ Engine role plumbing, `EnableMeshHub`). A leaf-only engine's
`udpToTun` is byte-for-byte the same hot path as before this milestone —
the relay check is a single `if e.IsHub() { ... }` guard so it costs a
predictable, cheap branch (not a table lookup) on every packet for leaf
engines, keeping "leaf clients never carry forwarding logic" true at
runtime, not just true "by convention."

### 5.2 Decision: forward vs. deliver locally

Today, `udpToTun`'s phase-3 commit step unconditionally treats a decrypted,
non-fragment, non-probe inner packet as destined for the local TUN device
(`tunBufs = append(tunBufs, full)`). There is currently no concept of "this
inner IP packet's destination isn't me."

The hub relay branch adds exactly that check, using machinery that already
exists:

- **`RoutingTable.Lookup(dstIP)`** already does LPM over every peer's
  `AllowedIPs` — including, on a hub, every *other* connected client's
  `AllowedIPs`, since the hub's `AddPeer`/config-time `installPeer` already
  installs routes for every configured peer regardless of role. So
  `RoutingTable.Lookup` already answers "which peer, if any, owns this
  destination IP" — a hub doesn't need a new table.
- What's missing is comparing that answer against **the packet's own
  sender**: if `RoutingTable.Lookup(dstIP)` resolves to a peer other than
  the one the packet arrived from (`j.peer` in `udpToTun`'s phase-3 loop),
  the destination isn't the hub's own TUN — it's another client's traffic,
  and it must be forwarded, not written locally.
- The hub's own address (`cfg.Interface.Address`) is deliberately **not**
  added as a route in `RoutingTable` (nothing does that today, and this
  design doesn't change that), so "no peer owns this destination" continues
  to mean "it's mine" exactly as it implicitly does today for a
  non-hub/non-mesh deployment. The relay check is additive: it only ever
  intercepts traffic that would otherwise have gone nowhere useful on a pure
  star topology anyway (a client's config would need the other client's
  subnet in `AllowedIPs` pointed at the hub for this to even be reachable
  pre-mesh, which is exactly the "hand-configured star" pattern already
  described in `docs/ROADMAP.md` §9).

### 5.3 Mechanics: exactly which functions change

In `engine.go`'s `udpToTun`, phase 3 (the sequential dispatch loop, after
`j.sess.handleRecordFrame` has produced a data payload):

```go
res := j.sess.handleRecordFrame(plaintext, now)
if !res.ok {
    continue
}
if res.typ == recordv1.FrameControl {
    e.handleControlPayload(res.payload, j.sess, j.peer, remote, localIP)
    continue
}
inner := res.payload
if e.IsHub() {
    if dstIP := ExtractDstIP(inner); dstIP != nil {
        if target := e.routingTable.Lookup(dstIP); target != nil && target != j.peer {
            e.relayToPeer(target, inner)
            continue // do not also deliver to local TUN
        }
    }
}
// ...existing local-delivery path (append to tunBufs) unchanged
```

`e.relayToPeer(target, inner)` is a new small function, structurally a
peer-directed sibling of the existing `sendOnSession` helper: it looks up
`target.SendSession()`/`target.Path()` exactly as `tunToUDP` does for
locally-originated TUN traffic, and if both are available, re-encrypts
`inner` under `target`'s session and sends it — i.e. the hub decrypts under
the sender's session (already done, that's the record plaintext/`inner`) and
re-encrypts under the destination peer's session, forwarding instead of
writing to its own TUN, exactly as specified. If `target` has no confirmed
session or endpoint yet (e.g. never connected, or between handshakes), the
packet is dropped — same silent-drop behavior `tunToUDP` already has for a
`RoutingTable.Lookup` miss or a peer with no send session.

Reusing `ExtractDstIP` (already used identically in `tunToUDP` for
locally-originated traffic, `routing.go`) keeps the "how do I find the
destination IP in a raw packet, including the PI-header special case" logic
in exactly one place.

Fragmentation: a relayed packet is `inner` — the fully reassembled original
IP packet if the inbound side fragmented it, or a normal single packet
otherwise (`handleTransportFrame` already resolves this before the relay
check runs). `relayToPeer` re-fragments for the *outbound* peer's own frame
budget using the existing `makeTransportFrames`/`peer.FrameBudget()`
machinery, exactly as `tunToUDP` does for TUN-originated traffic — the two
peers' negotiated frame budgets are independent and a hub must not assume
they match.

### 5.4 What relay does *not* change

- No new session type, no new key material: relay re-encryption uses each
  leaf's already-established session with the hub, same as every other
  record/v1 frame the hub sends that peer.
- No multi-hop: `relayToPeer`'s `target` is always a directly-connected peer
  of this hub. A hub never relays a packet it received *from* a relay (there
  is no such concept in milestone-1 — see §2 Non-goals).
- No change to how a non-hub engine behaves: the entire branch is inside
  `if e.IsHub()`.

## 6. Engine role plumbing (implemented ahead of this doc, pure refactor)

`Engine.EnableMeshHub()` / `Engine.DisableMeshHub()` / `Engine.IsHub() bool`
(`engine/engine.go`) mark an Engine as hub/relay-capable at runtime. This
piece was implemented and tested before this document (it touches no wire
format, just an internal atomic flag gating the relay branch above), per the
project rule that pure-refactor engine plumbing that doesn't touch the wire
is not gated on a design doc, only mesh-specific protocol shape is.

## 7. Deferred: the config-schema question

How does a leaf client's `.conf` file eventually declare "this peer is my
mesh hub" (as opposed to an ordinary peer it happens to also route through)?
And symmetrically, how does an operator's hub config declare "I act as a
hub" on disk rather than via a runtime-only `EnableMeshHub()` call?

This is explicitly **not resolved by this document**. `config/config.go` is
concurrently being extended (`Serialize()`) by another workstream in this
same repo, and touching its schema here risks a write conflict as well as
conflating two different pieces of unfinished design (mesh semantics vs. GUI
serialization). Candidate directions for a future pass, listed only as
options and not decided:

- A new `InterfaceConfig` field, e.g. `MeshHub bool` or `Role string`
  (`"hub"`/`"leaf"`), set on the *hub's own* config and read by whatever
  daemon entry point calls `EnableMeshHub()`.
- A new `PeerConfig` field on the *leaf's* config marking one specific peer
  entry as the mesh hub (distinguishing it from an ordinary relay-unaware
  peer this client also happens to talk to) — relevant once a client can
  have more than one hub-like peer, which milestone-1 does not need to
  support (a client mesh-punches to whatever peers its currently-connected
  hub introduces it to; it does not need to know ahead of time, from config,
  which of its peers *is* a hub).
- Whether hub-ness needs to be in the wire-transmitted config at all
  (`LoadConfigString`, used for QR/link-based provisioning) or is purely a
  local daemon-startup flag (`--mesh-hub` CLI flag / systemd unit
  environment variable), sidestepping `config.go` entirely.

Until this is resolved, milestone-1's own daemon/client entry points
(`veil-linux`, `veil-windows`) are expected to call `EnableMeshHub()`
imperatively (e.g. gated on an existing CLI flag or hardcoded per
deployment) rather than reading it from a `.conf` file field that does not
yet exist. That entry-point wiring is itself out of scope for this `veil`
repo pass — see `docs/ROADMAP.md`'s cross-repo sync matrix.

## 8. Summary of what's implemented vs. deferred in milestone-1

**Implemented:**
- `Engine.EnableMeshHub`/`DisableMeshHub`/`IsHub` (§6).
- `MESH_INTRO` encode/parse (§3.3), package-level magic + fixed-layout
  struct, unit-tested round-trip.
- Hole-punch attempt logic reusing the existing handshake path, bounded
  5 attempts / 600ms spacing / ~3s window (§4.2).
- Hub relay branch, gated to `IsHub()`, in `udpToTun` (§5.3).
- Unit tests for frame encode/decode and the forward-vs-deliver-locally
  routing decision, following `fragment_test.go`/`lifecycle_test.go`'s
  style (plain `testing.T`, table-driven where natural, real objects over
  mocks). Full simultaneous-open hole-punch behavior against real NAT
  devices is not exercised by unit tests — it needs a real or emulated
  multi-network environment, out of scope for this pass' automated suite.

**Explicitly deferred (§2):** symmetric NAT / full ICE / TURN, multi-hop
relay chains, mesh-wide route gossip/propagation, IPv6 `AllowedIPs` in
`MESH_INTRO`, the config-schema question (§7), and the hub-side introduction
trigger policy beyond the simple relay-triggered cooldown described in §3.4.
