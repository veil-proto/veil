# VEIL-TOKENS-1

**Status:** DRAFT. Route tokens are implemented in the Go runtime data plane;
rendezvous and path tokens remain pending.

Source: `VEIL_FINAL_DEVELOPMENT_SPEC.md` section 10.

## Token Classes

- **Rendezvous token:** pre-session cheap gate,
  `MAC(rv_token_secret, server_id || time_bucket || peer_hint)[:16]`.
  Invalid tokens silently drop. Not implemented yet; current handshakes still
  use the existing `mac1` gate.
- **Route token:** per-packet session lookup token,
  `MAC(route_token_key, epoch_id || path_id || token_slot || direction)[:16]`.
  Implemented by `tokens.Route` and wired into `engine`.
- **Path token:** endpoint/path validation token,
  `MAC(path_token_key, endpoint_family || path_id || epoch_id)[:16]`.
  Not implemented yet; current roaming still trusts a packet that passed AEAD.

## Go Runtime State

`engine` now uses a bounded route-token table instead of `transport.TagTable`:

- Sender derives the route token from the send route key, token slot, and
  direction for each sequence number.
- Receiver pre-installs a small future window and retains a bounded past
  window while replay protection handles per-packet uniqueness.
- Token windows are removed when previous rekey sessions expire.
- Table teardown removes only entries that still belong to the same session,
  so an old session cannot delete a newer colliding entry.

The kmod/XDP ordering rule is not applicable yet because no kernel data plane
exists. When kmod starts, `veild` must install route-token windows in the
kernel before admitting those tokens in any XDP prefilter map.
