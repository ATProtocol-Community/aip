# AIP fork (bringyourowncomputer)

**Fork of [graze-social/aip](https://github.com/graze-social/aip)** (MIT) —
our ATProtocol Identity Provider / OIDC server (deployed at
`login.bringyourown.computer`, VM 111).

Why: we run atproto identity at the core, and **AIP is the login gate for the
whole cluster** — the natural place to enforce the **network allow-list** that
People (bringyourowncomputer/people, OVHP-87) administers.

## Branch layout

- **`main`** — upstream `main` (tracked; refresh upstream refs/tags here).
- **`byoc`** — **our working branch**: `v2.2.3` (the version we deploy) +
  local commits. Start new work here; rebase onto a newer upstream tag when
  we bump.
- Tags `v2.x.y` — upstream release tags (kept for reference/build pinning).

## Diff vs upstream v2.2.3 (the `byoc` delta)

1. **`src/oauth/openid.rs` — `at_hash`/`c_hash` truncated to 128 bits.** Folded
   in from the ovhproxmox deploy-time patch (`roles/aip/files/aip-at-hash.patch`):
   upstream AIP emits the full 32-byte digest, which strict OIDC clients
   (e.g. Grist/openid-client) reject.
2. **Network allow-list gate (OVHP-87)** — `src/oauth/atprotocol_bridge.rs` +
   `src/config.rs` + `src/errors.rs`:
   - Config: `ACCESS_POLICY_ENDPOINT` (People's check URL),
     `ACCESS_POLICY_DECISIONS_ENDPOINT` (People's decision ingest — AIP forwards
     every login decision incl. handle for the queryable audit trail), `ACCESS_POLICY_AUTH_TOKEN`
     (the shared bearer People requires), `ACCESS_POLICY_MODE` (`log` default |
     `enforce`), `ACCESS_POLICY_FAIL_OPEN` (default true).
   - In `handle_atp_callback_impl`, **after the DID is resolved, before
     `base_auth_server.authorize`**: calls
     `check?did=<resolved DID>&client_id=<OAuth client>` against People.
   - `log` mode audits every decision
     (`tracing::info! … "network_access_decision", did/client_id/allowed/rule`)
     and never blocks; `enforce` mode refuses denied DIDs with
     `error-aip-oauth-11` (upstream Access denied). Upstream unreachable → fail-open (unless
     `ACCESS_POLICY_FAIL_OPEN=false`).
   - Rollout: deploy in `log` mode, review the audit lines, then flip to
     `enforce` once rules are pre-allowlisted.

## Deploy

ovhproxmox `roles/aip` clones **this fork** at a pinned `byoc` commit and
builds (release, sqlite, embedded templates) — the old deploy-time at_hash
patch is no longer applied separately (it's in the fork now). Env lives in
`/etc/aip.env` (0600) on VM 111; the allow-list token is the same
`NETWORK_ACCESS_API_TOKEN` that gates People's check API (controller
`~/.config/people/people-secrets.env`).

## Related

- OVHP-87 (allow-list design + this gate) · bringyourowncomputer/people
  (`AccessPolicy` + check/snapshot APIs; `ADMIN_GUIDE.md`) · OVHP-91
  (atproto-crates PDS, group DIDs).