# Changelog

## Unreleased

### Added (fork: hosted multi-user mode)

- `RELAY_MODE=hosted` turns the relay into a multi-user service while the
  default `local` mode keeps upstream behavior. Policy, auth, lifecycle and
  admin code live in new modules; the data plane calls them from marked
  one-line hooks.
- Authentication at the WebSocket upgrade: per-account API tokens, short-lived
  anonymous demo tokens (optional Cloudflare Turnstile gate), and external
  OIDC JWTs verified via JWKS. Tokens travel as a `relay.token.<token>`
  subprotocol entry or an `Authorization: Bearer` header.
- Egress policy that refuses loopback, link-local (cloud metadata), private,
  CGNAT, multicast and reserved destinations plus port 25 with an immediate
  TCP RST; CIDR allow/deny lists.
- Learn-then-lock source address and MAC anti-spoofing, owner-scoped VM-to-VM
  reachability, per-tier caps (connections, SYN and DNS rates, UDP flows,
  bandwidth in both directions, session lifetime, sessions per account and
  per address) and byte quotas.
- Graceful shutdown on SIGTERM/SIGINT (clients receive close code 1001),
  crash handlers, WebSocket heartbeat, idle timeouts, `GET /healthz`.
- Trusted-proxy client address resolution (`TRUST_PROXY`), Origin allow list,
  CORS for the anonymous token endpoint.
- SQLite-backed accounts, API tokens, operator sessions, monthly usage and a
  pruned connection audit log; Prometheus metrics on `/metrics`.
- Operator panel rebuilt: sessions with owner/tier/policy counters and kill,
  accounts and tokens (create, ban/unban, tier, password, revoke), audit log
  browser, usage, inbound rules hidden when disabled. All values are rendered
  as text nodes.
- Inbound rule bodies are validated (pool address, ports, bind address) and
  the reverse proxy listener only starts when `INBOUND_RULES_ENABLED`.
- Docker image defaults to hosted mode; compose publishes only the public
  port and the loopback admin port.
- `METRICS_PUBLIC=true` serves `/metrics` without authentication for
  scrapers on a private network.
- Account API under `/api/me` on the public listener: a signed-in user can
  read their account, tier limits and usage, list and close their own
  sessions, and create, list and revoke their own API tokens.
- Invite-only sign-up (`SIGNUP_MODE=invite`): new external accounts start
  `pending` (migration 2 adds the status and an `invites` table) and redeem a
  single-use code via `POST /api/me/redeem`; operators create, list and revoke
  codes and activate accounts from the panel's Invites section.
- Abuse lookup: `GET /api/audit` takes `dstIp`, `dstPort`, `at` and
  `windowMinutes` to find connections open to a destination at a moment;
  the panel's audit tab searches that way, shows usernames and can ban the
  owner from a result row (migration 3 indexes the audit by destination).
- `DELETE /api/me` lets a signed-in user delete their own account after
  typing their username back.
- `DELETE /api/users/:id` on the admin API, with a Delete button in the panel,
  removes an account, its tokens and usage rows and closes its sessions.

### Changed (fork)

- Legacy `admin_users` rows migrate into the `users` table as operators.
- UDP replies, VM-to-VM traffic and reverse-proxy traffic now count against
  the per-session download budget.
- Missing operator bootstrap credentials no longer stop the relay; operator
  login is simply unavailable until an operator exists.
- The SQLite database runs with `synchronous=NORMAL` and a 5 s
  `busy_timeout`, as WAL-shipping backups such as Litestream expect.

- Operator single sign-on for the admin panel through OIDC (`ADMIN_OIDC_*`):
  authorization code flow with PKCE, accepted only for an active operator
  whose external identity matches, and by default only with MFA (`amr`).
  `ADMIN_PASSWORD_LOGIN=false` turns the password form off.
  `POST /api/users/:id/role` and a panel button promote or demote operators.
- `SESSION_ALLOWED_ORIGINS` sets which browser origins may open sessions,
  separately from `ALLOWED_ORIGINS` (which it defaults to); `*` allows any,
  so third-party pages can embed the relay with a user's token while the
  HTTP APIs stay limited to the operator's own frontend.
- `METRICS_MERGE_URLS` appends other local metrics endpoints (such as
  Litestream's) to `/metrics`, for platforms that scrape one endpoint per app.

### Changed

- TCP toward the VM uses slow start below ssthresh (RFC 5681, with RFC 3465
  byte counting) instead of always growing by about one segment per round
  trip. With a large `TCP_WINDOW_SIZE` and a distant client, a 1 MB download
  over 100 ms of round-trip time drops from 3.5 s to 2.0 s. Offered upstream.

### Security (fork)

Fixes from a review of the hosted code paths:

- API tokens can no longer create or revoke tokens (`403 sign-in-required`);
  only a signed-in (external JWT) session can, so a leaked token cannot
  outlive its own revocation. Revoking a token closes the sessions opened
  with it.
- All SQLite access goes through one queue and transactions hold it
  exclusively: statements from other callers could join an open audit or
  usage transaction (a ban could be rolled back) and a second BEGIN failed,
  dropping usage and audit rows. Failed flushes now requeue their rows.
- Audit volume and memory per session are bounded: denied attempts beyond 30
  rows a minute and allowed connections beyond 600 are summarised in one
  row; the denied-destination map is capped.
- `TRUSTED_PROXY_CIDRS` and `PEER_IP_HEADER`: the client-address header is
  believed only from the configured proxy ranges, so clients reaching the
  platform hostname directly cannot forge their address; values must be IPs.
- Admission reserves its slot before the quota lookup and handshake, so
  parallel upgrades cannot exceed per-account, per-address or pool caps.
- Public listener: 10 s header timeout, 15 s request timeout.
- External JWTs: `JWT_ALGORITHMS` (default RS256) and `JWT_VERIFIED_CLAIM`
  (an unverified email is not used as the username).
- Invite redemption is one statement that also refuses a second code for the
  same account; concurrent first logins no longer fail on the unique key.
- Admin session cookie is SameSite=Lax (needed for the OIDC redirect).
- Admin API: no form-encoded bodies, and state-changing requests carrying an
  Origin must come from the panel's own host (CSRF via `fly proxy` on
  localhost).
- A malformed session id in `DELETE /api/me/sessions/:id` returns 404, not 500.

### Fixed (fork)

- `benchmarks/ws-relay-throughput.js` logs into the admin API before polling
  sessions; its accounting had been broken since admin authentication was
  added.
- A VM that changed its MAC mid-session no longer leaks its first IP
  allocation (the MAC is locked instead).
- Monthly usage counted a session only if it moved bytes after the last
  flush, so most sessions were never counted.

### Fixed

- Deduplicate overlapping out-of-order TCP receive ranges and deliver their
  remaining tails, including across sequence-number wraparound.
- Recover lost zero-window reopening updates with backed-off probes in both TCP
  directions, preserving byte accounting and cleaning up probe timers on close.
- Honor small nonzero peer MSS values and use the 536-byte IPv4 default when no
  MSS is advertised, as specified by RFC 9293 section 3.7.1.

### Changed

- Forward small outbound TCP writes without waiting for earlier ACKs, matching
  reverse TCP behavior and avoiding delayed-ACK stalls for interactive traffic.
  Pacing, congestion control, and flow control remain in effect.

## 0.6.0 — 2026-09-12

### Added

- Published `rootlessrelay` command for global installs and `npx`, with all runtime modules and the admin page included in the npm package.
- TCP retransmission timeouts with exponential backoff for handshakes, data, and connection teardown in both relay directions.
- Configurable adaptive, fixed, and disabled TCP pacing, with ACK-driven congestion control and loss recovery.
- Optional jumbo VM MTUs advertised through DHCP and TCP MSS negotiation.
- TCP input backpressure, bounded send queues, and delayed cumulative ACKs for VM uploads.
- Repeatable IP-stack, WebSocket/UDP, and TCP throughput benchmarks, Git revision comparisons, and relay CPU profiling.
- Regression tests for TCP stream integrity, flow control, retransmission, packet checksums, and UDP flow isolation.

### Changed

- Reduce forwarding overhead by reusing parsed addresses, avoiding transport-checksum copies, and batching socket writes.
- Restrict WebSocket write batching to unpaced mode to preserve the timing of paced bursts.
- Resume TCP output when WebSocket writes complete instead of polling transport backpressure on a timer.
- Aggregate rate-limit accounting within each millisecond while preserving exact expiration boundaries.
- Reuse UDP sockets per flow, with idle expiry and per-session flow limits.
- Update the locked `ws` dependency to 8.21.3.

### Fixed

- Load the admin page from the installed package directory when launched from another working directory.
- Preserve valid six-byte TCP payloads containing only spaces or zero bytes.
- Deliver data carried on the final outbound TCP handshake ACK.
- Resume queued TCP data on valid window-only ACKs and reject window changes from invalid ACKs.
- Ignore unnegotiated TCP window scaling and avoid counting data-bearing ACKs or window updates as duplicate ACKs.
- Isolate UDP flows that share a VM source port but use different remote endpoints.
- Handle IPv4 header lengths, packet padding, and transport checksum boundaries consistently.
- Make zero-delay benchmark ACKs immediate, and make backpressure tests explicitly exercise sink recovery.

See the [performance investigation](https://github.com/obegron/rootlessRelay/blob/v0.6.0/benchmarks/PERFORMANCE.md) for measurements,
reproduction commands, and remaining correctness limitations.
