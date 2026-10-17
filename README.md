# RootlessRelay

A WebSocket based VPN/proxy relay for virtual machines.

## Features

- **Secure Communication:** Supports secure WebSockets (WSS) for encrypted data transfer.
- **Dynamic IP Allocation:** Built-in DHCP-like server to automatically assign IP
  addresses to virtual machines.
- **VM-to-VM Networking:** Allows virtual machines on the same relay to communicate
  communicate with each other (configurable).
- **Admin Interface:** A web-based UI to monitor active sessions and manage
  proxy rules.
- **HTTP Proxying:** Reverse proxy functionality to expose services from VMs to
  the host network.
- **Rate Limiting:** Configurable bandwidth limits for each connected VM.
- **TCP Loss Recovery:** Fast retransmit plus backed-off retransmission timeouts
  for handshakes, data, and connection teardown in both relay directions.
- **TCP Flow Recovery:** Overlapping receive ranges are deduplicated, and
  zero-window probes recover lost window-reopen updates in both directions.
- **Hosted Mode:** Authentication (accounts, API tokens, anonymous demo
  tokens, external OIDC), tenant isolation, egress policy, per-tier limits and
  quotas, audit log, metrics, and an operator panel for running the relay as a
  multi-user service. See [Hosted mode](#hosted-mode).

## Configuration

These default values can be overridden by setting corresponding environment variables.

### General Settings

| Setting                  | Purpose                                                                | Default     |
| ------------------------ | ---------------------------------------------------------------------- | ----------- |
| `RATE_LIMIT_KBPS`        | Maximum upload/download bandwidth for each VM in kilobytes per second. | `1024`      |
| `MAX_CONNECTIONS_PER_IP` | Maximum number of concurrent WebSocket connections from a single IP.   | `4`         |
| `ENABLE_WSS`             | Use Secure WebSockets (WSS). Requires `cert.pem` and `key.pem`.        | `true`      |
| `ENABLE_VM_TO_VM`        | Allow VMs on the same relay to communicate with each other.            | `true`      |
| `LOG_LEVEL`              | Controls logging verbosity. `0` (Disabled), `1` (Debug), `2` (Trace).  | `1` (Debug) |

### Network & Port Settings

| Setting              | Purpose                                                    | Default                    |
| -------------------- | ---------------------------------------------------------- | -------------------------- |
| `GATEWAY_IP`         | IP address of the virtual gateway within the VM's network. | `10.0.2.2`                 |
| `DHCP_START`         | The starting IP address for the DHCP pool (last octet).    | `15`                       |
| `DHCP_END`           | The ending IP address for the DHCP pool (last octet).      | `254`                      |
| `DNS_SERVER_IP`      | DNS server provided to VMs via DHCP.                       | `8.8.8.8`                  |
| `VM_MTU`             | VM-to-relay link MTU; also controls the negotiated TCP MSS. | `1500`                    |
| `TCP_WINDOW_SIZE`    | TCP window size for connections to/from the VM.            | `10240`                    |
| `TCP_PACING_MODE`     | VM-bound pacing mode: `adaptive`, `fixed`, or `off`.       | `adaptive`                 |
| `TCP_SEND_BURST_SEGMENTS` | Initial adaptive or exact fixed TCP burst.           | `3`                        |
| `TCP_SEND_BURST_MAX_SEGMENTS` | Maximum burst used by adaptive pacing.           | `8`                        |
| `TCP_SEND_BURST_INTERVAL_MS` | Delay between paced TCP bursts sent to a VM.       | `6`                        |
| `TCP_INITIAL_CWND_BYTES` | Initial ACK-driven TCP congestion window.                | `10240`                    |
| `TCP_SEND_QUEUE_HIGH_WATER_BYTES` | Pause the real input stream at this queued size. | `1048576`                  |
| `TCP_ACK_EVERY_SEGMENTS` | VM upload segments per cumulative ACK.                  | `2`                        |
| `TCP_ACK_DELAY_MS`    | Maximum delay before ACKing VM upload data.                 | `10`                       |
| `UDP_FLOW_IDLE_TIMEOUT_MS` | Idle lifetime of a UDP flow mapping.                  | `30000`                    |
| `MAX_UDP_FLOWS_PER_SESSION` | Maximum concurrent UDP flows per VM session.          | `256`                      |
| `TCP_RTO_INITIAL_MS` | Initial TCP retransmission timeout.                            | `1000`                     |
| `TCP_RTO_MAX_MS` | Maximum backed-off TCP retransmission timeout.                      | `60000`                    |
| `TCP_RTO_MAX_RETRANSMISSIONS` | Retransmissions before a TCP connection is aborted.   | `4`                        |
| `WS_PORT`            | Port for the WebSocket server.                             | `8443` (WSS) / `8086` (WS) |
| `WS_BIND_ADDRESS`    | IP address for the WebSocket server to bind to.            | `0.0.0.0`                  |
| `ADMIN_PORT`         | Port for the web-based admin interface.                    | `8001`                     |
| `ADMIN_BIND_ADDRESS` | IP address for the admin interface to bind to.             | `127.0.0.1`                |
| `PROXY_PORT`         | Port for the HTTP reverse proxy server.                    | `8080`                     |
| `PROXY_BIND_ADDRESS` | IP address for the reverse proxy to bind to.               | `127.0.0.1`                |

### Admin Authentication Settings

| Setting                    | Purpose                                                                 | Default                     |
| -------------------------- | ----------------------------------------------------------------------- | --------------------------- |
| `ADMIN_SESSION_SECRET`     | Secret used to sign admin session cookies. Set this in production.      | `change-me-in-production`   |
| `ADMIN_AUTH_DB_PATH`       | Path to the SQLite database used for admin users.                       | `./admin_auth.sqlite`       |
| `ADMIN_BOOTSTRAP_USERNAME` | Initial admin username (required on first run if DB is empty).          | none                        |
| `ADMIN_BOOTSTRAP_PASSWORD` | Initial admin password (required on first run if DB is empty).          | none                        |
| `ADMIN_LOGIN_WINDOW_MS`    | Sliding window for failed login attempts.                               | `600000` (10 minutes)       |
| `ADMIN_LOGIN_MAX_ATTEMPTS` | Max failed attempts per IP+username within the login window.            | `6`                         |
| `ADMIN_TRUST_PROXY`        | Trust reverse proxy headers for IP/session security settings.            | `false`                     |
| `ADMIN_COOKIE_SECURE`      | Force secure admin session cookies (requires HTTPS at edge/proxy).      | `false`                     |

## How to use

### 1. Installation

Run the published package directly with npm:

```bash
npx rootlessrelay
```

WSS is enabled by default and requires `key.pem` and `cert.pem` in your current
directory (see below). To run without TLS:

```bash
ENABLE_WSS=false npx rootlessrelay
```

Alternatively, install the command globally:

```bash
npm install -g rootlessrelay
rootlessrelay
```

This project requires Node.js. You can install the dependencies using npm:

```bash
npm install
```

### 2. Generating SSL/TLS key pair (for WSS)

For secure WebSockets (WSS), you need to generate a private key and a certificate.
You can generate a self-signed pair using the following npm script:

```bash
npm run keygen
```

This will create `key.pem` and `cert.pem` in your project directory. When prompted,
you can leave the fields for distinguished name blank.

Alternatively, you can run the `openssl` command directly.
This is useful if you want to use different settings:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 3. Running the relay

Once the dependencies are installed and you have your key pair (if using WSS),
you can start the relay server:

```bash
npm start

```

For first startup with an empty admin auth database, provide bootstrap credentials:

```bash
ADMIN_SESSION_SECRET="replace-with-strong-secret" \
ADMIN_BOOTSTRAP_USERNAME="admin" \
ADMIN_BOOTSTRAP_PASSWORD="replace-with-strong-password" \
npm start
```

Once the first user is created, you can remove bootstrap username/password env vars.

| In the browser you will use the relay first visit <https://127.0.0.1:8443> and
| trust the certificate you created.

The server will start, and you can see log output in your console.

### 4. Admin UI

The project includes a web-based admin UI. By default, it's available at `http://localhost:8001`.

The admin API now requires login. Open the admin UI and sign in using your configured admin credentials.

For public deployments behind HTTPS, set:

```bash
ADMIN_TRUST_PROXY=true
ADMIN_COOKIE_SECURE=true
```

### 5. Running in Docker

The image runs as the unprivileged `node` user in **hosted mode** (see below):
authentication required, egress policy on, inbound rules off, per-packet
logging off. It speaks plain WebSocket on port 8086 and keeps its database on
a volume at `/data`. TLS is expected to terminate at a reverse proxy or load
balancer in front of the container.

```bash
cp .env.example .env   # set ADMIN_SESSION_SECRET, ANON_TOKEN_SECRET and the bootstrap credentials
docker compose up -d --build
```

The admin UI is published on the host loopback only (`127.0.0.1:8001`). The
bootstrap credentials are used once, when the database is empty, and can be
removed from `.env` afterwards. To run the container the way the bare
`npm start` behaves (no authentication, open egress), set `RELAY_MODE=local`.

To terminate TLS inside the container instead, set `ENABLE_WSS=true`, mount
`key.pem` and `cert.pem` into `/app`, and publish `WS_PORT` (default 8443 when
WSS is on).

## Hosted mode

`RELAY_MODE=hosted` turns the relay into a multi-user service. The default
(`local`) keeps the original single-operator behavior, so existing setups,
tests and benchmarks are unaffected. Every setting below can be overridden
individually in either mode.

### What hosted mode changes

| Concern | Local (default) | Hosted |
| --- | --- | --- |
| WebSocket authentication | none | required: API token, anonymous token or external JWT |
| Egress policy | open | denies loopback, link-local (cloud metadata), RFC1918, CGNAT, multicast, reserved ranges, the relay's own addresses and port 25 |
| Tenant isolation | all VMs share one LAN | VM-to-VM only between sessions of the same account; anonymous sessions are isolated |
| Source address anti-spoofing | on | on |
| Per-session caps (connections, SYN rate, DNS rate, UDP flows, bandwidth, lifetime) | unlimited | per tier |
| Inbound rules (reverse proxy / port forwards) | enabled | disabled |
| Client IP behind a proxy | socket address | `X-Forwarded-For` (`TRUST_PROXY`) |
| Audit log, metrics, JSON logs | off | on |
| Startup validation | warn on default secret | refuse default secret, require `ANON_TOKEN_SECRET`, refuse `EGRESS_POLICY=open` |

### Connecting a client

Browser clients cannot set HTTP headers on a WebSocket, so the credential is
sent as a subprotocol entry next to `relay.v1`; the server answers with
`relay.v1`:

```js
const ws = new WebSocket("wss://relay.example.com", ["relay.v1", `relay.token.${token}`]);
```

Non-browser clients may send `Authorization: Bearer <token>` instead. Rejected
upgrades return a plain HTTP status before the handshake: 401 (no or invalid
credential), 403 (banned account, origin not allowed), 429 (per-address,
per-account or quota limit), 503 (address pool exhausted or shutting down).

Tokens come from one of three places:

- **API tokens** (`rr_…`): created by an operator for an account via the admin
  panel or `POST /api/users/:id/tokens`. Hashed at rest, revocable, optional
  expiry.
- **Anonymous demo tokens**: `POST /api/anon/token` on the public port returns
  a short-lived token bound to the caller's address, limited to
  `ANON_TOKENS_PER_IP_PER_HOUR`. If `TURNSTILE_SECRET` is set, the request
  body must carry a valid Cloudflare Turnstile `turnstileToken`.
- **External OIDC JWTs**: set `JWT_ISSUER`, `JWT_AUDIENCE` and `JWT_JWKS_URL`.
  Tokens are verified against the provider's JWKS and an account is created on
  first sight (`JWT_USERNAME_CLAIM`, `JWT_DEFAULT_TIER`).

The public port also serves `GET /healthz` (200, or 503 while shutting down).

### Tiers

Identities map to tiers: `anon`, `user`, `operator` (and `local` for
unauthenticated local-mode sessions). Defaults:

| Limit | anon | user | operator |
| --- | --- | --- | --- |
| Upload / download bandwidth | 256 KiB/s / 512 KiB/s | `RATE_LIMIT_KBPS` | 4 MiB/s |
| Concurrent TCP connections | 32 | 256 | 1024 |
| New connections per second / DNS queries per second | 10 / 20 | 50 / 100 | 200 / 400 |
| Allowed TCP ports | 80, 443 | any (minus `EGRESS_DENY_PORTS`) | any |
| DNS servers | `DNS_SERVER_IP` only | any public | any public |
| VM-to-VM | no | same account | same account |
| Session lifetime / idle timeout | 15 min / 3 min | 12 h / 30 min | none |
| Sessions per account / per address | 1 / 2 | 4 / `MAX_CONNECTIONS_PER_IP` | 10 |
| Quota | 200 MB per day per address | 20 GB per month | none |

Override any field with `TIERS_JSON`, for example
`TIERS_JSON='{"user":{"quotaBytes":53687091200},"anon":{"maxSessionMs":600000}}'`.
`null` means unlimited. Operators can move an account to another tier from the
admin panel.

### Operator panel and API

The admin app on `ADMIN_PORT` (keep it private; reach it through an SSH
tunnel or your platform's proxy) shows live sessions with owner, tier and
policy counters, lets operators kill sessions, manage accounts, tokens, bans
and tiers, browse the connection audit log and view per-account usage.
`GET /metrics` exposes Prometheus metrics to a logged-in operator or to a
scraper presenting `Authorization: Bearer $METRICS_TOKEN`. Set
`METRICS_PUBLIC=true` to let an unauthenticated scraper read it when the
admin port is only reachable over a private network.
`METRICS_MERGE_URLS` (comma-separated) appends other local endpoints' metrics
to the same response, for platforms that scrape one endpoint per app (for
example Litestream's `http://127.0.0.1:9090/metrics`).

### Account API

Signed-in users manage their own account on the public listener under
`/api/me`, authenticated with `Authorization: Bearer <token>` where the token
is an external JWT or one of their API tokens. Anonymous tokens are refused.
Browser origins must be in `ALLOWED_ORIGINS` (sessions: `SESSION_ALLOWED_ORIGINS`, `*` for any); CORS headers are emitted.

| Route | Purpose |
|---|---|
| `GET /api/me` | Account, tier limits, current-period usage, active session count. |
| `GET /api/me/usage` | Current period plus up to 12 monthly rows. |
| `GET /api/me/sessions` | The caller's live sessions. |
| `DELETE /api/me/sessions/:id` | Close one of the caller's sessions (code 1008). |
| `GET /api/me/tokens` | The caller's API tokens (never the secrets). |
| `POST /api/me/tokens` | Create a token: `{ "name", "expiresInDays"? }`. The secret is returned once. At most 20 active tokens. Needs a sign-in (external JWT), not an API token. |
| `DELETE /api/me/tokens/:id` | Revoke one of the caller's tokens and close sessions opened with it. Needs a sign-in. |
| `POST /api/me/redeem` | Redeem an invite code: `{ "code" }`. Activates a pending account; 10 failed attempts per hour per account. |
| `DELETE /api/me` | Delete the caller's account, tokens and usage: `{ "confirm": "<username>" }`. Needs a sign-in (external JWT), not an API token; operators are deleted from the admin panel. |

With `SIGNUP_MODE=invite`, an account first seen through the external
identity provider starts `pending`. It can call `GET /api/me`, redeem an
invite and delete itself; opening a session or creating a token returns
`403 account-pending`. Operators create single-use codes (`RLY-XXXX-XXXX-XXXX`,
only a hash is stored) under **Invites** in the admin panel, or activate a
pending account directly.

### Hosted-mode settings

| Setting | Purpose | Local default | Hosted default |
| --- | --- | --- | --- |
| `RELAY_MODE` | `local` or `hosted`. | `local` | |
| `AUTH_REQUIRED` | Require a credential on every WebSocket upgrade. | `false` | `true` |
| `ANON_ENABLED`, `ANON_TOKEN_SECRET` | Anonymous demo tokens and their signing key. | `false` | `true`, required |
| `ANON_TOKEN_TTL_S`, `ANON_TOKEN_BIND_IP`, `ANON_TOKENS_PER_IP_PER_HOUR` | Anonymous token lifetime, address binding, issuance limit. | `900`, `true`, `10` | same |
| `TURNSTILE_SECRET` | Require a Cloudflare Turnstile check to issue anonymous tokens. | unset | unset |
| `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_JWKS_URL`, `JWT_USERNAME_CLAIM`, `JWT_DEFAULT_TIER` | External OIDC verification. | unset | unset |
| `TRUSTED_PROXY_CIDRS`, `PEER_IP_HEADER` | Only believe `CLIENT_IP_HEADER` when the peer (socket address, or `PEER_IP_HEADER` such as `fly-client-ip`) is in these ranges, e.g. Cloudflare's. | unset | unset (warns when `TRUST_PROXY` is on) |
| `ADMIN_OIDC_ISSUER`, `ADMIN_OIDC_CLIENT_ID`, `ADMIN_OIDC_CLIENT_SECRET`, `ADMIN_OIDC_REDIRECT_URL` | Operator single sign-on for the admin panel (OIDC code flow). The callback path comes from the redirect URL; an operator's account must have the provider identity as `external_sub` (`<iss>\|<sub>`). | unset | unset |
| `ADMIN_OIDC_REQUIRE_MFA`, `ADMIN_PASSWORD_LOGIN` | Refuse SSO logins whose ID token lacks `amr: ["mfa"]`; keep the password form. | `true`, `true` | same |
| `JWT_ALGORITHMS`, `JWT_VERIFIED_CLAIM` | Allowed JWT algorithms; claim that must be `true` before the email becomes the username. | `RS256`, unset | same |
| `SIGNUP_MODE` | `open`, or `invite` to create new external accounts as pending until they redeem an invite code. | `open` | `open` |
| `ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the HTTP APIs (`/api/me`, anonymous tokens) and, unless `SESSION_ALLOWED_ORIGINS` is set, to open sessions. | unset | unset (warns) |
| `SESSION_ALLOWED_ORIGINS` | Browser origins allowed to open sessions; `*` for any. Safe to open up because sessions authenticate with a token, not a cookie. | `ALLOWED_ORIGINS` | `ALLOWED_ORIGINS` |
| `ALLOW_QUERY_TOKEN` | Accept `?token=` on the upgrade URL (leaks into logs). | `false` | `false` |
| `EGRESS_POLICY`, `EGRESS_DENY_CIDRS`, `EGRESS_ALLOW_CIDRS`, `EGRESS_DENY_PORTS` | Outbound destination policy. Allow-listed CIDRs are exceptions to the deny list. | `open` | `hosted`, deny port 25 |
| `ANTI_SPOOF` | Lock each session to its first source IP and MAC. | `true` | `true` |
| `TRUST_PROXY`, `TRUST_PROXY_HOPS`, `CLIENT_IP_HEADER` | Derive the client address from a trusted reverse proxy header. | `false` | `true`, `1`, `x-forwarded-for` |
| `INBOUND_RULES_ENABLED` | Enable the reverse proxy and port-forward rules. | `true` | `false` |
| `TIERS_JSON` | Tier overrides. | unset | unset |
| `WS_HEARTBEAT_MS`, `SESSION_IDLE_TIMEOUT_MS` | Ping interval (terminate after two missed pongs) and a global idle timeout override. | `30000`, `0` | same |
| `ADDRESS_HOLD_MS` | How long a closed session's address stays reserved for its owner's reconnect; `0` releases it at once. | `0` | `60000` |
| `SHUTDOWN_TIMEOUT_MS`, `SHUTDOWN_HARD_EXIT_MS` | Flush budget and hard exit after SIGTERM. | `500`, `800` | same |
| `AUDIT_ENABLED`, `AUDIT_RETENTION_DAYS` | Connection audit log and its retention. | `false`, `30` | `true`, `30` |
| `USAGE_FLUSH_INTERVAL_MS` | How often byte counters are persisted. | `30000` | same |
| `METRICS_ENABLED`, `METRICS_TOKEN`, `METRICS_PUBLIC` | Prometheus endpoint, an optional scrape token, and whether to serve it without auth. | `false` | `true`, unset, `false` |
| `METRICS_MERGE_URLS` | Comma-separated local metrics endpoints appended to `/metrics`; families the relay already exports and unreachable URLs are skipped. | unset | unset |
| `LOG_JSON` | JSON-lines logs for the hosted modules. | `false` | `true` |
| `ADMIN_AUTH_DB_PATH` | SQLite database (accounts, tokens, usage, audit, admin sessions). | `./admin_auth.sqlite` | `/data/admin_auth.sqlite` in Docker |
| `ADMIN_SESSION_SECRET`, `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_PASSWORD`, `ADMIN_TRUST_PROXY`, `ADMIN_COOKIE_SECURE` | Operator login. The bootstrap pair creates the first operator when none exists. | | secret required |
| `ADMIN_PUBLIC_PATH` | Also mount the admin app on the public port under this prefix (single-port platforms; requires `ADMIN_COOKIE_SECURE=true`). | unset | unset |

Set `LOG_LEVEL=0` in hosted deployments; the data plane logs every packet at
the default level.

### Deployment notes

- One instance serves at most 240 concurrent sessions (the `10.0.2.0/24`
  pool). Session state is in memory and the database is SQLite, so run a
  single instance behind TLS termination. Fly.io or a VPS with Docker and a
  reverse proxy are the simplest fits. Cloud Run works for the WebSocket data
  plane but cuts connections at its request timeout, so set `maxSessionMs`
  below it and keep `min-instances=1`.
- Egress bandwidth is the dominant cost. Tier quotas and `RATE_LIMIT_KBPS`
  are the knobs.
- The audit log (owner, destination, bytes, times) is what lets you answer an
  abuse report; keep `AUDIT_RETENTION_DAYS` at least as long as your provider's
  complaint window.
- Upload limiting drops VM data segments over budget, so it polices rather
  than shapes. Anonymous tokens are bound to the client address and break if
  that address changes mid-session.

## IP-stack choke test

The [performance investigation](benchmarks/PERFORMANCE.md) records the correctness
fixes, baseline revisions (including `main`), CPU hotspots, and measured results.

Run the single-process packet construction and checksum benchmark with:

```bash
npm run bench:ip-stack
```

The benchmark reports packets per second, application-payload throughput, and
IPv4 throughput for TCP and UDP across several payload sizes. It measures the
CPU ceiling of the relay's packet-building hot path; it does not include
WebSocket, kernel socket, rate limiting, or network I/O. TCP packets larger than
the relay's 1460-byte MSS are synthetic stress cases; the separately reported
`Production TCP MSS ceiling` is the relevant packet-building limit for TCP.
Use longer samples or select cases with:

```bash
npm run bench:ip-stack -- --duration-ms=3000 --protocol=tcp --sizes=1460,8192,32768
```

Use `--json` to capture comparable results before and after an optimization.

To include the real WebSocket ingress and relay UDP forwarding path, run:

```bash
npm run bench:ws
```

This starts a temporary loopback relay, sends Ethernet/IPv4/UDP frames through
WebSocket, and reports the payload received by an isolated-worker UDP socket.
Separating the sender and receiver event loops prevents the load generator from
creating its own receive loss. Packet loss is still reported when strict
sent/relayed/received accounting detects it. Payloads above 1400 bytes are
synthetic jumbo-frame stress cases; use the reported standard-MTU reference for
ordinary Ethernet. Customize it with `--duration-ms`, `--buffer-bytes`,
`--sizes`, or `--json`.

To measure the opposite, TCP-download direction without requiring a browser or
VM image, run:

```bash
npm run bench:tcp-egress
```

This starts a real loopback TCP source and relay, then connects a fake VM over
WebSocket. The fake VM completes the TCP handshake, validates received payload,
and sends delayed cumulative ACKs. Its bounded fake NIC queue makes burst loss
and retransmission visible. The defaults compare the relay's `10240`- and
`65535`-byte TCP windows with a 20 ms ACK delay and an eight-packet receive
queue. Use `--rx-queue-packets=0` to remove the artificial NIC queue limit, or
customize the workload with `--duration-ms`, `--ack-delay-ms`, `--ack-every`,
`--rx-service-ms`, `--send-burst-segments`, `--send-burst-interval-ms`,
`--send-burst-max-segments`, `--pacing-mode`, `--initial-cwnd-bytes`,
`--tcp-mss`, `--source-bytes`, `--windows`, or `--json`.

To benchmark TCP uploads from a fake VM through the relay to a real loopback
TCP sink, run:

```bash
npm run bench:tcp-ingress
```

This direction checks byte integrity, cumulative-ACK frequency, maximum bytes
in flight, and the relay's advertised receive window. Use `--sink-pause-ms` to
exercise socket backpressure. Compare it to a Git revision with:

```bash
npm run bench:tcp-ingress-compare -- --baseline-ref=main --runs=5
```

For a repeatable comparison against a Git revision, run:

```bash
npm run bench:tcp-compare -- --baseline-ref=main --runs=5
```

The comparison extracts the baseline revision to a temporary directory and
alternates baseline/current runs to reduce run-order bias. It reports median
goodput and coefficient of variation; `--json` includes every sample plus loss,
retransmission, and payload-validity counters. The benchmark driver remains in
the current worktree for both candidates, so only the relay implementation is
changed. Use `--relay-runtime=/path/to/runtime` to run both relay candidates on
another compatible JavaScript runtime while keeping the Node.js driver fixed.
For example, after installing Bun:

```bash
npm run bench:tcp-compare -- --relay-runtime=/usr/bin/bun --runs=5
```

The default comparison models a constrained VM receive path and is useful for
detecting burst loss and recovery collapse. To measure the end-to-end TCP relay
ceiling without the simulated NIC and ACK delays, run:

```bash
npm run bench:tcp-ceiling -- --runs=5 --duration-ms=2000
```

Ceiling runs use a larger finite source payload. If a candidate delivers all of
it before the sample ends, the report warns that `--source-bytes` must be raised
before treating the result as a throughput ceiling.

Adaptive pacing starts conservatively, grows its burst after clean ACK progress,
and halves it on detected loss. Fixed mode is useful for controlled experiments;
off mode removes pacing timers while retaining a cooperative event-loop yield.

Small TCP writes are forwarded as soon as pacing, flow control, and rate limits
allow, without waiting for an earlier write's ACK. This favors interactive
latency and can produce more short packets. If a peer omits its MSS option, the
relay uses the IPv4 default of 536 bytes; smaller nonzero advertised MSS values
are also honored.

When a VM closes its receive window, the relay probes with exponential backoff
using the configured TCP RTO intervals. Valid probe ACKs keep a responsive peer
alive; consecutive unanswered probes use `TCP_RTO_MAX_RETRANSMISSIONS` as their
limit. Existing reverse-connection idle timeouts still apply. Window reopening
repairs unacknowledged probe data immediately without waiting for another RTO.

For CPU profiling, add `--relay-cpu-prof-dir` to either TCP benchmark. This profiles
only the relay child using Node's CPU profiler and flushes the profile when the
benchmark stops it. Create the output directory first:

```bash
mkdir -p performance-results/profiles
npm run bench:tcp-egress -- --duration-ms=10000 --windows=65535 \
  --ack-delay-ms=0 --ack-every=1 --rx-queue-packets=0 --rx-service-ms=0 \
  --pacing-mode=off --send-burst-segments=64 --send-burst-max-segments=64 \
  --send-burst-interval-ms=0 --source-bytes=8589934592 \
  --relay-cpu-prof-dir=performance-results/profiles
npm run bench:tcp-ingress -- --duration-ms=10000 \
  --relay-cpu-prof-dir=performance-results/profiles
```

Open the resulting `.cpuprofile` files in a CPU-profile viewer such as Chrome
DevTools. Use separate runs without profiling for throughput comparisons.
`--ack-delay-ms=0` sends fake-VM ACKs immediately; it does not schedule zero-delay
timers. For a sink that pauses and then recovers, ingress also accepts
`--sink-pause-ms=500 --sink-pause-count=3`; omitting the count keeps pausing.

### Experimental jumbo VM link

The relay terminates TCP instead of forwarding Internet IP packets directly.
That means only the private VM-to-relay link needs to support a larger MTU. To
reduce WebSocket messages and virtual-NIC packets per byte, start the relay with
an opt-in jumbo MTU, for example:

```bash
VM_MTU=9000 \
TCP_WINDOW_SIZE=65535 \
TCP_INITIAL_CWND_BYTES=17920 \
TCP_SEND_BURST_SEGMENTS=3 \
TCP_SEND_BURST_INTERVAL_MS=5 \
node relay.js
```

`VM_MTU` is advertised with DHCP option 26 and as a TCP MSS option. Confirm the
guest interface reports the requested MTU before testing a new TCP connection:

```bash
ip link show
```

If the DHCP client ignores the MTU option, set it explicitly inside the guest:

```bash
ip link set dev eth0 mtu 9000
```

Jumbo support depends on the browser VM's virtual NIC. If connectivity stalls,
return to `VM_MTU=1500`. The default remains 1500, and the relay limits outbound
segments to the MSS advertised by the guest, so a guest that advertises 1460
will not receive jumbo TCP segments.

The real-socket UDP flow collision test is opt-in:

```bash
npm run test:network
