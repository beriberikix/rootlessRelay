"use strict";

// Per-session policy: anti-spoofing, tenant isolation, egress control,
// connection caps and bandwidth policing. relay.js calls these methods from
// one-line `// HOSTED:` hooks and treats a false return as "drop this packet".
//
// The policy never touches the data plane's own state except through the
// documented session fields (vmIP, tcpConnections, rateLimiter, udpFlows) and
// the shared IP bookkeeping Maps that relay.js passes in as `ctx`.

const { SlidingWindowRateLimiter } = require("../rate_limiter");
const { buildIPv4Packet, tcpChecksum } = require("../packet_utils");

const WS_OPEN = 1;
const DHCP_SERVER_PORT = 67;
const DENY_AUDIT_INTERVAL_MS = 10000;
// Audit volume caps per session, so a VM cannot fill the disk or memory with
// rows: denied attempts beyond the budget are summarised once per minute;
// allowed connections beyond theirs are counted in the same summary.
const AUDIT_WINDOW_MS = 60000;
const DENY_AUDIT_PER_WINDOW = 30;
const ALLOW_AUDIT_PER_WINDOW = 600;
const DENIED_KEYS_MAX = 1024;
// Traffic between sessions of one owner is shaped rather than policed: it
// waits in a short per-session queue and leaves at the download rate, so
// TCP between sessions sees delay instead of bursts of loss, which made it
// collapse to a fraction of the limit. The queue is capped at about a
// quarter second of traffic; beyond that packets are dropped as before.
const PEER_BURST_BYTES = 64 * 1024;
const PEER_QUEUE_MAX_BYTES = 256 * 1024;
const PEER_DRAIN_MIN_MS = 2;
const PEER_DRAIN_MAX_MS = 50;

function unlimitedLimiter() {
  return { tryConsume: () => true, get usage() { return 0; } };
}

function makeLimiter(perSecond, now) {
  if (perSecond === null || perSecond === undefined) return null;
  if (perSecond <= 0) return { tryConsume: () => false };
  return new SlidingWindowRateLimiter(perSecond, 1000, now);
}

function buildTcpReset({ srcIP, srcPort, dstIP, dstPort, seq = 0, ack = 0 }) {
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 5 << 4;
  tcp[13] = 0x14; // RST | ACK
  tcp.writeUInt16BE(0, 14);
  tcp.writeUInt16BE(0, 16);
  tcp.writeUInt16BE(0, 18);
  const packet = buildIPv4Packet(tcp, srcIP, dstIP, 6);
  packet.writeUInt16BE(tcpChecksum(packet), 20 + 16);
  return packet;
}

// Token bucket pacing the peer queue; the session's sliding-window limiter
// still accounts for every byte.
class TokenBucket {
  constructor(rate, burst, now) {
    this.rate = rate;
    this.burst = burst;
    this.now = now;
    this.tokens = burst;
    this.last = now();
  }

  refill() {
    const t = this.now();
    this.tokens = Math.min(this.burst, this.tokens + ((t - this.last) * this.rate) / 1000);
    this.last = t;
  }

  // Packets larger than the burst pass once the bucket is full.
  has(bytes) {
    this.refill();
    return this.tokens >= Math.min(bytes, this.burst);
  }

  consume(bytes) {
    this.tokens -= bytes;
  }

  msUntil(bytes) {
    this.refill();
    const need = Math.min(bytes, this.burst) - this.tokens;
    return need <= 0 ? 0 : (need * 1000) / this.rate;
  }
}

function ipv4ToInt(ip) {
  if (typeof ip !== "string") return -1;
  return ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
}

function isLive(session) {
  return Boolean(session && session.ws && session.ws.readyState === WS_OPEN);
}

class SessionPolicy {
  constructor({
    tier,
    identity,
    egress,
    ctx,
    antiSpoof = true,
    audit = null,
    metrics = null,
    log = null,
    now = Date.now,
    setTimer = setTimeout,
    clearTimer = clearTimeout,
  }) {
    this.tier = tier;
    this.identity = identity;
    this.egress = egress;
    this.ctx = ctx;
    this.antiSpoof = antiSpoof;
    this.audit = audit;
    this.metrics = metrics;
    this.log = log;
    this.now = now;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;

    this.peerPacer = tier.downloadBps === null ? null : new TokenBucket(tier.downloadBps, PEER_BURST_BYTES, now);
    this.gatewayInt = ipv4ToInt(ctx && ctx.GATEWAY_IP);
    this.peerQueue = [];
    this.peerQueueBytes = 0;
    this.peerTimer = null;
    this.peerReleasing = false;

    this.uploadLimiter = tier.uploadBps === null ? null : new SlidingWindowRateLimiter(tier.uploadBps, 1000, now);
    this.synLimiter = makeLimiter(tier.synPerSec, now);
    this.dnsLimiter = makeLimiter(tier.dnsQps, now);
    this.allowedTcpPorts = tier.allowedTcpPorts ? new Set(tier.allowedTcpPorts) : null;
    this.allowedUdpPorts = tier.allowedUdpPorts ? new Set(tier.allowedUdpPorts) : null;
    this.dnsServers = tier.dnsServers ? new Set(tier.dnsServers) : null;

    this.pendingConnects = new Map(); // connKey -> { startedAt, dstIP, dstPort }
    this.deniedAt = new Map(); // "proto:ip:port" -> last audit time, at most DENIED_KEYS_MAX
    this.auditWindow = { start: now(), deny: 0, allow: 0, suppressedDeny: 0, suppressedAllow: 0 };
    this.counters = {
      spoofDrops: 0,
      macDrops: 0,
      uploadDrops: 0,
      downloadDrops: 0,
      peerQueued: 0,
      egressDenied: 0,
      synRateDrops: 0,
      connCapDenied: 0,
      udpDenied: 0,
      dnsRateDrops: 0,
      connectTimeouts: 0,
    };
  }

  // Shape the session's upstream-owned limiter and flow cap to the tier.
  applyToSession(session) {
    if (this.tier.downloadBps === null) {
      session.rateLimiter = unlimitedLimiter();
    } else {
      session.rateLimiter = new SlidingWindowRateLimiter(this.tier.downloadBps, 1000, this.now);
    }
    if (this.tier.maxUdpFlows !== null && session.udpFlows) {
      session.udpFlows.maxFlows = this.tier.maxUdpFlows;
    }
  }

  // H3: a session keeps the MAC it first used, and may not borrow a MAC that
  // another live session's IP is bound to.
  admitFrame(session, srcMAC) {
    if (!this.antiSpoof) return true;
    if (session.vmMACBytes) {
      if (session.vmMACBytes.equals(srcMAC)) return true;
      this.counters.macDrops += 1;
      return false;
    }
    const macStr = Array.from(srcMAC).map((b) => b.toString(16).padStart(2, "0")).join(":");
    const boundIP = this.ctx.macToIP.get(macStr);
    if (boundIP) {
      const holder = this.ctx.ipToSession.get(boundIP);
      if (holder && holder !== session && isLive(holder)) {
        this.counters.macDrops += 1;
        return false;
      }
    }
    return true;
  }

  // H4: learn-then-lock source address, then police upload bandwidth.
  admitIPv4(session, parsed, ipPacket) {
    const { protocol, srcIP, dstIP } = parsed;
    if (this.antiSpoof) {
      if (srcIP === "0.0.0.0") {
        if (!(protocol === 17 && dstIP === "255.255.255.255")) {
          this.counters.spoofDrops += 1;
          return false;
        }
      } else if (!session.vmIP) {
        if (!this.claimIP(session, srcIP)) {
          this.counters.spoofDrops += 1;
          return false;
        }
      } else if (srcIP !== session.vmIP) {
        this.counters.spoofDrops += 1;
        return false;
      }
    }

    if (!this.uploadLimiter) return true;
    if (srcIP === "0.0.0.0" || protocol === 1 || dstIP === this.ctx.GATEWAY_IP) return true;
    // Traffic to another session of this owner is shaped at the receiver
    // (admitDownload); policing it here as well would drop it first.
    const peer = this.ctx.ipToSession.get(dstIP);
    if (peer && this.canReach(session, peer)) return true;
    const headerLength = parsed.headerLength;
    let bytes = 0;
    if (protocol === 6) {
      if (ipPacket.length < headerLength + 13) return true;
      const dataOffset = (ipPacket[headerLength + 12] >>> 4) * 4;
      bytes = parsed.totalLength - headerLength - dataOffset;
      if (bytes <= 0) return true;
    } else {
      bytes = parsed.totalLength - headerLength;
    }
    if (this.uploadLimiter.tryConsume(bytes)) return true;
    this.counters.uploadDrops += 1;
    return false;
  }

  claimIP(session, srcIP) {
    const prefix = this.ctx.poolPrefix;
    if (!srcIP.startsWith(prefix)) return false;
    const lastOctet = Number(srcIP.slice(prefix.length));
    if (!Number.isInteger(lastOctet)) return false;
    if (lastOctet < this.ctx.DHCP_START || lastOctet > this.ctx.DHCP_END) return false;
    if (srcIP === this.ctx.GATEWAY_IP || lastOctet === 255) return false;
    const holder = this.ctx.ipToSession.get(srcIP);
    if (holder && holder !== session && isLive(holder)) return false;

    this.ctx.usedIPs.add(lastOctet);
    if (session.vmMAC) this.ctx.macToIP.set(session.vmMAC, srcIP);
    this.ctx.ipToSession.set(srcIP, session);
    session.vmIP = srcIP;
    this.log?.info("vm ip learned", { owner: this.identity.owner, vmIP: srcIP });
    return true;
  }

  // H5-H7: VM-to-VM only inside one owner's network.
  canReach(session, other) {
    if (!this.tier.vmToVm) return false;
    if (!other || other === session) return false;
    const otherPolicy = other.policy;
    if (!otherPolicy || !otherPolicy.tier.vmToVm) return false;
    return otherPolicy.identity.owner === this.identity.owner;
  }

  // H8: egress policy, SYN rate and connection cap before net.connect.
  allowTcpConnect(session, { srcIP, srcPort, dstIP, dstPort, seqNum }) {
    const reset = () =>
      session.sendIPToVM(buildTcpReset({
        srcIP: dstIP,
        srcPort: dstPort,
        dstIP: srcIP,
        dstPort: srcPort,
        seq: 0,
        ack: (seqNum + 1) >>> 0,
      }));

    if (this.synLimiter && !this.synLimiter.tryConsume(1)) {
      this.counters.synRateDrops += 1;
      this.metrics?.synRateDrops?.inc();
      return false;
    }
    if (this.tier.maxTcpConnections !== null && session.tcpConnections.size >= this.tier.maxTcpConnections) {
      this.counters.connCapDenied += 1;
      this.metrics?.connCapDenied?.inc();
      reset();
      return false;
    }
    let reason = null;
    if (this.allowedTcpPorts && !this.allowedTcpPorts.has(dstPort)) {
      reason = "tier-port";
    } else {
      const verdict = this.egress.check(dstIP, dstPort, "tcp");
      if (!verdict.allow) reason = verdict.reason;
    }
    if (reason) {
      this.counters.egressDenied += 1;
      this.metrics?.egressDenied?.inc({ proto: "tcp" });
      this.recordDenied(session, "tcp", dstIP, dstPort, reason);
      reset();
      return false;
    }

    const connKey = `${srcPort}:${dstIP}:${dstPort}`;
    this.pendingConnects.set(connKey, { startedAt: this.now(), dstIP, dstPort });
    if (this.audit && this.takeAuditSlot(session, "allow")) {
      this.audit.record({
        owner: this.identity.owner,
        sessionId: session.sessionId,
        proto: "tcp",
        dstIP,
        dstPort,
        verdict: "allow",
        startedAt: this.now(),
        key: `${session.sessionId}:${connKey}`,
      });
    }
    return true;
  }

  // H9/H10: bytes and end time for the audit log, pending-connect cleanup.
  onTcpClose(session, connKey, conn, error) {
    const pending = this.pendingConnects.get(connKey);
    this.pendingConnects.delete(connKey);
    if (!pending) return;
    const socket = conn && conn.socket;
    this.audit?.finish(`${session.sessionId}:${connKey}`, {
      endedAt: this.now(),
      bytesIn: socket ? socket.bytesRead || 0 : 0,
      bytesOut: socket ? socket.bytesWritten || 0 : 0,
      error: error ? error.message : null,
    });
  }

  // H11/H12: UDP egress policy and DNS rate limiting.
  allowUdpSend(session, dstIP, dstPort, isDNS, bytes) {
    if (isDNS) {
      if (this.dnsLimiter && !this.dnsLimiter.tryConsume(1)) {
        this.counters.dnsRateDrops += 1;
        return false;
      }
      if (this.dnsServers && !this.dnsServers.has(dstIP)) {
        this.counters.udpDenied += 1;
        this.recordDenied(session, "udp", dstIP, dstPort, "tier-dns-server");
        return false;
      }
    } else if (this.allowedUdpPorts && !this.allowedUdpPorts.has(dstPort)) {
      this.counters.udpDenied += 1;
      this.recordDenied(session, "udp", dstIP, dstPort, "tier-port");
      return false;
    }
    const verdict = this.egress.check(dstIP, dstPort, "udp");
    if (!verdict.allow) {
      this.counters.udpDenied += 1;
      this.metrics?.egressDenied?.inc({ proto: "udp" });
      this.recordDenied(session, "udp", dstIP, dstPort, verdict.reason);
      return false;
    }
    return true;
  }

  // H13: everything the relay sends to the VM except internet TCP (which
  // drainTCPToVM already paces) and DHCP replies shares the download budget.
  admitDownload(session, ipPacket) {
    if (this.peerReleasing) return true; // budget already taken by releasePeerQueue
    if (!session.rateLimiter) return true;
    const protocol = ipPacket[9];
    const headerLength = (ipPacket[0] & 0x0f) * 4;
    const srcInPool = ipPacket[12] === this.ctx.poolBytes[0] &&
      ipPacket[13] === this.ctx.poolBytes[1] &&
      ipPacket[14] === this.ctx.poolBytes[2];
    if (protocol === 6 && !srcInPool) return true;
    if (protocol === 17 && ipPacket.length >= headerLength + 2 &&
      ipPacket.readUInt16BE(headerLength) === DHCP_SERVER_PORT) {
      return true;
    }
    if (srcInPool && this.peerPacer && ipPacket.readUInt32BE(12) !== this.gatewayInt) {
      return this.shapePeerPacket(session, ipPacket);
    }
    if (session.rateLimiter.tryConsume(ipPacket.length)) return true;
    this.counters.downloadDrops += 1;
    return false;
  }

  // Sends a packet from another session now if the pacer and the download
  // budget allow and nothing is queued ahead of it; otherwise queues it.
  // Returns true when relay.js should send it immediately.
  shapePeerPacket(session, ipPacket) {
    if (this.peerQueue.length === 0 && this.takePeerBudget(session, ipPacket.length)) return true;
    if (this.peerQueueBytes + ipPacket.length > PEER_QUEUE_MAX_BYTES) {
      this.counters.downloadDrops += 1;
      return false;
    }
    this.peerQueue.push(ipPacket);
    this.peerQueueBytes += ipPacket.length;
    this.counters.peerQueued += 1;
    this.schedulePeerRelease(session);
    return false;
  }

  takePeerBudget(session, bytes) {
    if (!this.peerPacer.has(bytes)) return false;
    if (!session.rateLimiter.tryConsume(bytes)) return false;
    this.peerPacer.consume(bytes);
    return true;
  }

  schedulePeerRelease(session) {
    if (this.peerTimer || this.peerQueue.length === 0) return;
    const wait = this.peerPacer.msUntil(this.peerQueue[0].length);
    const delay = Math.min(PEER_DRAIN_MAX_MS, Math.max(PEER_DRAIN_MIN_MS, Math.ceil(wait)));
    this.peerTimer = this.setTimer(() => {
      this.peerTimer = null;
      this.releasePeerQueue(session);
    }, delay);
  }

  // Sends queued packets in order while budget allows, then reschedules.
  releasePeerQueue(session) {
    if (!isLive(session)) {
      this.clearPeerQueue();
      return;
    }
    while (this.peerQueue.length > 0 && this.takePeerBudget(session, this.peerQueue[0].length)) {
      const packet = this.peerQueue.shift();
      this.peerQueueBytes -= packet.length;
      this.peerReleasing = true;
      try {
        session.sendIPToVM(packet);
      } finally {
        this.peerReleasing = false;
      }
    }
    this.schedulePeerRelease(session);
  }

  clearPeerQueue() {
    if (this.peerTimer) this.clearTimer(this.peerTimer);
    this.peerTimer = null;
    this.peerQueue = [];
    this.peerQueueBytes = 0;
  }

  // Called periodically by the connection handler: abort real sockets that
  // never finished connecting so a VM cannot park thousands of half-open
  // connections to black-holed hosts.
  sweep(session, now = this.now()) {
    const timeout = this.tier.connectTimeoutMs;
    if (timeout === null) return;
    for (const [connKey, pending] of this.pendingConnects) {
      const conn = session.tcpConnections.get(connKey);
      if (!conn) {
        this.pendingConnects.delete(connKey);
        continue;
      }
      const socket = conn.socket;
      if (socket && socket.connecting && now - pending.startedAt >= timeout) {
        this.counters.connectTimeouts += 1;
        session.abortTCPConnection(connKey, conn, new Error("connect timeout"));
      } else if (socket && !socket.connecting) {
        // Connected; keep the entry only for audit bookkeeping.
        pending.connected = true;
      }
    }
  }

  onSessionClose(session) {
    this.clearPeerQueue();
    const endedAt = this.now();
    for (const connKey of this.pendingConnects.keys()) {
      const conn = session.tcpConnections.get(connKey);
      const socket = conn && conn.socket;
      this.audit?.finish(`${session.sessionId}:${connKey}`, {
        endedAt,
        bytesIn: socket ? socket.bytesRead || 0 : 0,
        bytesOut: socket ? socket.bytesWritten || 0 : 0,
        error: "session closed",
      });
    }
    this.pendingConnects.clear();
    this.deniedAt.clear();
    if (this.audit) this.flushAuditSummary(session);
  }

  // Writes one row summarising audit rows skipped in the last window.
  flushAuditSummary(session) {
    const w = this.auditWindow;
    if (w.suppressedDeny === 0 && w.suppressedAllow === 0) return;
    this.audit.record({
      owner: this.identity.owner,
      sessionId: session.sessionId,
      proto: "summary",
      dstIP: "0.0.0.0",
      dstPort: 0,
      verdict: `suppressed:deny=${w.suppressedDeny}:allow=${w.suppressedAllow}`,
      startedAt: w.start,
      endedAt: this.now(),
    });
    w.suppressedDeny = 0;
    w.suppressedAllow = 0;
  }

  takeAuditSlot(session, kind) {
    const now = this.now();
    const w = this.auditWindow;
    if (now - w.start >= AUDIT_WINDOW_MS) {
      this.flushAuditSummary(session);
      w.start = now;
      w.deny = 0;
      w.allow = 0;
    }
    const limit = kind === "deny" ? DENY_AUDIT_PER_WINDOW : ALLOW_AUDIT_PER_WINDOW;
    if (w[kind] >= limit) {
      if (kind === "deny") w.suppressedDeny += 1;
      else w.suppressedAllow += 1;
      return false;
    }
    w[kind] += 1;
    return true;
  }

  recordDenied(session, proto, dstIP, dstPort, reason) {
    if (!this.audit) return;
    const key = `${proto}:${dstIP}:${dstPort}`;
    const now = this.now();
    const last = this.deniedAt.get(key);
    if (last !== undefined && now - last < DENY_AUDIT_INTERVAL_MS) return;
    if (!this.takeAuditSlot(session, "deny")) return;
    if (this.deniedAt.size >= DENIED_KEYS_MAX) {
      for (const [k, t] of this.deniedAt) if (now - t >= DENY_AUDIT_INTERVAL_MS) this.deniedAt.delete(k);
      if (this.deniedAt.size >= DENIED_KEYS_MAX) this.deniedAt.clear();
    }
    this.deniedAt.set(key, now);
    this.audit.record({
      owner: this.identity.owner,
      sessionId: session.sessionId,
      proto,
      dstIP,
      dstPort,
      verdict: `deny:${reason}`,
      startedAt: now,
      endedAt: now,
    });
  }
}

function createPolicyFactory({
  config,
  tiers,
  egress,
  ctx,
  audit = null,
  metrics = null,
  log = null,
  now = Date.now,
}) {
  const poolBytes = ctx.poolPrefix.split(".").filter(Boolean).map(Number);
  const policyCtx = { ...ctx, poolBytes };
  return {
    forSession(identity) {
      const tier = tiers[identity.tier] || tiers.user;
      return new SessionPolicy({
        tier,
        identity,
        egress,
        ctx: policyCtx,
        antiSpoof: config.antiSpoof,
        audit,
        metrics,
        log,
        now,
      });
    },
  };
}

module.exports = {
  SessionPolicy,
  buildTcpReset,
  createPolicyFactory,
  unlimitedLimiter,
};
