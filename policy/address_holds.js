"use strict";

// Address holds: when a session closes, its pool address stays reserved for
// its owner for a short time instead of returning to the pool. A client that
// reconnects within the hold (a browser tab waking up, a dropped network, a
// relay deploy) gets the same address back, by DHCP with the same MAC or by
// sending from the address. Traffic between an owner's sessions is routed
// as raw IP, so their TCP connections survive such a gap.
//
// Held addresses stay in usedIPs so DHCP skips them, but they count as free
// pool capacity: a full pool evicts the oldest hold.

function createAddressHolds({
  ctx,
  holdMs,
  log = null,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  const holds = new Map(); // ip -> { owner, mac, until, timer }

  function lastOctet(ip) {
    return Number(ip.slice(ctx.poolPrefix.length));
  }

  // Drops the hold; returns the address to the pool unless a session took it.
  function expire(ip) {
    const hold = holds.get(ip);
    if (!hold) return;
    clearTimer(hold.timer);
    holds.delete(ip);
    if (!ctx.ipToSession.has(ip)) ctx.usedIPs.delete(lastOctet(ip));
  }

  // Removes the hold for a session of its owner, which now holds the address.
  function take(ip) {
    const hold = holds.get(ip);
    clearTimer(hold.timer);
    holds.delete(ip);
    log?.info("held address reclaimed", { owner: hold.owner, vmIP: ip });
  }

  return {
    get size() {
      return holds.size;
    },

    // Called instead of releasing the address when a session closes. Returns
    // false when nothing is held, and the caller releases as before.
    hold(session, owner) {
      const ip = session.vmIP;
      if (!(holdMs > 0) || !ip || !owner || !ip.startsWith(ctx.poolPrefix)) return false;
      if (ctx.ipToSession.get(ip) !== session) return false;
      ctx.ipToSession.delete(ip);
      if (session.vmMAC && ctx.macToIP.get(session.vmMAC) === ip) ctx.macToIP.delete(session.vmMAC);
      const timer = setTimer(() => expire(ip), holdMs);
      timer?.unref?.();
      holds.set(ip, { owner, mac: session.vmMAC || null, until: now() + holdMs, timer });
      log?.info("address held", { owner, vmIP: ip, holdMs });
      return true;
    },

    // DHCP and ARP: give a session back the address held for its owner
    // and MAC by restoring the MAC binding that allocateIP looks up.
    reclaimForMac(owner, mac) {
      for (const [ip, hold] of holds) {
        if (hold.owner === owner && hold.mac === mac) {
          take(ip);
          ctx.macToIP.set(mac, ip);
          return ip;
        }
      }
      return null;
    },

    // Static addresses: true when the owner may claim the address.
    // Claiming an address held for the same owner takes the hold.
    mayClaim(owner, ip) {
      const hold = holds.get(ip);
      if (!hold) return true;
      if (hold.owner !== owner) return false;
      take(ip);
      return true;
    },

    // True while the address is held for the owner: traffic to it may
    // resume, so the relay should not reset connections toward it.
    isHeldFor(owner, ip) {
      const hold = holds.get(ip);
      return Boolean(hold && hold.owner === owner);
    },

    // A full pool reclaims the hold closest to expiring.
    evictOldest() {
      let oldest = null;
      for (const [ip, hold] of holds) {
        if (!oldest || hold.until < holds.get(oldest).until) oldest = ip;
      }
      if (!oldest) return false;
      log?.info("held address evicted", { vmIP: oldest });
      expire(oldest);
      return true;
    },

    clear() {
      for (const ip of [...holds.keys()]) expire(ip);
    },
  };
}

module.exports = { createAddressHolds };
