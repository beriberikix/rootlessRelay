"use strict";

function getReverseFlow(srcIP, dstIP, srcPort, dstPort) {
  return {
    relaySrcIP: dstIP,
    relayDstIP: srcIP,
    relaySrcPort: dstPort,
    relayDstPort: srcPort,
  };
}

module.exports = {
  getReverseFlow,
};
