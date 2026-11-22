package libv2ray

// -----------------------------------------------------------------------------
// libv2ray_alfa_uplink.go
//
// Give the outbounds the splice ADDED the same protected egress Java gave the
// ones it could see.
//
// THE PROBLEM, MEASURED
//
// On the secure ALFA path the uplink is applied in Java, by
// XrayConfigFactory.withUplink, to the scaffold - which is before this file's
// neighbour opens the blob. So Java puts sockopt.dialerProxy = "uplink" on the
// freedom placeholder tagged "exit-node" and on "direct", because those are the
// outbounds that exist at that moment.
//
// Then alfaSplice REPLACES the exit-node placeholder with the real upstream
// server, and the dialerProxy goes away with the object it was written on. The
// split server is worse: it is appended, so it never had one at all.
//
// The result is an outbound that dials from an unprotected socket while the tun
// carries 0.0.0.0/0, so its packets are handed back to the core and the tunnel
// feeds itself - the broken-pipe shape AlfaRoutes describes at its top. And
// because AlfaOptions is empty on this path, AlfaRoutes cannot keep that
// server's address outside the tun either: it does not know the address.
//
// Nothing in the chain work causes this and nothing in it needs this; a profile
// with only chain_server never hits it, because the chain's last link dials
// aether and aether's own socket is protected already. It matters the day a
// blob carries `upstream` or `split_server`.
//
// WHAT THIS DOES
//
// One pass over the finished outbounds, the same walk withUplink does, applied
// after the secrets are in place:
//
//   - the outbound is skipped when it cannot dial out (blackhole, dns) or when
//     it only ever dials loopback (the aether leg, the uplink itself).
//   - the dialerProxy chain is followed to the link that opens the real socket.
//   - a link that already dials through the uplink is left alone.
//   - a link whose chain ends at a LOOPBACK listener is left alone too. That is
//     the chain server, whose socket is opened by aether, and aether's egress
//     is protected on its own. withUplink treats this shape as unrewritable and
//     refuses the whole config; here it is simply not our business.
//   - anything else gets the uplink.
//
// No uplink outbound in the scaffold means the service decided the core keeps
// its own egress, and then this is a no-op.
// -----------------------------------------------------------------------------

import "strings"

// alfaCarryUplink points every spliced-in outbound at the scaffold's uplink,
// where that is what the outbound needs. It is a no-op when there is no uplink.
func alfaCarryUplink(outs []interface{}) {
	uplinkTag := alfaUplinkTagOf(outs)
	if uplinkTag == "" {
		return
	}
	byTag := nwayByTag(outs)
	for _, o := range outs {
		out, ok := o.(map[string]interface{})
		if !ok {
			continue
		}
		proto := nwayStr(out, "protocol")
		if proto == "blackhole" || proto == "dns" {
			continue
		}
		if nwayDialsOnlyLoopback(out) {
			continue
		}
		end, status := nwayChainEnd(byTag, out, uplinkTag)
		if status != nwayChainFound {
			// Already at the uplink, or a chain this pass cannot follow. Either
			// way there is nothing safe to add.
			continue
		}
		if nwayDialsOnlyLoopback(end) {
			// The chain server: carried by aether, protected by aether.
			continue
		}
		if nwayDialerOf(end) != "" {
			continue
		}
		nwaySetDialer(end, uplinkTag)
	}
}

// alfaUplinkTagOf finds the uplink Java added: a socks outbound on loopback
// whose tag is the uplink tag or one of freeTag's "uplink-N" variants.
func alfaUplinkTagOf(outs []interface{}) string {
	for _, o := range outs {
		out, ok := o.(map[string]interface{})
		if !ok {
			continue
		}
		tag := nwayStr(out, "tag")
		if tag != nwayTagUplink && !strings.HasPrefix(tag, nwayTagUplink+"-") {
			continue
		}
		if nwayStr(out, "protocol") != "socks" || !nwayDialsOnlyLoopback(out) {
			continue
		}
		return tag
	}
	return ""
}
