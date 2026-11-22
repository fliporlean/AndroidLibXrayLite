package libv2ray

// -----------------------------------------------------------------------------
// libv2ray_alfa_chain.go
//
// The chain server: the hop that sits AFTER aether.
//
// WHAT IT IS, AND HOW IT DIFFERS FROM `upstream`
//
// `upstream` (the outbound tagged "exit-node") sits UNDER aether: it is how
// aether REACHES Cloudflare, so the address the internet sees is still
// Cloudflare's. `chain_server` is the opposite end: the apps' catch-all goes to
// it, and it is dialled THROUGH aether, so the address the internet sees is
// this server.
//
//   socks-in --> "chain-exit" --dialerProxy--> "aether" --> libaether.so
//                                                             |
//                                                       Cloudflare
//                                                             |
//                                                      the chain server
//                                                             |
//                                                         internet
//
// Two consequences worth knowing, because they are the whole point:
//
//   - the exit COUNTRY becomes selectable, which `upstream` can never do.
//   - the chain server's address is only ever dialled from inside Cloudflare's
//     network, never from the user's, so a DPI on the user's carrier never sees
//     it and it does not burn.
//
// FAILOVER
//
// A dead chain server would otherwise cost the user the whole internet: every
// app connection ends at a door that no longer opens. So the catch-all does not
// point at the chain directly - it points at a balancer whose only candidate is
// the chain and whose fallbackTag is "aether". The core's burst observatory
// probes the chain; while it answers, the balancer picks it; when it stops, the
// balancer has no live candidate and the fallback carries the traffic. The user
// loses the chosen exit, not the connection.
//
// Three facts from the core this rests on (app/router, app/observatory/burst):
//
//   - the "random" strategy counts a candidate with NO observation yet as
//     alive, so the chain is in use from the first connection rather than only
//     after the first probe returns.
//   - Alive is `All != Fail`: the chain is dropped only when EVERY sample in
//     the window failed, and ONE successful probe brings it back.
//   - an interval under 10s is clamped up to 10s with a warning, so 10s is the
//     most responsive setting there is.
//
// That last one matters more here than on Apple. aether is started AFTER the
// core (its --upstream dials the core's second inbound during its first
// handshake), so the observatory's initial probe always goes out before aether
// is listening and always fails. The chain is therefore demoted for the first
// moments of every connection and restored by the first probe that lands after
// aether is up. 10s keeps that window as short as the core allows.
//
// WHY THIS IS ALL IN GO
//
// The chain server is a server secret, so it only exists after the blob is
// decrypted in here. Java builds no part of it: no field, no placeholder, no
// balancer. A build whose .aar predates this file produces exactly the config
// it produces today, and a blob with no chain_server leaves the config
// untouched - so there is no coupling between the two sides to get wrong.
//
// Nothing in this file modifies an existing function. alfaSplice calls
// alfaApplyChain once; everything else lives here.
// -----------------------------------------------------------------------------

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	// XrayConfigFactory.TAG_AETHER - the socks outbound pointing at
	// libaether.so's own listener, and the fallback when the chain is down.
	alfaTagAether = "aether"

	// The chain's head. NOT "chain": the balancer's selector is matched by
	// PREFIX (outbound.Manager.Select uses strings.HasPrefix), so a selector of
	// "chain" would also name the hops and the balancer could pick a hop - and
	// a hop dials the destination with nothing in front of it. "chain-exit" is
	// not a prefix of "chain-via-…", and nothing in the chain refers to the
	// head, so the head can be renamed freely.
	alfaTagChainExit = "chain-exit"

	// The hops. Deliberately NOT alfaChainAs's "<head>-hop-<i>" shape, for the
	// prefix reason above.
	alfaChainHopPrefix = "chain-via-"

	alfaTagChainBalancer = "chain-balancer"

	// The DEFAULTS for the two probe addresses. Both can be replaced from the
	// blob - chain_probe_url and chain_probe_connectivity - because an address
	// that stops answering must be fixable from the backend rather than by
	// shipping a new .aar. These are only what is used when the blob says
	// nothing.
	//
	// A 204 endpoint: no body, no redirect, reachable from anywhere the chain
	// server itself can reach the internet. Note WHERE it has to be reachable
	// from: this one is fetched through the chain, so it is the chain server's
	// exit that must reach it, not the user's carrier.
	alfaChainProbeURL = "https://www.gstatic.com/generate_204"

	// The core clamps anything smaller up to 10s with a warning.
	alfaChainProbeInterval = "10s"

	// The connectivity check, and the whole reason the startup window closes.
	//
	// When a probe through the chain fails, the core asks THIS url whether the
	// network itself is up (checkConnectivity in app/observatory/burst). If it
	// cannot be reached either, the probe's result is pushed as 0 and doCheck
	// drops it - "should not put results when network is down" - so the chain
	// is not blamed for it.
	//
	// That is exactly the first moments of every connection: aether is still
	// coming up, so a probe through the chain cannot succeed. Without this, the
	// one failed sample is the only sample and the chain is demoted until the
	// next probe. With it, the sample is discarded, the chain has NO
	// observation at all, and the random strategy counts a candidate with no
	// observation as alive - so the chain is in use from the first connection.
	//
	// It is dialled DIRECTLY (newDirectPingClient, a plain http.Client with no
	// dispatcher), so it leaves the process as an ordinary socket, enters the
	// tun and comes back round to the apps' inbound. The rule below pins it to
	// the aether outbound so that it measures "is WARP up", never "is the chain
	// up" - which is what keeps the failover working: once WARP is up and only
	// the chain server is dead, this url answers, the failure is real, and the
	// chain is demoted as it should be.
	//
	// A Cloudflare host on purpose: the path to it is WARP, which IS Cloudflare,
	// so it is the one address that cannot be unreachable while the tunnel is up.
	alfaChainConnectivityURL = "http://cp.cloudflare.com/generate_204"

	// How many samples the health record keeps. Small on purpose: one bad round
	// is enough to take the chain out, one good round enough to bring it back.
	alfaChainProbeSampling = 2

	// Used when the blob does not say. Seconds.
	alfaChainDefaultLatency = 8
)

// alfaApplyChain adds the chain server to a scaffold that Java built, and
// returns the outbounds to store. A blob with no chain_server returns the
// outbounds unchanged and leaves cfg alone.
//
// It fails rather than degrading: a chain that cannot be parsed, or a scaffold
// with no "aether" outbound to dial through, is an error. Carrying on would
// send every app connection somewhere other than where the profile said, which
// is the failure that looks like success.
func alfaApplyChain(cfg map[string]interface{}, outs []interface{},
	alfa map[string]interface{}) ([]interface{}, error) {
	v, ok := alfa["chain_server"]
	if !ok || alfaIsBlank(v) {
		return outs, nil
	}

	chain, err := alfaChainOf(v)
	if err != nil {
		return nil, fmt.Errorf("chain_server: %w", err)
	}

	// The scaffold must really have the outbound we are about to dial through,
	// and it must be the aether one. Checked rather than assumed: if it is
	// missing, pointing the chain at a tag that is not there would make Xray
	// refuse the outbound and the catch-all would fall to the default.
	if _, found := nwayByTag(outs)[alfaTagAether]; !found {
		return nil, errors.New("chain_server: the scaffold has no outbound tagged " +
			strconv.Quote(alfaTagAether) + " to dial the chain through")
	}

	alfaChainVia(alfaTagChainExit, chain)

	// The LAST link, not the head. The head may dial through hops of its own -
	// a fragment leg, a noise leg - and the one that opens the real socket is
	// the end of that chain. Putting it on the head instead would cut those
	// legs out of the path, which is exactly what they are there to do.
	nwaySetDialer(chain[len(chain)-1], alfaTagAether)

	outs = append(outs, alfaToIface(chain)...)

	if err := alfaChainRoute(cfg, alfa); err != nil {
		return nil, fmt.Errorf("chain_server: %w", err)
	}
	cfg["burstObservatory"] = alfaChainObservatory(alfa)
	return outs, nil
}

// alfaChainOf is alfaOutboundChain plus the one shape the chain field can take
// that the other three fields cannot: a LIST of outbounds, which is how a
// chained server with its own fragment leg is written in a profile. The list is
// treated as the config's outbounds, so the head is picked and its dialerProxy
// chain followed through the list - the same walk alfaChainFromObject does.
func alfaChainOf(v interface{}) ([]map[string]interface{}, error) {
	if list, ok := v.([]interface{}); ok {
		if len(list) == 0 {
			return nil, errors.New("the outbound list is empty")
		}
		head, err := alfaProxyOutboundOf(list)
		if err != nil {
			return nil, err
		}
		return alfaFollowChain(head, list)
	}
	return alfaOutboundChain(v)
}

// alfaChainVia is alfaChainAs with hop names that the balancer's selector
// cannot match. Same job otherwise: retag the head, rename each hop, and
// repoint the dialerProxy of the one that dialled through it.
func alfaChainVia(headTag string, chain []map[string]interface{}) {
	if len(chain) == 0 {
		return
	}
	chain[0]["tag"] = headTag
	for i := 1; i < len(chain); i++ {
		fresh := alfaChainHopPrefix + strconv.Itoa(i)
		chain[i]["tag"] = fresh
		nwaySetDialer(chain[i-1], fresh)
	}
}

// alfaChainRoute points the apps' catch-all at the balancer instead of at
// aether, and adds the balancer.
//
// The catch-all is found by what it IS - the rule from the apps' inbound to the
// aether outbound - not by position. The rules above it (block, split, bypass)
// are left exactly where they are, so a destination assigned to one of them
// still goes there rather than through the chain.
func alfaChainRoute(cfg map[string]interface{}, alfa map[string]interface{}) error {
	routing := nwayObj(cfg, "routing")
	if routing == nil {
		return errors.New("the scaffold has no routing")
	}
	rules := nwayArr(routing, "rules")
	if rules == nil {
		return errors.New("the scaffold has no routing rules")
	}

	found := false
	for i, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok || nwayStr(rule, "outboundTag") != alfaTagAether {
			continue
		}
		if !alfaRuleFromInbound(rule, nwaySocksInTag) {
			continue
		}
		// Replaced, not added alongside: a rule carrying both an outboundTag
		// and a balancerTag is ambiguous, and the core reads the outbound one.
		delete(rule, "outboundTag")
		rule["balancerTag"] = alfaTagChainBalancer
		found = true
		// The connectivity check rides aether, not the chain. The domain comes
		// from whichever address is actually in use, so changing it from the
		// backend moves the rule with it. Inserted right here, immediately
		// above the catch-all, so every rule the scaffold already had keeps
		// its place and its precedence.
		if host := alfaHostRule(alfaChainConnectivity(alfa)); host != "" {
			rules = alfaInsertBefore(rules, i, map[string]interface{}{
				"inboundTag":  []interface{}{nwaySocksInTag},
				"domain":      []interface{}{host},
				"outboundTag": alfaTagAether,
			})
			routing["rules"] = rules
		}
		break
	}
	if !found {
		return errors.New("the scaffold has no rule sending the apps' inbound to " +
			strconv.Quote(alfaTagAether) + ", so there is no catch-all to put the chain in front of")
	}

	routing["balancers"] = []interface{}{
		map[string]interface{}{
			"tag":      alfaTagChainBalancer,
			"selector": []interface{}{alfaTagChainExit},
			// "random" over a single candidate is deterministic, and it is the
			// one strategy that treats a candidate with no observation yet as
			// alive - which is what keeps the chain in use from the first
			// connection instead of only after the first probe returns.
			"strategy": map[string]interface{}{"type": "random"},
			// Without this the strategy never consults the observatory at all,
			// and the chain would be picked even when it is dead.
			"fallbackTag": alfaTagAether,
		},
	}
	return nil
}

// alfaRuleFromInbound reports whether a rule is scoped to one inbound tag.
func alfaRuleFromInbound(rule map[string]interface{}, tag string) bool {
	list, ok := rule["inboundTag"].([]interface{})
	if !ok {
		return false
	}
	for _, v := range list {
		if s, ok := v.(string); ok && s == tag {
			return true
		}
	}
	return false
}

// alfaChainObservatory is the burstObservatory section that watches the chain.
//
// The connectivity entry is left OUT when its host cannot be worked out, and
// that is deliberate rather than tidy: the core dials it directly, so it only
// stays off the chain because of the routing rule alfaChainRoute pins to its
// host. An unpinned connectivity check would ride the chain, and then a dead
// chain server would make every failure be discarded and the failover would
// never fire. Without the entry the core counts every failure, which is the
// behaviour this had before - safe, just less forgiving at startup.
func alfaChainObservatory(alfa map[string]interface{}) map[string]interface{} {
	ping := map[string]interface{}{
		"destination": alfaChainProbeDestination(alfa),
		"interval":    alfaChainProbeInterval,
		"sampling":    alfaChainProbeSampling,
		// A string: the core's duration type refuses a bare number.
		"timeout": strconv.Itoa(alfaChainLatency(alfa)) + "s",
	}
	if conn := alfaChainConnectivity(alfa); conn != "" && alfaHostRule(conn) != "" {
		ping["connectivity"] = conn
	}
	return map[string]interface{}{
		"subjectSelector": []interface{}{alfaTagChainExit},
		"pingConfig":      ping,
	}
}

// alfaChainProbeDestination is what the probe asks for, through the chain.
// chain_probe_url replaces it; absent or blank keeps the default.
func alfaChainProbeDestination(alfa map[string]interface{}) string {
	if s := alfaChainStr(alfa, "chain_probe_url"); s != "" {
		return s
	}
	return alfaChainProbeURL
}

// alfaChainConnectivity is the address that decides whether a failed probe
// counts. chain_probe_connectivity replaces it; a key sent EMPTY turns the
// connectivity check off altogether, which is a real choice and not a mistake:
// it restores the stricter behaviour where every failed probe counts, at the
// cost of the chain being demoted for the first moments of a connection.
func alfaChainConnectivity(alfa map[string]interface{}) string {
	v, ok := alfa["chain_probe_connectivity"]
	if !ok {
		return alfaChainConnectivityURL
	}
	if s, isStr := v.(string); isStr {
		return strings.TrimSpace(s)
	}
	return alfaChainConnectivityURL
}

// alfaHostRule turns an address into the routing-rule form that matches only
// it - "full:host" - or "" when there is no host to match on. A rule built from
// a guess would send the wrong traffic to aether, so no guessing: a url that
// does not parse, or has no host, gets no rule.
func alfaHostRule(address string) string {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	return "full:" + strings.ToLower(host)
}

// alfaChainStr reads a trimmed string field, or "" when it is absent, null or
// of another type.
func alfaChainStr(alfa map[string]interface{}, key string) string {
	if v, ok := alfa[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// alfaChainLatency reads chain_server_latency - how long one probe through the
// chain may take. It comes from the profile rather than being fixed here
// because only whoever wrote the profile knows how far the chain is: a distant
// server behind Cloudflare needs more than a near one.
func alfaChainLatency(alfa map[string]interface{}) int {
	v, ok := alfa["chain_server_latency"]
	if !ok {
		return alfaChainDefaultLatency
	}
	switch n := v.(type) {
	case float64:
		if int(n) > 0 {
			return int(n)
		}
	case string:
		if i, err := strconv.Atoi(n); err == nil && i > 0 {
			return i
		}
	}
	return alfaChainDefaultLatency
}

// alfaInsertBefore puts rule at index i, keeping everything else in order.
func alfaInsertBefore(rules []interface{}, i int, rule map[string]interface{}) []interface{} {
	if i < 0 || i > len(rules) {
		i = len(rules)
	}
	next := make([]interface{}, 0, len(rules)+1)
	next = append(next, rules[:i]...)
	next = append(next, rule)
	next = append(next, rules[i:]...)
	return next
}
