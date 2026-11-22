package libv2ray

import (
	"encoding/json"
	"strings"
	"testing"
)

// The ALFA alfaChainScaffold Java builds: XrayConfigFactory.forAlfa(new AlfaOptions())
// followed by withUplink(), which is what reaches startLoopSecureAlfa today.
const alfaChainScaffold = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag":"socks-in","listen":"127.0.0.1","port":10808,"protocol":"socks",
     "settings":{"auth":"noauth","udp":true},
     "sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}},
    {"tag":"aether-upstream","listen":"127.0.0.1","port":10822,"protocol":"socks",
     "settings":{"auth":"noauth","udp":true}}
  ],
  "outbounds": [
    {"tag":"aether","protocol":"socks","settings":{"address":"127.0.0.1","port":10819}},
    {"tag":"exit-node","protocol":"freedom","settings":{},
     "streamSettings":{"sockopt":{"dialerProxy":"uplink"}}},
    {"tag":"direct","protocol":"freedom","settings":{},
     "streamSettings":{"sockopt":{"dialerProxy":"uplink"}}},
    {"tag":"block","protocol":"blackhole","settings":{}},
    {"tag":"uplink","protocol":"socks","settings":{"address":"127.0.0.1","port":41234}}
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {"inboundTag":["aether-upstream"],"outboundTag":"exit-node"},
      {"inboundTag":["socks-in"],"domain":["domain:doubleclick.net"],"outboundTag":"block"},
      {"inboundTag":["socks-in"],"domain":["domain:bank.ir"],"outboundTag":"direct"},
      {"inboundTag":["socks-in"],"outboundTag":"aether"}
    ]
  }
}`

const alfaChainTestUpstream = "vless://11111111-1111-1111-1111-111111111111@up.example.com:443?encryption=none&security=tls&type=ws&host=up.example.com&path=/u#UP"

// A chain written as a LIST: the server plus its own fragment leg, which is the
// shape a real profile uses. The fragment values are deliberate DPI settings
// and must come through untouched.
const alfaChainTestList = `[
  {"tag":"proxy","protocol":"vless",
   "settings":{"vnext":[{"address":"ch.example.com","port":2053,
     "users":[{"id":"22222222-2222-2222-2222-222222222222","encryption":"none","level":8}]}]},
   "streamSettings":{"network":"ws","security":"tls",
     "tlsSettings":{"serverName":"ch.example.com","fingerprint":"firefox","alpn":["h2"]},
     "wsSettings":{"path":"/","headers":{"Host":"ch.example.com"}},
     "sockopt":{"dialerProxy":"fragment","tcpNoDelay":true}},
   "mux":{"enabled":true,"concurrency":4,"xudpProxyUDP443":"reject"}},
  {"tag":"fragment","protocol":"freedom",
   "settings":{"fragment":{"packets":"1-2","length":"10-100","interval":"2-4"},
     "noises":[{"type":"rand","packet":"8-15","delay":"3-8"}]},
   "streamSettings":{"sockopt":{"tcpNoDelay":true,"mark":255}}}
]`

func alfaChainRun(t *testing.T, blob string) map[string]interface{} {
	t.Helper()
	out, err := alfaSplice(alfaChainScaffold, blob, false)
	if err != nil {
		t.Fatalf("alfaSplice: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("output is not json: %v", err)
	}
	return cfg
}

func alfaChainTags(cfg map[string]interface{}) []string {
	var out []string
	for _, o := range nwayArr(cfg, "outbounds") {
		out = append(out, nwayStr(o.(map[string]interface{}), "tag"))
	}
	return out
}

func alfaChainByTag(cfg map[string]interface{}, tag string) map[string]interface{} {
	return nwayByTag(nwayArr(cfg, "outbounds"))[tag]
}

func alfaChainCatchAll(t *testing.T, cfg map[string]interface{}) map[string]interface{} {
	t.Helper()
	rules := nwayArr(nwayObj(cfg, "routing"), "rules")
	last := rules[len(rules)-1].(map[string]interface{})
	if !alfaRuleFromInbound(last, "socks-in") {
		t.Fatalf("last rule is not the apps' catch-all: %v", last)
	}
	return last
}

func alfaChainDialerOf(cfg map[string]interface{}, tag string) string {
	return nwayDialerOf(alfaChainByTag(cfg, tag))
}

// ---------------------------------------------------------------- case 1 of 4

func TestNeitherUpstreamNorChain(t *testing.T) {
	cfg := alfaChainRun(t, `{"aether":"aether://162.159.198.245:443?protocol=masque"}`)

	if got := strings.Join(alfaChainTags(cfg), ","); got != "aether,exit-node,direct,block,uplink" {
		t.Errorf("outbounds changed: %s", got)
	}
	if got := nwayStr(alfaChainCatchAll(t, cfg), "outboundTag"); got != "aether" {
		t.Errorf("catch-all should still be aether, got %q", got)
	}
	if _, ok := cfg["burstObservatory"]; ok {
		t.Error("no chain, so there should be no observatory")
	}
	if nwayArr(nwayObj(cfg, "routing"), "balancers") != nil {
		t.Error("no chain, so there should be no balancers")
	}
	if got := alfaChainDialerOf(cfg, "exit-node"); got != "uplink" {
		t.Errorf("exit-node lost its uplink: %q", got)
	}
}

// ---------------------------------------------------------------- case 2 of 4

func TestUpstreamOnly(t *testing.T) {
	blob, _ := json.Marshal(map[string]interface{}{
		"aether":   "aether://162.159.198.245:443?protocol=masque",
		"upstream": alfaChainTestUpstream,
	})
	cfg := alfaChainRun(t, string(blob))

	ex := alfaChainByTag(cfg, "exit-node")
	if ex == nil || nwayStr(ex, "protocol") != "vless" {
		t.Fatalf("exit-node was not replaced by the real server: %v", ex)
	}
	if got := nwayStr(alfaChainCatchAll(t, cfg), "outboundTag"); got != "aether" {
		t.Errorf("catch-all should still be aether, got %q", got)
	}
	if _, ok := cfg["burstObservatory"]; ok {
		t.Error("no chain, so there should be no observatory")
	}
	for _, tag := range alfaChainTags(cfg) {
		if strings.HasPrefix(tag, "chain") {
			t.Errorf("no chain asked for, yet %q is in the config", tag)
		}
	}
}

// ---------------------------------------------------------------- case 3 of 4

func TestChainOnly(t *testing.T) {
	blob := `{"aether":"aether://162.159.198.245:443?protocol=masque",
	          "chain_server":` + alfaChainTestList + `,"chain_server_latency":12}`
	cfg := alfaChainRun(t, blob)

	// the chain is there, head first, hops renamed out of the selector's reach
	if got := strings.Join(alfaChainTags(cfg), ","); got != "aether,exit-node,direct,block,uplink,chain-exit,chain-via-1" {
		t.Fatalf("unexpected outbounds: %s", got)
	}
	head := alfaChainByTag(cfg, "chain-exit")
	if nwayStr(head, "protocol") != "vless" {
		t.Errorf("chain-exit is not the server: %v", head)
	}
	// the head dials its own fragment leg, the fragment leg dials aether
	if got := alfaChainDialerOf(cfg, "chain-exit"); got != "chain-via-1" {
		t.Errorf("head should dial its hop, got %q", got)
	}
	if got := alfaChainDialerOf(cfg, "chain-via-1"); got != "aether" {
		t.Errorf("the LAST link must dial aether, got %q", got)
	}
	// the fragment's own settings are untouched
	frag := nwayObj(nwayObj(alfaChainByTag(cfg, "chain-via-1"), "settings"), "fragment")
	if nwayStr(frag, "packets") != "1-2" || nwayStr(frag, "length") != "10-100" ||
		nwayStr(frag, "interval") != "2-4" {
		t.Errorf("fragment settings were altered: %v", frag)
	}
	// the catch-all now goes to the balancer and ONLY to the balancer
	ca := alfaChainCatchAll(t, cfg)
	if _, ok := ca["outboundTag"]; ok {
		t.Errorf("catch-all still carries an outboundTag: %v", ca)
	}
	if got := nwayStr(ca, "balancerTag"); got != "chain-balancer" {
		t.Errorf("catch-all balancerTag is %q", got)
	}
	// connectivity is OFF by default, so no extra rule is added: the scaffold's 4
	rules := nwayArr(nwayObj(cfg, "routing"), "rules")
	if len(rules) != 4 {
		t.Fatalf("rule count: %d, want 4 (connectivity off by default adds none)", len(rules))
	}
	if nwayStr(rules[0].(map[string]interface{}), "outboundTag") != "exit-node" ||
		nwayStr(rules[1].(map[string]interface{}), "outboundTag") != "block" ||
		nwayStr(rules[2].(map[string]interface{}), "outboundTag") != "direct" {
		t.Error("the rules above the catch-all were disturbed")
	}
	// the balancer
	bal := nwayArr(nwayObj(cfg, "routing"), "balancers")
	if len(bal) != 1 {
		t.Fatalf("balancers: %v", bal)
	}
	b := bal[0].(map[string]interface{})
	if nwayStr(b, "tag") != "chain-balancer" || nwayStr(b, "fallbackTag") != "aether" {
		t.Errorf("balancer wrong: %v", b)
	}
	if nwayStr(nwayObj(b, "strategy"), "type") != "random" {
		t.Errorf("strategy wrong: %v", b["strategy"])
	}
	sel := b["selector"].([]interface{})
	if len(sel) != 1 || sel[0].(string) != "chain-exit" {
		t.Errorf("selector wrong: %v", sel)
	}
	// the selector is matched by PREFIX, so no other tag may start with it
	for _, tag := range alfaChainTags(cfg) {
		if tag != "chain-exit" && strings.HasPrefix(tag, "chain-exit") {
			t.Errorf("tag %q is caught by the selector too", tag)
		}
	}
	// the observatory, with the profile's own latency
	obs := nwayObj(cfg, "burstObservatory")
	if obs == nil {
		t.Fatal("no burstObservatory")
	}
	ss := obs["subjectSelector"].([]interface{})
	if len(ss) != 1 || ss[0].(string) != "chain-exit" {
		t.Errorf("subjectSelector wrong: %v", ss)
	}
	ping := nwayObj(obs, "pingConfig")
	if _, ok := ping["connectivity"]; ok {
		t.Error("connectivity must be OFF by default (no field) so failover stays reliable")
	}
	if nwayStr(ping, "timeout") != "12s" {
		t.Errorf("timeout should come from chain_server_latency, got %q", nwayStr(ping, "timeout"))
	}
	if nwayStr(ping, "interval") != "10s" {
		t.Errorf("interval wrong: %q", nwayStr(ping, "interval"))
	}
	// and aether itself is untouched, so the fallback still works
	if got := nwayStr(nwayObj(alfaChainByTag(cfg, "aether"), "settings"), "address"); got != "127.0.0.1" {
		t.Errorf("the aether outbound was disturbed: %q", got)
	}
}

// ---------------------------------------------------------------- case 4 of 4

func TestUpstreamAndChainTogether(t *testing.T) {
	blob := `{"aether":"aether://162.159.198.245:443?protocol=masque",
	          "upstream":"` + alfaChainTestUpstream + `",
	          "chain_server":` + alfaChainTestList + `}`
	cfg := alfaChainRun(t, blob)

	// upstream still took the exit-node slot
	ex := alfaChainByTag(cfg, "exit-node")
	if nwayStr(ex, "protocol") != "vless" {
		t.Fatalf("exit-node is not the upstream server: %v", ex)
	}
	// a link becomes the flat settings shape (address/port/id), as PattNG emits
	if addr := nwayStr(nwayObj(ex, "settings"), "address"); addr != "up.example.com" {
		t.Errorf("exit-node points at %q", addr)
	}
	// and the chain took its own
	ch := alfaChainByTag(cfg, "chain-exit")
	if addr := nwayStr(nwayArr(nwayObj(ch, "settings"), "vnext")[0].(map[string]interface{}), "address"); addr != "ch.example.com" {
		t.Errorf("chain-exit points at %q", addr)
	}
	// aether's own traffic still leaves by the exit node, not by the chain
	rules := nwayArr(nwayObj(cfg, "routing"), "rules")
	first := rules[0].(map[string]interface{})
	if !alfaRuleFromInbound(first, "aether-upstream") ||
		nwayStr(first, "outboundTag") != "exit-node" {
		t.Errorf("rule 0 disturbed: %v", first)
	}
	// no tag is claimed twice
	seen := map[string]bool{}
	for _, tag := range alfaChainTags(cfg) {
		if seen[tag] {
			t.Errorf("tag %q appears twice", tag)
		}
		seen[tag] = true
	}
	// the chain still ends at aether, not at the exit node
	if got := alfaChainDialerOf(cfg, "chain-via-1"); got != "aether" {
		t.Errorf("the chain must end at aether, got %q", got)
	}
}

// ------------------------------------------------------------------- the edges

func TestChainAsPlainLink(t *testing.T) {
	blob := `{"chain_server":"vless://33333333-3333-3333-3333-333333333333@ch2.example.com:443?encryption=none&security=none&type=tcp#NL"}`
	cfg := alfaChainRun(t, blob)
	if got := strings.Join(alfaChainTags(cfg), ","); got != "aether,exit-node,direct,block,uplink,chain-exit" {
		t.Fatalf("unexpected outbounds: %s", got)
	}
	// one link, no hops: the head itself is the last link and dials aether
	if got := alfaChainDialerOf(cfg, "chain-exit"); got != "aether" {
		t.Errorf("single-link chain must dial aether, got %q", got)
	}
}

func TestBlankChainChangesNothing(t *testing.T) {
	for _, blob := range []string{
		`{"chain_server":""}`,
		`{"chain_server":null}`,
		`{"chain_server":"   "}`,
		`{}`,
	} {
		cfg := alfaChainRun(t, blob)
		if _, ok := cfg["burstObservatory"]; ok {
			t.Errorf("%s produced an observatory", blob)
		}
		if got := nwayStr(alfaChainCatchAll(t, cfg), "outboundTag"); got != "aether" {
			t.Errorf("%s moved the catch-all to %q", blob, got)
		}
	}
}

func TestChainRefusedWhenScaffoldHasNoAether(t *testing.T) {
	broken := strings.Replace(alfaChainScaffold,
		`{"tag":"aether","protocol":"socks","settings":{"address":"127.0.0.1","port":10819}},`, "", 1)
	broken = strings.Replace(broken, `{"inboundTag":["socks-in"],"outboundTag":"aether"}`,
		`{"inboundTag":["socks-in"],"outboundTag":"direct"}`, 1)
	if _, err := alfaSplice(broken, `{"chain_server":`+alfaChainTestList+`}`, false); err == nil {
		t.Fatal("a alfaChainScaffold with no aether outbound must be refused, not patched around")
	}
}

func TestBadChainIsRefused(t *testing.T) {
	for _, blob := range []string{
		`{"chain_server":"not-a-link"}`,
		`{"chain_server":[]}`,
		`{"chain_server":{"no":"protocol"}}`,
		`{"chain_server":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.com","port":1,"users":[{"id":"x"}]}]},"streamSettings":{"sockopt":{"dialerProxy":"missing"}}}]}`,
	} {
		if _, err := alfaSplice(alfaChainScaffold, blob, false); err == nil {
			t.Errorf("%s should have been refused", blob)
		}
	}
}

func TestLatencyFallsBackToDefault(t *testing.T) {
	for _, blob := range []string{
		`{"chain_server":` + alfaChainTestList + `}`,
		`{"chain_server":` + alfaChainTestList + `,"chain_server_latency":0}`,
		`{"chain_server":` + alfaChainTestList + `,"chain_server_latency":"nonsense"}`,
	} {
		cfg := alfaChainRun(t, blob)
		ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
		if got := nwayStr(ping, "timeout"); got != "8s" {
			t.Errorf("%s gave timeout %q, want 8s", blob, got)
		}
	}
	cfg := alfaChainRun(t, `{"chain_server":`+alfaChainTestList+`,"chain_server_latency":"15"}`)
	if got := nwayStr(nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig"), "timeout"); got != "15s" {
		t.Errorf("a numeric string latency gave %q", got)
	}
}

func TestSplitStillWinsOverTheChain(t *testing.T) {
	blob := `{"chain_server":` + alfaChainTestList + `,
	          "split_server":"` + alfaChainTestUpstream + `",
	          "split_domains":["domain:ir"]}`
	cfg := alfaChainRun(t, blob)
	rules := nwayArr(nwayObj(cfg, "routing"), "rules")
	// the split rule must sit ABOVE the catch-all, so its domains never reach
	// the chain
	splitAt, caAt := -1, -1
	for i, r := range rules {
		rule := r.(map[string]interface{})
		if nwayStr(rule, "outboundTag") == "split" {
			splitAt = i
		}
		if nwayStr(rule, "balancerTag") == "chain-balancer" {
			caAt = i
		}
	}
	if splitAt < 0 || caAt < 0 || splitAt > caAt {
		t.Fatalf("split at %d, catch-all at %d", splitAt, caAt)
	}
	// and the split server dials out on its own, not through the chain
	if got := alfaChainDialerOf(cfg, "split"); got == "chain-exit" {
		t.Errorf("split must not ride the chain")
	}
}

// ------------------------------------- the uplink the splice used to lose

func TestUpstreamKeepsTheUplink(t *testing.T) {
	blob, _ := json.Marshal(map[string]interface{}{"upstream": alfaChainTestUpstream})
	cfg := alfaChainRun(t, string(blob))
	if got := alfaChainDialerOf(cfg, "exit-node"); got != "uplink" {
		t.Errorf("the real exit node dials from an unprotected socket: dialerProxy=%q", got)
	}
}

func TestSplitServerGetsTheUplink(t *testing.T) {
	blob := `{"split_server":"` + alfaChainTestUpstream + `","split_domains":["domain:ir"]}`
	cfg := alfaChainRun(t, blob)
	if got := alfaChainDialerOf(cfg, "split"); got != "uplink" {
		t.Errorf("the split server dials from an unprotected socket: dialerProxy=%q", got)
	}
}

func TestChainDoesNotTakeTheUplink(t *testing.T) {
	cfg := alfaChainRun(t, `{"chain_server":`+alfaChainTestList+`}`)
	// the chain's socket is opened by aether, whose egress is protected already
	if got := alfaChainDialerOf(cfg, "chain-via-1"); got != "aether" {
		t.Errorf("the chain's last link should dial aether, got %q", got)
	}
	if got := alfaChainDialerOf(cfg, "chain-exit"); got != "chain-via-1" {
		t.Errorf("the chain head should dial its hop, got %q", got)
	}
}

func TestEverythingTogetherKeepsItsOwnEgress(t *testing.T) {
	blob := `{"upstream":"` + alfaChainTestUpstream + `",
	          "split_server":"` + alfaChainTestUpstream + `","split_domains":["domain:ir"],
	          "chain_server":` + alfaChainTestList + `}`
	cfg := alfaChainRun(t, blob)
	for tag, want := range map[string]string{
		"exit-node":   "uplink",
		"split":       "uplink",
		"direct":      "uplink",
		"chain-via-1": "aether",
		"chain-exit":  "chain-via-1",
		"aether":      "",
		"uplink":      "",
	} {
		if got := alfaChainDialerOf(cfg, tag); got != want {
			t.Errorf("%s dials %q, want %q", tag, got, want)
		}
	}
}

func TestNoUplinkInScaffoldIsANoOp(t *testing.T) {
	plain := strings.Replace(alfaChainScaffold,
		`,
    {"tag":"uplink","protocol":"socks","settings":{"address":"127.0.0.1","port":41234}}`, "", 1)
	plain = strings.ReplaceAll(plain, `,
     "streamSettings":{"sockopt":{"dialerProxy":"uplink"}}`, "")
	out, err := alfaSplice(plain, `{"upstream":"`+alfaChainTestUpstream+`","chain_server":`+alfaChainTestList+`}`, false)
	if err != nil {
		t.Fatalf("alfaSplice: %v", err)
	}
	var cfg map[string]interface{}
	json.Unmarshal([]byte(out), &cfg)
	if got := alfaChainDialerOf(cfg, "exit-node"); got != "" {
		t.Errorf("no uplink in the alfaChainScaffold, yet exit-node got %q", got)
	}
	if got := alfaChainDialerOf(cfg, "chain-via-1"); got != "aether" {
		t.Errorf("the chain must still reach aether, got %q", got)
	}
}

// ------------------------- the connectivity check that closes the window

func TestConnectivityIsPinnedToAether(t *testing.T) {
	// opt in with an IP, the recommended form: pinned to aether by an "ip" rule,
	// so the check needs no DNS and never rides the chain.
	blob := `{"chain_server":` + alfaChainTestList + `,"chain_probe_connectivity":"http://1.1.1.1/generate_204"}`
	cfg := alfaChainRun(t, blob)

	ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
	if got := nwayStr(ping, "connectivity"); got != "http://1.1.1.1/generate_204" {
		t.Fatalf("connectivity url is %q", got)
	}

	rules := nwayArr(nwayObj(cfg, "routing"), "rules")
	pinAt, caAt := -1, -1
	for i, r := range rules {
		rule := r.(map[string]interface{})
		if ips, ok := rule["ip"].([]interface{}); ok {
			for _, ip := range ips {
				if ip.(string) == "1.1.1.1" {
					pinAt = i
					if got := nwayStr(rule, "outboundTag"); got != "aether" {
						t.Errorf("the connectivity check goes to %q, not aether", got)
					}
					if !alfaRuleFromInbound(rule, "socks-in") {
						t.Error("the connectivity rule is not scoped to the apps' inbound")
					}
				}
			}
		}
		if nwayStr(rule, "balancerTag") == "chain-balancer" {
			caAt = i
		}
	}
	if pinAt < 0 {
		t.Fatal("no IP rule pins the connectivity check to aether")
	}
	if pinAt > caAt {
		t.Errorf("connectivity rule at %d is below the catch-all at %d", pinAt, caAt)
	}
	// and no DNS-dependent domain rule was used for an IP
	for _, r := range rules {
		rule := r.(map[string]interface{})
		if nwayStr(rule, "outboundTag") == "aether" && rule["domain"] != nil {
			t.Errorf("an IP connectivity must not produce a domain rule: %v", rule)
		}
	}
}

func TestNoConnectivityRuleWithoutAChain(t *testing.T) {
	cfg := alfaChainRun(t, `{"upstream":"`+alfaChainTestUpstream+`"}`)
	for _, r := range nwayArr(nwayObj(cfg, "routing"), "rules") {
		rule := r.(map[string]interface{})
		if doms, ok := rule["domain"].([]interface{}); ok {
			for _, d := range doms {
				if strings.Contains(d.(string), "cp.cloudflare.com") {
					t.Error("no chain asked for, yet a connectivity rule was added")
				}
			}
		}
	}
}

// ------------------------------ both probe addresses come from the backend

func TestProbeAddressesFromTheBlob(t *testing.T) {
	blob := `{"chain_server":` + alfaChainTestList + `,
	          "chain_probe_url":"https://probe.example.net/204",
	          "chain_probe_connectivity":"http://up.example.net/204"}`
	cfg := alfaChainRun(t, blob)

	ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
	if got := nwayStr(ping, "destination"); got != "https://probe.example.net/204" {
		t.Errorf("destination is %q", got)
	}
	if got := nwayStr(ping, "connectivity"); got != "http://up.example.net/204" {
		t.Errorf("connectivity is %q", got)
	}
	// the pin rule must have FOLLOWED the new address
	found := ""
	for _, r := range nwayArr(nwayObj(cfg, "routing"), "rules") {
		rule := r.(map[string]interface{})
		if nwayStr(rule, "outboundTag") != "aether" {
			continue
		}
		if doms, ok := rule["domain"].([]interface{}); ok && len(doms) == 1 {
			found = doms[0].(string)
		}
	}
	if found != "full:up.example.net" {
		t.Errorf("the pin rule still points at %q", found)
	}
}

func TestEmptyConnectivityTurnsItOff(t *testing.T) {
	blob := `{"chain_server":` + alfaChainTestList + `,"chain_probe_connectivity":""}`
	cfg := alfaChainRun(t, blob)

	ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
	if _, ok := ping["connectivity"]; ok {
		t.Error("an empty connectivity should turn the check off, not set it")
	}
	// and then no rule may pin anything to aether, or it would pin nothing
	for _, r := range nwayArr(nwayObj(cfg, "routing"), "rules") {
		rule := r.(map[string]interface{})
		if nwayStr(rule, "outboundTag") == "aether" && rule["domain"] != nil {
			t.Errorf("a pin rule was added with no connectivity check: %v", rule)
		}
	}
	// the chain itself is unaffected
	if nwayStr(alfaChainCatchAll(t, cfg), "balancerTag") != "chain-balancer" {
		t.Error("the chain stopped working")
	}
}

func TestUnusableConnectivityIsDroppedNotGuessed(t *testing.T) {
	for _, bad := range []string{"not a url", "://", "http://", "   "} {
		blob, _ := json.Marshal(map[string]interface{}{
			"chain_server":             json.RawMessage(alfaChainTestList),
			"chain_probe_connectivity": bad,
		})
		cfg := alfaChainRun(t, string(blob))
		ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
		if _, ok := ping["connectivity"]; ok {
			t.Errorf("%q was accepted as a connectivity address", bad)
		}
		for _, r := range nwayArr(nwayObj(cfg, "routing"), "rules") {
			rule := r.(map[string]interface{})
			if nwayStr(rule, "outboundTag") == "aether" && rule["domain"] != nil {
				t.Errorf("%q produced a pin rule anyway: %v", bad, rule)
			}
		}
		// and the chain still works, just stricter at startup
		if nwayStr(alfaChainCatchAll(t, cfg), "balancerTag") != "chain-balancer" {
			t.Errorf("%q broke the chain", bad)
		}
	}
}

func TestBlankProbeUrlKeepsTheDefault(t *testing.T) {
	cfg := alfaChainRun(t, `{"chain_server":`+alfaChainTestList+`,"chain_probe_url":"  "}`)
	ping := nwayObj(nwayObj(cfg, "burstObservatory"), "pingConfig")
	if got := nwayStr(ping, "destination"); got != "https://www.gstatic.com/generate_204" {
		t.Errorf("destination is %q", got)
	}
}
