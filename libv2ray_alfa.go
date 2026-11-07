package libv2ray

// -----------------------------------------------------------------------------
// libv2ray_alfa.go
//
// Phase B secure start path for ALFA mode. The ALFA server config travels DOWN
// ENCRYPTED and its secrets must reach the Xray core WITHOUT ever existing as a
// Java String. aether (libaether.so) already opens the same encrypted blob for
// its own fields; THIS file opens it for the Xray-side secrets:
//
//     upstream       -> the exit-node outbound (aether's handshake egress)
//     split_server   -> the split outbound, with split_domains / split_ips
//     register_upstream -> the key-server, for the throwaway openExit
//
// Java builds only the NON-SECRET ALFA scaffold (the fixed inbounds, the aether
// / direct / block outbounds, a freedom exit-node placeholder and the routing
// skeleton). This file:
//
//   1. decrypts the blob through libEncryption.so (reusing nwayDecrypt from
//      libv2ray_nway.go - so `ak` never leaves C++ and the plaintext never
//      touches Java);
//   2. turns each secret (a share link OR an outbound/whole-config JSON object)
//      into an Xray outbound chain IN GO - a faithful 1:1 port of the module's
//      ConfigParser (vless / vmess / trojan / ss / socks + streamSettings) and
//      XrayConfigFactory.chainAs;
//   3. splices those chains into the scaffold by tag, and builds the split rule
//      from split_domains / split_ips, exactly where XrayConfigFactory.routing
//      puts it (after block, before bypass);
//   4. hands the result to the SAME doStartLoop the normal StartLoop uses.
//
// Nothing here modifies StartLoop, libv2ray_nway.go, or any existing file. It
// is purely additive and has no cgo of its own; the decrypt bridge lives in
// libv2ray_nway.go and is reused through nwayDecrypt.
//
// Crash policy: every failure returns an error (never panics). The caller
// already wraps the start in try/catch and falls back.
// -----------------------------------------------------------------------------

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
)

// Tags, kept in sync with XrayConfigFactory. (nwaySocksPort / nwayLoopback /
// nwaySocksInTag / nwayTagUplink / nwayMaxChain live in libv2ray_nway.go.)
const (
	alfaTagExitNode = "exit-node" // XrayConfigFactory.TAG_EXIT_NODE
	alfaTagSplit    = "split"     // XrayConfigFactory.TAG_SPLIT
	alfaTagBlock    = "block"     // XrayConfigFactory.TAG_BLOCK
	alfaLogLevel    = "warning"   // AlfaSettings.XRAY_LOG_LEVEL
)

// =============================================================================
// Bound entry points
// =============================================================================

// StartLoopSecureAlfa is the encrypted twin of StartLoop for ALFA mode.
//
//	scaffold    the NON-SECRET ALFA Xray JSON Java built (XrayConfigFactory,
//	            with an empty AlfaOptions): fixed inbounds, aether/direct/block
//	            outbounds, a freedom exit-node placeholder, routing skeleton.
//	encConfig   the GCM envelope exactly as the server sent it (base64) - the
//	            SAME blob aether is given.
//	filesDir    context.getFilesDir().getAbsolutePath()  (NOT secret)
//	uuid        ANDROID_ID                                (NOT secret)
//	enableStats whether to inject the traffic-stats policy
//	uplinkPort  the service's live AlfaUplink loopback port, or <=0 for none.
//	tunFd       0 here, same as StartLoop.
//
// The plaintext config lives only inside this Go call; it is never returned to
// Java and `ak` is never seen outside libEncryption.
func (x *CoreController) StartLoopSecureAlfa(scaffold string, encConfig string, filesDir string, uuid string, enableStats bool, uplinkPort int32, tunFd int32) error {
	plain := nwayDecrypt(encConfig, filesDir, uuid)
	if plain == "" {
		return errors.New("alfa: decrypt failed")
	}

	full, err := alfaSplice(scaffold, plain, enableStats)
	if err != nil {
		return fmt.Errorf("alfa: splice failed: %w", err)
	}

	if uplinkPort > 0 {
		rewritten, applied := nwayWithUplink(full, int(uplinkPort))
		if !applied {
			// Refuse rather than run with egress unprotected - same choice the
			// service makes, kept here so the plaintext never leaves native.
			return errors.New("alfa: uplink could not be applied")
		}
		full = rewritten
	}

	setEnvVariable(tunFdKey, strconv.Itoa(int(tunFd)))

	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if x.IsRunning {
		log.Println("Core is already running")
		return nil
	}
	return x.doStartLoop(full)
}

// OpenExitSecure is the encrypted twin of OpenExit for the ALFA key-server.
//
// It decrypts the same blob, reads register_upstream, turns it into the exit
// outbound chain IN GO (tagged "exit-node", as forExitOnly does), wraps it in a
// no-inbound config and hands it to the existing OpenExit. Java only ever gets
// back the port; the key-server address never reaches it.
//
// register_fingerprint is deliberately NOT read here: it is an aether concern
// (AetherExecutor maps it to --tls-ciphers), not an Xray one.
func OpenExitSecure(encConfig string, filesDir string, uuid string) (int64, error) {
	plain := nwayDecrypt(encConfig, filesDir, uuid)
	if plain == "" {
		return -1, errors.New("alfa: decrypt failed")
	}

	var alfa map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(plain)), &alfa); err != nil {
		return -1, fmt.Errorf("alfa: bad config json: %w", err)
	}

	server, ok := alfa["register_upstream"]
	if !ok || alfaIsBlank(server) {
		return -1, errors.New("alfa: no register_upstream in config")
	}

	chain, err := alfaOutboundChain(server)
	if err != nil {
		return -1, fmt.Errorf("alfa: register_upstream: %w", err)
	}
	alfaChainAs(alfaTagExitNode, chain)

	root := map[string]interface{}{
		"log":       map[string]interface{}{"loglevel": alfaLogLevel},
		"inbounds":  []interface{}{}, // deliberately empty; openExit's contract
		"outbounds": alfaToIface(chain),
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules":          []interface{}{},
		},
	}
	out, err := json.Marshal(root)
	if err != nil {
		return -1, err
	}
	return OpenExit(string(out))
}

// =============================================================================
// Splice: put the decrypted secrets into the Java scaffold
// =============================================================================

// alfaSplice parses the scaffold fresh, replaces the exit-node placeholder with
// the real upstream, adds the split outbound + rule when present, applies the
// stats policy, and returns the final runnable Xray JSON.
func alfaSplice(scaffold string, plain string, enableStats bool) (string, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(scaffold)), &cfg); err != nil {
		return "", fmt.Errorf("bad scaffold json: %w", err)
	}
	var alfa map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(plain)), &alfa); err != nil {
		return "", fmt.Errorf("bad config json: %w", err)
	}

	outs := nwayArr(cfg, "outbounds")
	if outs == nil {
		return "", errors.New("scaffold has no outbounds")
	}

	// ---- exit node (field "upstream") -------------------------------------
	if v, ok := alfa["upstream"]; ok && !alfaIsBlank(v) {
		chain, err := alfaOutboundChain(v)
		if err != nil {
			return "", fmt.Errorf("upstream: %w", err)
		}
		alfaChainAs(alfaTagExitNode, chain)
		outs, err = alfaReplaceByTag(outs, alfaTagExitNode, chain)
		if err != nil {
			return "", err
		}
	}
	// (upstream absent/blank: leave the scaffold's freedom exit-node as-is.)

	// ---- split (server + domains + ips) -----------------------------------
	splitServer, hasServer := alfa["split_server"]
	domains := alfaList(alfa["split_domains"])
	ips := alfaList(alfa["split_ips"])
	if hasServer && !alfaIsBlank(splitServer) && (len(domains) > 0 || len(ips) > 0) {
		schain, err := alfaOutboundChain(splitServer)
		if err != nil {
			return "", fmt.Errorf("split_server: %w", err)
		}
		alfaChainAs(alfaTagSplit, schain)
		outs = append(outs, alfaToIface(schain)...)

		rules, err := alfaInsertSplitRule(cfg, domains, ips)
		if err != nil {
			return "", err
		}
		if routing := nwayObj(cfg, "routing"); routing != nil {
			routing["rules"] = rules
		}
	}

	cfg["outbounds"] = outs
	nwayApplyStats(cfg, enableStats)

	out, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// alfaReplaceByTag replaces the single outbound tagged `tag` with `chain`
// (head first), keeping the chain where the placeholder was so the first
// outbound - the default - is never displaced.
func alfaReplaceByTag(outs []interface{}, tag string, chain []map[string]interface{}) ([]interface{}, error) {
	idx := -1
	for i, o := range outs {
		if obj, ok := o.(map[string]interface{}); ok && nwayStr(obj, "tag") == tag {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("scaffold has no outbound tagged %q to replace", tag)
	}
	next := make([]interface{}, 0, len(outs)+len(chain)-1)
	next = append(next, outs[:idx]...)
	next = append(next, alfaToIface(chain)...)
	next = append(next, outs[idx+1:]...)
	return next, nil
}

// alfaInsertSplitRule mirrors XrayConfigFactory.listRule + routingRules: a rule
// scoped to the apps' inbound (socks-in) that sends split_domains / split_ips
// to the split outbound, placed AFTER the block rule (or right after the fixed
// aether-upstream rule at index 0 when there is no block rule), i.e. above the
// bypass list - exactly as routingRules orders it.
func alfaInsertSplitRule(cfg map[string]interface{}, domains, ips []string) ([]interface{}, error) {
	routing := nwayObj(cfg, "routing")
	if routing == nil {
		return nil, errors.New("scaffold has no routing")
	}
	rules := nwayArr(routing, "rules")
	if rules == nil {
		rules = []interface{}{}
	}

	rule := map[string]interface{}{
		"inboundTag": []interface{}{nwaySocksInTag},
	}
	if len(domains) > 0 {
		rule["domain"] = alfaStrIface(domains)
	}
	if len(ips) > 0 {
		rule["ip"] = alfaStrIface(ips)
	}
	rule["outboundTag"] = alfaTagSplit

	// Position: right after the block rule if there is one, else right after
	// the aether-upstream rule at index 0.
	insertAt := 1
	for i, r := range rules {
		if obj, ok := r.(map[string]interface{}); ok && nwayStr(obj, "outboundTag") == alfaTagBlock {
			insertAt = i + 1
			break
		}
	}
	if insertAt > len(rules) {
		insertAt = len(rules)
	}
	next := make([]interface{}, 0, len(rules)+1)
	next = append(next, rules[:insertAt]...)
	next = append(next, rule)
	next = append(next, rules[insertAt:]...)
	return next, nil
}

// alfaChainAs mirrors XrayConfigFactory.chainAs + renameHops: retag the head,
// rename each hop "<head>-hop-<i>" and repoint the dialerProxy of the one that
// dialled through it. The head's own dialerProxy (pointing at the first hop's
// old tag) is repointed by the i=1 step.
func alfaChainAs(headTag string, chain []map[string]interface{}) {
	if len(chain) == 0 {
		return
	}
	chain[0]["tag"] = headTag
	for i := 1; i < len(chain); i++ {
		fresh := headTag + "-hop-" + strconv.Itoa(i)
		chain[i]["tag"] = fresh
		nwaySetDialer(chain[i-1], fresh)
	}
}

// =============================================================================
// ConfigParser port: a secret value (link OR JSON) -> an outbound chain
// =============================================================================

// alfaOutboundChain accepts what the backend put in upstream / split_server /
// register_upstream: a share-link string, a stringified JSON, or an already
// parsed JSON object (a single outbound, or a whole config). It returns the
// outbound chain, head first - the head is the server, the rest are the hops
// its dialerProxy chain needs.
func alfaOutboundChain(v interface{}) ([]map[string]interface{}, error) {
	switch val := v.(type) {
	case string:
		return alfaChainFromString(val)
	case map[string]interface{}:
		return alfaChainFromObject(val)
	default:
		return nil, errors.New("value is neither a link/JSON string nor an object")
	}
}

func alfaChainFromString(raw string) ([]map[string]interface{}, error) {
	t := alfaNormalize(raw)
	if t == "" {
		return nil, errors.New("nothing to read")
	}
	if alfaLooksLikeLink(t) {
		head, err := alfaToOutbound(t)
		if err != nil {
			return nil, err
		}
		return []map[string]interface{}{head}, nil
	}
	if !strings.HasPrefix(t, "{") {
		return nil, errors.New("not a share link and not JSON: expected" +
			" vless://, trojan://, vmess://, ss://, socks5:// or a { … } config")
	}
	var o map[string]interface{}
	if err := json.Unmarshal([]byte(t), &o); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	return alfaChainFromObject(o)
}

func alfaChainFromObject(o map[string]interface{}) ([]map[string]interface{}, error) {
	// A whole config: pick the proxy outbound and follow its dialerProxy chain
	// through the config's own outbounds.
	if outs := nwayArr(o, "outbounds"); outs != nil {
		head, err := alfaProxyOutboundOf(outs)
		if err != nil {
			return nil, err
		}
		return alfaFollowChain(head, outs)
	}
	// A single outbound object.
	if _, ok := o["protocol"]; ok {
		return []map[string]interface{}{o}, nil
	}
	return nil, errors.New("this JSON is neither a config (no \"outbounds\")" +
		" nor a single outbound (no \"protocol\")")
}

// alfaFollowChain mirrors ConfigParser.outboundChainFrom's walk: from head,
// follow sockopt.dialerProxy to each hop in outs, head first, refusing a
// missing tag, a loop, or a chain longer than nwayMaxChain.
func alfaFollowChain(head map[string]interface{}, outs []interface{}) ([]map[string]interface{}, error) {
	chain := []map[string]interface{}{head}
	at := head
	seen := map[string]bool{}
	for hop := 0; hop < nwayMaxChain; hop++ {
		next := nwayDialerOf(at)
		if next == "" {
			return chain, nil
		}
		if seen[next] {
			return nil, fmt.Errorf("dialerProxy chain loops at %q", next)
		}
		seen[next] = true
		var to map[string]interface{}
		for _, e := range outs {
			if ob, ok := e.(map[string]interface{}); ok && nwayStr(ob, "tag") == next {
				to = ob
				break
			}
		}
		if to == nil {
			return nil, fmt.Errorf("outbound dials through %q, which is not an outbound in it", next)
		}
		chain = append(chain, to)
		at = to
	}
	return nil, fmt.Errorf("dialerProxy chain is longer than %d hops", nwayMaxChain)
}

// alfaProxyOutboundOf mirrors ConfigParser.proxyOutboundOf: the outbound tagged
// "proxy" among those that carry traffic, else the first that carries traffic.
func alfaProxyOutboundOf(outs []interface{}) (map[string]interface{}, error) {
	var firstReal, taggedProxy map[string]interface{}
	for _, e := range outs {
		ob, ok := e.(map[string]interface{})
		if !ok || !alfaCarriesTraffic(ob) {
			continue
		}
		if taggedProxy == nil && nwayStr(ob, "tag") == "proxy" {
			taggedProxy = ob
		}
		if firstReal == nil {
			firstReal = ob
		}
	}
	if taggedProxy != nil {
		return taggedProxy, nil
	}
	if firstReal != nil {
		return firstReal, nil
	}
	return nil, errors.New("this config has no outbound that goes anywhere - only freedom/blackhole legs")
}

func alfaCarriesTraffic(ob map[string]interface{}) bool {
	p := nwayStr(ob, "protocol")
	return p != "freedom" && p != "blackhole" && p != "dns" && p != "loopback"
}

// =============================================================================
// ConfigParser port: share link -> outbound object
// =============================================================================

func alfaLooksLikeLink(s string) bool { return alfaScheme(s) != "" }

func alfaScheme(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	sep := strings.Index(t, "://")
	if sep <= 0 {
		return ""
	}
	switch t[:sep] {
	case "vless", "trojan", "vmess", "ss", "socks", "http", "https", "hysteria2", "hy2":
		return t[:sep]
	case "socks5", "socks5h":
		return "socks"
	default:
		return ""
	}
}

func alfaToOutbound(link string) (map[string]interface{}, error) {
	raw := strings.TrimSpace(link)
	switch alfaScheme(raw) {
	case "hysteria2", "hy2":
		return nil, errors.New("hysteria2 links are not built in secure mode;" +
			" send the outbound object instead")
	case "vless":
		return alfaVless(raw)
	case "trojan":
		return alfaTrojan(raw)
	case "vmess":
		return alfaVmess(raw)
	case "ss":
		return alfaShadowsocks(raw)
	case "socks":
		return alfaSocksOrHttp(raw, "socks")
	case "http", "https":
		return alfaSocksOrHttp(raw, "http")
	default:
		return nil, errors.New("not a share link this module reads: expected" +
			" vless://, trojan://, vmess://, ss://, socks5:// or hysteria2://")
	}
}

func alfaVless(raw string) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a usable link: %w", err)
	}
	host, port, err := alfaHostPortURI(u)
	if err != nil {
		return nil, err
	}
	q := alfaQuery(u.RawQuery)
	id := ""
	if u.User != nil {
		id = u.User.Username()
	}
	if id == "" {
		return nil, errors.New("the vless link has no uuid before the @")
	}
	settings := map[string]interface{}{"address": host, "port": port, "id": id}
	enc := q["encryption"]
	if enc == "" {
		enc = "none"
	}
	settings["encryption"] = enc
	alfaPutIf(settings, "flow", q["flow"])

	ss, err := alfaStream(q, host, "")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"protocol": "vless", "settings": settings, "streamSettings": ss}, nil
}

func alfaTrojan(raw string) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a usable link: %w", err)
	}
	host, port, err := alfaHostPortURI(u)
	if err != nil {
		return nil, err
	}
	q := alfaQuery(u.RawQuery)
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
	}
	if pw == "" {
		return nil, errors.New("the trojan link has no password before the @")
	}
	settings := map[string]interface{}{"address": host, "port": port, "password": pw}
	alfaPutIf(settings, "flow", q["flow"])

	ss, err := alfaStream(q, host, "tls") // trojan is TLS by definition
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"protocol": "trojan", "settings": settings, "streamSettings": ss}, nil
}

func alfaVmess(raw string) (map[string]interface{}, error) {
	body := raw[len("vmess://"):]
	if !strings.Contains(body, "@") {
		return alfaVmessBase64(body)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a usable link: %w", err)
	}
	host, port, err := alfaHostPortURI(u)
	if err != nil {
		return nil, err
	}
	q := alfaQuery(u.RawQuery)
	id := ""
	if u.User != nil {
		id = u.User.Username()
	}
	if id == "" {
		return nil, errors.New("the vmess link has no uuid before the @")
	}
	scy := q["encryption"]
	if scy == "" {
		scy = "auto"
	}
	settings := map[string]interface{}{"address": host, "port": port, "id": id, "security": scy}
	ss, err := alfaStream(q, host, "")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"protocol": "vmess", "settings": settings, "streamSettings": ss}, nil
}

func alfaVmessBase64(body string) (map[string]interface{}, error) {
	if h := strings.IndexByte(body, '#'); h >= 0 {
		body = body[:h]
	}
	decoded, err := alfaDecodeBase64(body)
	if err != nil {
		return nil, errors.New("the vmess link is neither base64 nor a uuid@host link")
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("the vmess link's base64 is not JSON: %w", err)
	}
	host := alfaVStr(v, "add")
	if host == "" {
		return nil, errors.New("the vmess link has no \"add\" (server address)")
	}
	port := alfaParseInt(alfaVStr(v, "port"))
	if port < 0 {
		return nil, errors.New("the vmess link has no usable \"port\"")
	}
	id := alfaVStr(v, "id")
	if id == "" {
		return nil, errors.New("the vmess link has no \"id\" (uuid)")
	}
	q := map[string]string{}
	alfaPutNonEmpty(q, "type", alfaVStr(v, "net"))
	alfaPutNonEmpty(q, "headerType", alfaVStr(v, "type"))
	alfaPutNonEmpty(q, "host", alfaVStr(v, "host"))
	alfaPutNonEmpty(q, "path", alfaVStr(v, "path"))
	alfaPutNonEmpty(q, "security", alfaVStr(v, "tls"))
	alfaPutNonEmpty(q, "sni", alfaVStr(v, "sni"))
	alfaPutNonEmpty(q, "alpn", alfaVStr(v, "alpn"))
	alfaPutNonEmpty(q, "fp", alfaVStr(v, "fp"))
	alfaPutNonEmpty(q, "serviceName", alfaVStr(v, "path"))
	alfaPutNonEmpty(q, "mode", alfaVStr(v, "mode"))

	scy := alfaVStr(v, "scy")
	if scy == "" {
		scy = "auto"
	}
	settings := map[string]interface{}{"address": host, "port": port, "id": id, "security": scy}
	ss, err := alfaStream(q, host, "")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"protocol": "vmess", "settings": settings, "streamSettings": ss}, nil
}

func alfaShadowsocks(raw string) (map[string]interface{}, error) {
	body := raw[len("ss://"):]
	if h := strings.IndexByte(body, '#'); h >= 0 {
		body = body[:h]
	}
	var queryText string
	if qm := strings.IndexByte(body, '?'); qm >= 0 {
		queryText = body[qm+1:]
		body = body[:qm]
	}
	q := alfaQuery(queryText)
	if _, ok := q["plugin"]; ok {
		return nil, fmt.Errorf("this ss link uses a plugin (%s), which needs a"+
			" separate binary this app does not ship", q["plugin"])
	}

	var method, password, host string
	var port int
	if at := strings.LastIndexByte(body, '@'); at < 0 {
		// Legacy: whole thing is base64 of method:password@host:port.
		decoded, err := alfaDecodeBase64(body)
		if err != nil {
			return nil, errors.New("the ss link is not base64 and has no @")
		}
		at = strings.LastIndexByte(decoded, '@')
		if at < 0 {
			return nil, errors.New("the ss link has no @ even after base64 decoding")
		}
		mp := alfaSplitFirst(decoded[:at], ':')
		if mp == nil {
			return nil, errors.New("the ss link has no method:password")
		}
		method, password = mp[0], mp[1]
		h, p, err := alfaHostPortStr(decoded[at+1:])
		if err != nil {
			return nil, err
		}
		host, port = h, p
	} else {
		userInfo := body[:at]
		mp := alfaSplitFirst(userInfo, ':')
		if mp == nil {
			// SIP002: user info is base64 of method:password.
			decoded, err := alfaDecodeBase64(userInfo)
			if err != nil {
				return nil, errors.New("the ss link's user info is neither base64 nor method:password")
			}
			mp = alfaSplitFirst(decoded, ':')
			if mp == nil {
				return nil, errors.New("the ss link has no method:password")
			}
		} else {
			mp = []string{alfaDecode(mp[0]), alfaDecode(mp[1])}
		}
		method, password = mp[0], mp[1]
		h, p, err := alfaHostPortStr(body[at+1:])
		if err != nil {
			return nil, err
		}
		host, port = h, p
	}

	settings := map[string]interface{}{"address": host, "port": port, "method": method, "password": password}
	ss, err := alfaStream(q, host, "")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"protocol": "shadowsocks", "settings": settings, "streamSettings": ss}, nil
}

func alfaSocksOrHttp(raw, protocol string) (map[string]interface{}, error) {
	body := raw[strings.Index(raw, "://")+3:]
	if h := strings.IndexByte(body, '#'); h >= 0 {
		body = body[:h]
	}
	var queryText string
	if qm := strings.IndexByte(body, '?'); qm >= 0 {
		queryText = body[qm+1:]
		body = body[:qm]
	}
	q := alfaQuery(queryText)

	var user, pass string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userInfo := body[:at]
		up := alfaSplitFirst(userInfo, ':')
		if up == nil {
			if decoded, err := alfaDecodeBase64(userInfo); err == nil {
				up = alfaSplitFirst(decoded, ':')
			}
		}
		if up != nil {
			user = alfaDecode(up[0])
			pass = alfaDecode(up[1])
		}
		body = body[at+1:]
	}
	host, port, err := alfaHostPortStr(body)
	if err != nil {
		return nil, err
	}

	settings := map[string]interface{}{"address": host, "port": port}
	if user != "" {
		settings["user"] = user
		settings["pass"] = pass
	}
	out := map[string]interface{}{"protocol": protocol, "settings": settings}
	if strings.EqualFold(q["security"], "tls") {
		ss, err := alfaStream(q, host, "tls")
		if err != nil {
			return nil, err
		}
		out["streamSettings"] = ss
	}
	return out, nil
}

// =============================================================================
// ConfigParser port: streamSettings
// =============================================================================

func alfaStream(q map[string]string, server, defaultSecurity string) (map[string]interface{}, error) {
	network := q["type"]
	if network == "" {
		network = "tcp"
	}
	host := q["host"]
	path := q["path"]
	headerType := q["headerType"]

	ss := map[string]interface{}{}
	sniHint := ""

	switch network {
	case "tcp":
		header := map[string]interface{}{}
		if headerType == "http" {
			header["type"] = "http"
			headers := map[string]interface{}{}
			if host != "" {
				hostList := alfaSplitList(host)
				headers["Host"] = hostList
				if len(hostList) > 0 {
					sniHint, _ = hostList[0].(string)
				}
			}
			request := map[string]interface{}{}
			p := path
			if p == "" {
				p = "/"
			}
			request["path"] = []interface{}{p}
			request["headers"] = headers
			header["request"] = request
		} else {
			header["type"] = "none"
			sniHint = host
		}
		ss["network"] = "tcp"
		ss["tcpSettings"] = map[string]interface{}{"header": header}
	case "ws", "httpupgrade":
		p := path
		if p == "" {
			p = "/"
		}
		s := map[string]interface{}{"host": host, "path": p}
		sniHint = host
		ss["network"] = network
		if network == "ws" {
			ss["wsSettings"] = s
		} else {
			ss["httpupgradeSettings"] = s
		}
	case "xhttp":
		p := path
		if p == "" {
			p = "/"
		}
		s := map[string]interface{}{"host": host, "path": p}
		alfaPutIf(s, "mode", q["mode"])
		if extra := strings.TrimSpace(q["extra"]); extra != "" {
			var ex map[string]interface{}
			if err := json.Unmarshal([]byte(extra), &ex); err == nil {
				s["extra"] = ex
			}
		}
		sniHint = host
		ss["network"] = "xhttp"
		ss["xhttpSettings"] = s
	case "h2", "http":
		hosts := alfaSplitList(host)
		p := path
		if p == "" {
			p = "/"
		}
		s := map[string]interface{}{"host": hosts, "path": p}
		if len(hosts) > 0 {
			sniHint, _ = hosts[0].(string)
		}
		ss["network"] = "h2" // the core knows only h2
		ss["httpSettings"] = s
	case "grpc":
		s := map[string]interface{}{
			"serviceName":          q["serviceName"],
			"authority":            q["authority"],
			"multiMode":            q["mode"] == "multi",
			"idle_timeout":         60,
			"health_check_timeout": 20,
		}
		sniHint = q["authority"]
		ss["network"] = "grpc"
		ss["grpcSettings"] = s
	case "kcp":
		return nil, errors.New("mKCP links are not built by this module; pass a complete outbound object instead")
	default:
		return nil, fmt.Errorf("unknown transport %q; this module builds tcp, ws, httpupgrade, xhttp, h2 and grpc", network)
	}

	// ------------------------------------------------------------------- tls
	security := q["security"]
	if security == "" {
		security = defaultSecurity
	}
	if security != "" && security != "tls" && security != "reality" {
		security = ""
	}
	if security == "" {
		return ss, nil
	}
	ss["security"] = security

	pinnedCa := q["pcs"]
	insecure := alfaIsTrue(q["insecure"]) || alfaIsTrue(q["allowInsecure"]) || alfaIsTrue(q["allow_insecure"])

	tls := map[string]interface{}{"allowInsecure": insecure && pinnedCa == ""}

	sni := q["sni"]
	if sni == "" {
		if sniHint != "" && alfaIsDomainName(sniHint) {
			sni = sniHint
		} else if server != "" && alfaIsDomainName(server) {
			sni = server
		} else {
			sni = sniHint
		}
	}
	alfaPutIf(tls, "serverName", sni)
	alfaPutIf(tls, "fingerprint", q["fp"])
	alfaPutIf(tls, "cipherSuites", q["cs"])
	alfaPutIf(tls, "echConfigList", q["ech"])
	alfaPutIf(tls, "verifyPeerCertByName", q["vcn"])
	alfaPutIf(tls, "pinnedPeerCertSha256", pinnedCa)
	if alpn := q["alpn"]; alpn != "" {
		tls["alpn"] = alfaSplitList(alpn)
	}
	if security == "reality" {
		alfaPutIf(tls, "publicKey", q["pbk"])
		alfaPutIf(tls, "shortId", q["sid"])
		alfaPutIf(tls, "spiderX", q["spx"])
		ss["realitySettings"] = tls
	} else {
		ss["tlsSettings"] = tls
	}
	return ss, nil
}

// =============================================================================
// Small helpers (ConfigParser port)
// =============================================================================

// alfaNormalize mirrors ConfigParser.normalize: for a link, strip invisible
// marks and fold typographic quotes; for JSON, leave it (encoding/json reads
// it). The decrypted blob is clean, but the secret VALUES inside may have been
// pasted into a panel, so the same cleaning is kept.
func alfaNormalize(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" {
		return ""
	}
	if !strings.HasPrefix(t, "{") {
		cleaned := alfaStrip(t)
		if cleaned == "" {
			return t
		}
		return cleaned
	}
	return t
}

func alfaStrip(s string) string {
	var b strings.Builder
	for _, c := range s {
		if alfaIsInvisible(c) {
			continue
		}
		switch c {
		case '“', '”', '„', '‟', '″', '«', '»':
			b.WriteByte('"')
		case '‘', '’', '‚', '‛', '′':
			b.WriteByte('\'')
		case ' ', ' ', ' ':
			b.WriteByte(' ')
		default:
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}

func alfaIsInvisible(c rune) bool {
	return c == '\uFEFF' ||
		(c >= '\u200B' && c <= '\u200F') ||
		(c >= '\u202A' && c <= '\u202E') ||
		(c >= '\u2066' && c <= '\u2069') ||
		c == '\u2060' ||
		c == '\u00AD'
}

// alfaHostPortURI reads host (IPv6 brackets stripped) and port off a parsed URI.
func alfaHostPortURI(u *url.URL) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("the link has no host (an IPv6 address must be written as [::1]:443)")
	}
	ps := u.Port()
	if ps == "" {
		return "", 0, errors.New("the link has no port")
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port <= 0 {
		return "", 0, fmt.Errorf("%q is not a port number", ps)
	}
	return host, port, nil
}

// alfaHostPortStr splits "host:port", keeping an IPv6 literal's colons intact.
func alfaHostPortStr(s string) (string, int, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(t, "/")
	var host, portStr string
	if strings.HasPrefix(t, "[") {
		closeIdx := strings.IndexByte(t, ']')
		if closeIdx < 0 {
			return "", 0, errors.New("the link's IPv6 address is missing its ]")
		}
		host = t[1:closeIdx]
		colon := strings.IndexByte(t[closeIdx:], ':')
		if colon < 0 {
			return "", 0, errors.New("the link has no port")
		}
		portStr = t[closeIdx+colon+1:]
	} else {
		colon := strings.LastIndexByte(t, ':')
		if colon <= 0 {
			return "", 0, errors.New("the link has no port")
		}
		host = t[:colon]
		portStr = t[colon+1:]
	}
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port <= 0 {
		return "", 0, fmt.Errorf("%q is not a port number", portStr)
	}
	return host, port, nil
}

func alfaSplitFirst(s string, c byte) []string {
	i := strings.IndexByte(s, c)
	if i <= 0 || i == len(s)-1 {
		return nil
	}
	return []string{s[:i], s[i+1:]}
}

// alfaDecodeBase64 mirrors decodeBase64 + padBase64: URL-safe or standard,
// padding optional, surrounding whitespace ignored.
func alfaDecodeBase64(s string) (string, error) {
	t := strings.TrimSpace(s)
	t = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(t)
	t = strings.ReplaceAll(t, "-", "+")
	t = strings.ReplaceAll(t, "_", "/")
	switch len(t) % 4 {
	case 2:
		t += "=="
	case 3:
		t += "="
	}
	b, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func alfaSplitList(csv string) []interface{} {
	a := []interface{}{}
	if csv == "" {
		return a
	}
	for _, part := range strings.Split(csv, ",") {
		if t := strings.TrimSpace(part); t != "" {
			a = append(a, t)
		}
	}
	return a
}

// alfaList reads split_domains / split_ips, which the backend may send as a
// JSON array or as one comma/whitespace-separated string (AlfaOptions.explode).
func alfaList(v interface{}) []string {
	out := []string{}
	switch val := v.(type) {
	case []interface{}:
		for _, e := range val {
			if s, ok := e.(string); ok {
				for _, p := range alfaExplode(s) {
					out = append(out, p)
				}
			}
		}
	case string:
		out = append(out, alfaExplode(val)...)
	}
	return out
}

func alfaExplode(s string) []string {
	out := []string{}
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if t := strings.TrimSpace(field); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func alfaQuery(rawQuery string) map[string]string {
	out := map[string]string{}
	if rawQuery == "" {
		return out
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		if eq := strings.IndexByte(pair, '='); eq < 0 {
			out[alfaDecode(pair)] = ""
		} else {
			out[alfaDecode(pair[:eq])] = alfaDecode(pair[eq+1:])
		}
	}
	return out
}

func alfaDecode(s string) string {
	d, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return d
}

func alfaIsTrue(v string) bool {
	t := strings.TrimSpace(v)
	return t == "1" || strings.EqualFold(t, "true") || strings.EqualFold(t, "yes")
}

// alfaIsDomainName: a name rather than an address literal.
func alfaIsDomainName(host string) bool {
	if strings.IndexByte(host, ':') >= 0 {
		return false
	}
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c > 127 {
			return true
		}
	}
	return false
}

func alfaParseInt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

// alfaVStr reads a vmess-base64 field: "" when absent or blank.
func alfaVStr(o map[string]interface{}, key string) string {
	switch v := o[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	}
	return ""
}

func alfaPutIf(m map[string]interface{}, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func alfaPutNonEmpty(m map[string]string, key, value string) {
	if value != "" {
		m[key] = value
	}
}

// alfaIsBlank: a secret value that is absent for routing purposes - an empty
// string, or an empty object.
func alfaIsBlank(v interface{}) bool {
	switch val := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(val) == ""
	case map[string]interface{}:
		return len(val) == 0
	}
	return false
}

// alfaToIface turns an outbound chain into the []interface{} json.Marshal wants.
func alfaToIface(chain []map[string]interface{}) []interface{} {
	out := make([]interface{}, len(chain))
	for i := range chain {
		out[i] = chain[i]
	}
	return out
}

// alfaStrIface turns a []string into a []interface{} for a JSON array value.
func alfaStrIface(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i := range ss {
		out[i] = ss[i]
	}
	return out
}
