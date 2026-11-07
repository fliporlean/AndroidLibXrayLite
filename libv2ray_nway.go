package libv2ray

// -----------------------------------------------------------------------------
// libv2ray_nway.go
//
// Phase B secure start path. The app sends its server config DOWN ENCRYPTED and
// it must reach the Xray core WITHOUT the plaintext ever existing as a Java
// String. This file adds ONE new bound method, StartLoopSecure, that:
//
//   1. decrypts the envelope by calling back into libEncryption.so (the native
//      lib that holds the per-device key `ak`) through its C symbol
//      nway_decrypt_config - so `ak` never leaves C++ and the plaintext never
//      touches Java;
//   2. builds the final Xray JSON from the decrypted config IN GO (today: a
//      whole Xray config, "adopted" by adding the module's SOCKS inbound; the
//      share-link / single-outbound forms are reserved for phase 2 below);
//   3. when an uplink port is given, rewrites that config IN GO so every
//      outbound dials through the service's protected loopback SOCKS proxy
//      (XrayConfigFactory.withUplink, ported faithfully below) - so the whole
//      anti-leak arrangement happens without the plaintext config touching Java;
//   4. hands the result to the SAME doStartLoop the normal StartLoop uses.
//
// Nothing here modifies StartLoop or any existing file. It is purely additive.
//
// Crash policy: every failure returns an error (never panics). The caller
// (V2rayCoreExecutor) already wraps startCore in try/catch and falls back.
// -----------------------------------------------------------------------------

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>

// Resolve nway_decrypt_config out of libEncryption.so (already loaded by the
// app via System.loadLibrary("Encryption")) and call it. Returns a malloc'd
// C string the Go side must free, or NULL on any failure.
typedef const char* (*nway_dec_fn)(const char*, const char*, const char*);

static const char* nway_bridge_decrypt(const char* enc, const char* dir, const char* uuid) {
    void* h = dlopen("libEncryption.so", RTLD_NOW | RTLD_NOLOAD);
    if (h == 0) {
        h = dlopen("libEncryption.so", RTLD_NOW);
    }
    if (h == 0) {
        return 0;
    }
    nway_dec_fn fn = (nway_dec_fn) dlsym(h, "nway_decrypt_config");
    if (fn == 0) {
        return 0;
    }
    return fn(enc, dir, uuid); // malloc'd by C++ (or NULL); caller frees
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"unsafe"
)

// Keep in sync with the Java side.
const nwaySocksPort = 10808       // AlfaSettings.XRAY_SOCKS_PORT
const nwayLoopback = "127.0.0.1"  // AlfaSettings.LOOPBACK
const nwaySocksInTag = "socks-in" // XrayConfigFactory.TAG_SOCKS_IN
const nwayTagUplink = "uplink"    // XrayConfigFactory.TAG_UPLINK
const nwayMaxChain = 16           // XrayConfigFactory.MAX_CHAIN

// StartLoopSecure is the encrypted twin of StartLoop.
//
//	encConfig   the GCM envelope exactly as the server sent it (base64)
//	filesDir    context.getFilesDir().getAbsolutePath()  (NOT secret)
//	uuid        ANDROID_ID                                (NOT secret)
//	enableStats whether to inject the traffic-stats policy
//	uplinkPort  the service's live AlfaUplink loopback port, or <=0 for none.
//	            When > 0, every outbound is pointed at it (anti-leak) IN GO;
//	            if that rewrite cannot be done the start is refused rather than
//	            run unprotected - the plaintext config never reaches Java either
//	            way.
//	tunFd       0 here, same as StartLoop (tun2socks feeds the core over SOCKS)
//
// The plaintext config lives only inside this Go call; it is never returned to
// Java and `ak` is never seen outside libEncryption.
func (x *CoreController) StartLoopSecure(encConfig string, filesDir string, uuid string, enableStats bool, uplinkPort int32, tunFd int32) error {
	plain := nwayDecrypt(encConfig, filesDir, uuid)
	if plain == "" {
		return errors.New("nway: decrypt failed")
	}

	full, err := nwayBuildAuto(plain, enableStats)
	if err != nil {
		return fmt.Errorf("nway: build failed: %w", err)
	}

	if uplinkPort > 0 {
		rewritten, applied := nwayWithUplink(full, int(uplinkPort))
		if !applied {
			// The uplink could not be made to carry the transport. Refuse
			// rather than run with the egress unprotected - same choice the
			// service makes, kept here so the plaintext never leaves native.
			return errors.New("nway: uplink could not be applied")
		}
		full = rewritten
	}

	// Same lifecycle as StartLoop, so behaviour past this point is identical.
	setEnvVariable(tunFdKey, strconv.Itoa(int(tunFd)))

	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	if x.IsRunning {
		log.Println("Core is already running")
		return nil
	}
	return x.doStartLoop(full)
}

// nwayDecrypt calls libEncryption.so's nway_decrypt_config. Returns "" on any
// failure. The plaintext only ever lives in this process's Go/C memory.
func nwayDecrypt(enc, dir, uuid string) string {
	cEnc := C.CString(enc)
	cDir := C.CString(dir)
	cUuid := C.CString(uuid)
	defer C.free(unsafe.Pointer(cEnc))
	defer C.free(unsafe.Pointer(cDir))
	defer C.free(unsafe.Pointer(cUuid))

	res := C.nway_bridge_decrypt(cEnc, cDir, cUuid)
	if res == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(res))
	return C.GoString(res)
}

// nwayBuildAuto turns a decrypted AUTO config into the final runnable Xray JSON.
//
// Today the server sends a WHOLE Xray config, so we "adopt" it: keep everything
// as-is and make sure the module's SOCKS inbound (port 10808) is present, then
// apply the traffic-stats policy. This mirrors XrayConfigFactory.forServer's
// adopt() + Utilities.applyTrafficStaticsPolicy() exactly.
//
// PHASE 2 (not yet wired): a share link (vless://, vmess://, trojan://, ss://)
// or a single outbound object. Those return an explicit error for now so the
// caller falls back cleanly instead of running a half-built config.
func nwayBuildAuto(raw string, enableStats bool) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", errors.New("empty config")
	}
	if !strings.HasPrefix(t, "{") {
		return "", errors.New("link form not supported yet (phase 2)")
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(t), &cfg); err != nil {
		return "", fmt.Errorf("bad json: %w", err)
	}
	if _, ok := cfg["outbounds"]; !ok {
		return "", errors.New("single-outbound form not supported yet (phase 2)")
	}

	if err := nwayAdopt(cfg); err != nil {
		return "", err
	}
	nwayApplyStats(cfg, enableStats)

	out, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// nwayAdopt mirrors XrayConfigFactory.adopt(): leave the whole config as pasted
// and guarantee a reachable SOCKS inbound on XRAY_SOCKS_PORT for tun2socks.
func nwayAdopt(cfg map[string]interface{}) error {
	inbounds, _ := cfg["inbounds"].([]interface{})
	if inbounds == nil {
		inbounds = []interface{}{}
	}

	for _, it := range inbounds {
		in, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		if nwayInt(in["port"], -1) != nwaySocksPort {
			continue
		}
		proto, _ := in["protocol"].(string)
		if proto == "socks" || proto == "mixed" {
			in["listen"] = nwayLoopback
			settings, ok := in["settings"].(map[string]interface{})
			if !ok || settings == nil {
				settings = map[string]interface{}{}
				in["settings"] = settings
			}
			settings["udp"] = true
			cfg["inbounds"] = inbounds
			return nil
		}
		return fmt.Errorf("config already has a %s inbound on port %d", proto, nwaySocksPort)
	}

	inbounds = append(inbounds, nwaySocksInbound())
	cfg["inbounds"] = inbounds
	return nil
}

// nwaySocksInbound mirrors XrayConfigFactory.socksInbound().
func nwaySocksInbound() map[string]interface{} {
	return map[string]interface{}{
		"tag":      nwaySocksInTag,
		"listen":   nwayLoopback,
		"port":     nwaySocksPort,
		"protocol": "socks",
		"settings": map[string]interface{}{
			"auth": "noauth",
			"udp":  true,
		},
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []interface{}{"http", "tls", "quic"},
		},
	}
}

// nwayApplyStats mirrors Utilities.applyTrafficStaticsPolicy().
func nwayApplyStats(cfg map[string]interface{}, enable bool) {
	delete(cfg, "policy")
	delete(cfg, "stats")
	if !enable {
		return
	}
	cfg["policy"] = map[string]interface{}{
		"levels": map[string]interface{}{
			"8": map[string]interface{}{
				"connIdle":     300,
				"downlinkOnly": 1,
				"handshake":    4,
				"uplinkOnly":   1,
			},
		},
		"system": map[string]interface{}{
			"statsOutboundUplink":   true,
			"statsOutboundDownlink": true,
		},
	}
	cfg["stats"] = map[string]interface{}{}
}

// nwayInt reads an int out of a value json.Unmarshal produced (numbers arrive
// as float64), with a default for anything else.
func nwayInt(v interface{}, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

// =============================================================================
// withUplink: XrayConfigFactory.withUplink + pointsAtUplink + helpers, ported
// faithfully. Every outbound whose socket leaves the device is pointed at the
// uplink (a protected loopback SOCKS proxy) via sockopt.dialerProxy, following
// dialerProxy chains to the socket that actually opens. On any shape it cannot
// safely rewrite, it reports "not applied" (false) so the caller refuses rather
// than leaks - the same fail-safe direction as the Java original.
// =============================================================================

// nwayWithUplink parses `json` fresh (so the caller's original is never
// mutated), rewrites a COPY, and returns (rewrittenJSON, true) on success, or
// ("", false) when there was nothing to protect or the config could not be
// safely rewritten.
func nwayWithUplink(jsonStr string, port int) (string, bool) {
	if jsonStr == "" || port <= 0 {
		return "", false
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return "", false
	}
	outs, ok := cfg["outbounds"].([]interface{})
	if !ok || len(outs) == 0 {
		return "", false
	}

	uplinkTag, okTag := nwayFreeTag(outs, nwayTagUplink)
	if !okTag {
		return "", false
	}

	// The uplink goes in BEFORE the loop (a chain end may point at it).
	// Appended, not inserted: Xray takes the FIRST outbound as the default.
	outs = append(outs, nwayUplinkOutbound(port, uplinkTag))
	cfg["outbounds"] = outs
	byTag := nwayByTag(outs)

	marked := 0
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
		switch status {
		case nwayChainUnfollowable:
			// A tag that is not here, or a loop: Xray could not dial it
			// either. Leave the config alone (fail-safe).
			return "", false
		case nwayChainAtUplink:
			// Already ends at our uplink (marked a moment ago as another
			// outbound's chain end).
			continue
		default: // nwayChainFound
			if nwayDialsOnlyLoopback(end) {
				// Chain hands off to a loopback listener that is not the
				// uplink; nothing is there. Leave the config alone.
				return "", false
			}
			nwaySetDialer(end, uplinkTag)
			marked++
		}
	}
	if marked == 0 {
		return "", false
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// --- small typed-map helpers -------------------------------------------------

func nwayObj(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func nwayArr(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

func nwayStr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// --- withUplink helpers (mirror XrayConfigFactory) ---------------------------

// nwayIsLoopback mirrors isLoopback().
func nwayIsLoopback(address string) bool {
	a := strings.TrimSpace(address)
	if a == "" {
		return false
	}
	if strings.HasPrefix(a, "[") && strings.HasSuffix(a, "]") {
		a = a[1 : len(a)-1]
	}
	return strings.HasPrefix(a, "127.") ||
		a == "::1" ||
		strings.EqualFold(a, "0:0:0:0:0:0:0:1") ||
		strings.EqualFold(a, "localhost")
}

// nwayHostOf mirrors hostOf(): the host part of "host:port".
func nwayHostOf(hostPort string) string {
	s := strings.TrimSpace(hostPort)
	if strings.HasPrefix(s, "[") {
		if close := strings.IndexByte(s, ']'); close > 0 {
			return s[1:close]
		}
		return s
	}
	if colon := strings.LastIndexByte(s, ':'); colon > 0 {
		return s[:colon]
	}
	return s
}

// nwayDialsOnlyLoopback mirrors dialsOnlyLoopback().
func nwayDialsOnlyLoopback(out map[string]interface{}) bool {
	settings := nwayObj(out, "settings")
	if settings == nil {
		return false
	}
	seen := 0
	if flat := nwayStr(settings, "address"); flat != "" {
		seen++
		if !nwayIsLoopback(flat) {
			return false
		}
	}
	if redirect := nwayStr(settings, "redirect"); redirect != "" {
		seen++
		if !nwayIsLoopback(nwayHostOf(redirect)) {
			return false
		}
	}
	for _, key := range []string{"vnext", "servers"} {
		list := nwayArr(settings, key)
		if list == nil {
			continue
		}
		for _, e := range list {
			entry, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			address := nwayStr(entry, "address")
			if address == "" {
				continue
			}
			seen++
			if !nwayIsLoopback(address) {
				return false
			}
		}
	}
	return seen > 0
}

// nwayByTag mirrors byTag(): first outbound wins per tag.
func nwayByTag(outs []interface{}) map[string]map[string]interface{} {
	m := map[string]map[string]interface{}{}
	for _, o := range outs {
		obj, ok := o.(map[string]interface{})
		if !ok {
			continue
		}
		t := nwayStr(obj, "tag")
		if t != "" {
			if _, exists := m[t]; !exists {
				m[t] = obj
			}
		}
	}
	return m
}

// nwayDialerOf mirrors dialerOf().
func nwayDialerOf(out map[string]interface{}) string {
	if out == nil {
		return ""
	}
	stream := nwayObj(out, "streamSettings")
	if stream == nil {
		return ""
	}
	sockopt := nwayObj(stream, "sockopt")
	if sockopt == nil {
		return ""
	}
	return nwayStr(sockopt, "dialerProxy")
}

// nwaySetDialer mirrors setDialer().
func nwaySetDialer(out map[string]interface{}, uplinkTag string) {
	stream := nwayObj(out, "streamSettings")
	if stream == nil {
		stream = map[string]interface{}{}
		out["streamSettings"] = stream
	}
	sockopt := nwayObj(stream, "sockopt")
	if sockopt == nil {
		sockopt = map[string]interface{}{}
		stream["sockopt"] = sockopt
	}
	sockopt["dialerProxy"] = uplinkTag
}

type nwayChainStatus int

const (
	nwayChainFound        nwayChainStatus = iota // `end` is the real end outbound
	nwayChainAtUplink                            // chain already ends at our uplink
	nwayChainUnfollowable                        // missing tag, loop, or too long
)

// nwayChainEnd mirrors chainEnd(): follow dialerProxy to the outbound that
// actually opens the socket.
func nwayChainEnd(byTag map[string]map[string]interface{}, out map[string]interface{}, uplinkTag string) (map[string]interface{}, nwayChainStatus) {
	at := out
	seen := map[string]bool{}
	for hop := 0; hop < nwayMaxChain; hop++ {
		next := nwayDialerOf(at)
		if next == "" {
			return at, nwayChainFound
		}
		if next == uplinkTag {
			return nil, nwayChainAtUplink
		}
		if seen[next] {
			return nil, nwayChainUnfollowable
		}
		seen[next] = true
		to := byTag[next]
		if to == nil {
			return nil, nwayChainUnfollowable
		}
		at = to
	}
	return nil, nwayChainUnfollowable
}

// nwayFreeTag mirrors freeTag(): a tag like `wanted` that no outbound has.
func nwayFreeTag(outs []interface{}, wanted string) (string, bool) {
	for n := 0; n < 64; n++ {
		candidate := wanted
		if n != 0 {
			candidate = fmt.Sprintf("%s-%d", wanted, n)
		}
		taken := false
		for _, o := range outs {
			obj, ok := o.(map[string]interface{})
			if ok && nwayStr(obj, "tag") == candidate {
				taken = true
				break
			}
		}
		if !taken {
			return candidate, true
		}
	}
	return "", false
}

// nwayUplinkOutbound mirrors uplinkOutbound().
func nwayUplinkOutbound(port int, tag string) map[string]interface{} {
	return map[string]interface{}{
		"tag":      tag,
		"protocol": "socks",
		"settings": map[string]interface{}{
			"address": nwayLoopback,
			"port":    port,
		},
	}
}
