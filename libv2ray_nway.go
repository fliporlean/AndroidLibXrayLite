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
//   3. hands the result to the SAME doStartLoop the normal StartLoop uses.
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
    // RTLD_NOLOAD first: the lib is already in the process, so this just grabs
    // a handle without reloading. Fall back to a normal dlopen if, for any
    // reason, it is not loaded yet.
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

// XRAY_SOCKS_PORT in the module. The inbound tun2socks dials. Keep in sync with
// AlfaSettings.XRAY_SOCKS_PORT on the Java side.
const nwaySocksPort = 10808
const nwayLoopback = "127.0.0.1"
const nwaySocksInTag = "socks-in"

// StartLoopSecure is the encrypted twin of StartLoop.
//
//	encConfig   the GCM envelope exactly as the server sent it (base64)
//	filesDir    context.getFilesDir().getAbsolutePath()  (NOT secret)
//	uuid        ANDROID_ID                                (NOT secret)
//	enableStats whether to inject the traffic-stats policy (mirrors
//	            V2rayConfigModel.enableTrafficStatics)
//	tunFd       0 here, same as StartLoop (tun2socks feeds the core over SOCKS)
//
// The plaintext config lives only inside this Go call; it is never returned to
// Java and `ak` is never seen outside libEncryption.
func (x *CoreController) StartLoopSecure(encConfig string, filesDir string, uuid string, enableStats bool, tunFd int32) error {
	plain := nwayDecrypt(encConfig, filesDir, uuid)
	if plain == "" {
		return errors.New("nway: decrypt failed")
	}

	full, err := nwayBuildAuto(plain, enableStats)
	if err != nil {
		return fmt.Errorf("nway: build failed: %w", err)
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
	defer C.free(unsafe.Pointer(res)) // malloc'd by the C++ side; free with libc free
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
		// An object that is a single outbound, not a whole config: phase 2.
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
//   - a socks/mixed inbound already on that port  -> reuse it (listen+udp)
//   - a non-socks inbound on that port            -> refuse (don't silently break it)
//   - none                                        -> add one
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
