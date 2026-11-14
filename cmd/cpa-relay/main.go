// cpa-relay is a stock CPA native C ABI plugin, not a Go plugin (.so plugin.Open).
package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; cliproxy_host_call_fn call; cliproxy_host_free_fn free_buffer; } cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; cliproxy_plugin_call_fn call; cliproxy_plugin_free_fn free_buffer; cliproxy_plugin_shutdown_fn shutdown; } cliproxy_plugin_api;
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
static cliproxy_host_api host_api;
static int set_host(const cliproxy_host_api* h) {
 if (!h || h->abi_version != 1 || !h->call || !h->free_buffer) return 1;
 host_api = *h; return 0;
}
static int host_call(const char* method, const uint8_t* req, size_t len, cliproxy_buffer* out) {
 if (!host_api.call) return 1;
 return host_api.call(host_api.host_ctx, method, req, len, out);
}
static void host_free(void* ptr, size_t len) { if (ptr && host_api.free_buffer) host_api.free_buffer(ptr,len); }
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"

	"github.com/NotRllyRn/cpa-relay/internal/relay"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

var app = &application{host: callHost}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil || C.set_host(host) != 0 {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, req *C.uint8_t, n C.size_t, out *C.cliproxy_buffer) (rc C.int) {
	if out == nil {
		return 1
	}
	out.ptr = nil
	out.len = 0
	defer func() {
		if recover() != nil {
			app.fault.Store(true)
			writeResponse(out, failure())
		}
	}()
	if method == nil || n > relay.MaxBody*2 || (n > 0 && req == nil) {
		writeResponse(out, failure())
		return 0
	}
	var raw []byte
	if n > 0 {
		raw = C.GoBytes(unsafe.Pointer(req), C.int(n))
	}
	writeResponse(out, app.handle(C.GoString(method), raw))
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	defer func() {
		if recover() != nil {
			app.fault.Store(true)
		}
	}()
	app.stop()
}

func writeResponse(out *C.cliproxy_buffer, raw []byte) {
	if out == nil {
		return
	}
	// Also safe when a recovered panic replaces an already allocated response.
	if out.ptr != nil {
		C.free(out.ptr)
	}
	out.ptr = C.CBytes(raw)
	out.len = C.size_t(len(raw))
}

func callHost(method string, payload any, dst any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return errors.New("host unavailable")
	}
	cm := C.CString(method)
	defer C.free(unsafe.Pointer(cm))
	p := C.CBytes(raw)
	defer C.free(p)
	var out C.cliproxy_buffer
	rc := C.host_call(cm, (*C.uint8_t)(p), C.size_t(len(raw)), &out)
	if out.ptr != nil {
		defer C.host_free(out.ptr, out.len)
	}
	if rc != 0 || out.ptr == nil || out.len > relay.MaxBody*2 {
		return errors.New("host unavailable")
	}
	var env pluginabi.Envelope
	if json.Unmarshal(C.GoBytes(out.ptr, C.int(out.len)), &env) != nil || !env.OK || json.Unmarshal(env.Result, dst) != nil {
		return errors.New("host unavailable")
	}
	return nil
}
