#!/usr/bin/env python3
"""Extract actual dashboard bytes/headers through the built plugin's C ABI."""
import base64
import ctypes as C
import json
from pathlib import Path
import sys

from abi_smoke import Buffer, Host, HostCall, Free, Plugin, dumps


def payload(library):
    @HostCall
    def unavailable(*_args):
        return 1

    @Free
    def free(*_args):
        pass

    lib = C.CDLL(str(Path(library).resolve()))
    lib.cliproxy_plugin_init.argtypes = [C.POINTER(Host), C.POINTER(Plugin)]
    lib.cliproxy_plugin_init.restype = C.c_int
    host, plugin = Host(1, None, unavailable, free), Plugin()
    assert lib.cliproxy_plugin_init(C.byref(host), C.byref(plugin)) == 0

    def rpc(method, request):
        raw = dumps(request)
        buf, out = C.create_string_buffer(raw), Buffer()
        assert plugin.call(method.encode(), C.cast(buf, C.c_void_p), len(raw), C.byref(out)) == 0
        try:
            result = json.loads(C.string_at(out.ptr, out.len))
            assert result['ok']
            return result['result']
        finally:
            plugin.free_buffer(out.ptr, out.len)

    try:
        registration = rpc('plugin.register', {'schema_version': 10, 'config_yaml': base64.b64encode(b'{}').decode()})
        assert registration['metadata']['Version'] == '0.3.0'
        result = rpc('management.handle', {'Method': 'GET', 'Path': '/v0/resource/plugins/cpa-relay/status'})
        assert result['StatusCode'] == 200
        # Public resource is a shell, with no status JSON or sample inventory.
        body = base64.b64decode(result['Body'])
        assert b'__DASHBOARD_' not in body and b'window.mockup' not in body
        return result
    finally:
        plugin.shutdown()


if __name__ == '__main__':
    print(json.dumps(payload(sys.argv[1])))
