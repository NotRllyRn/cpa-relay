#!/usr/bin/env python3
"""Real Linux c-shared ABI + HTTPS + background host callback smoke test.

No CPA process, provider request, real credential, or production access is used.
The mock intentionally makes host.auth.save non-atomic, like CPA v8.0.63.
"""
import base64
import contextlib
import ctypes as C
import datetime as dt
import http.server
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Buffer(C.Structure):
    _fields_ = [("ptr", C.c_void_p), ("len", C.c_size_t)]


HostCall = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_char_p, C.c_void_p, C.c_size_t, C.POINTER(Buffer))
Free = C.CFUNCTYPE(None, C.c_void_p, C.c_size_t)
PluginCall = C.CFUNCTYPE(C.c_int, C.c_char_p, C.c_void_p, C.c_size_t, C.POINTER(Buffer))
Shutdown = C.CFUNCTYPE(None)


class Host(C.Structure):
    _fields_ = [("abi_version", C.c_uint32), ("host_ctx", C.c_void_p), ("call", HostCall), ("free_buffer", Free)]


class Plugin(C.Structure):
    _fields_ = [("abi_version", C.c_uint32), ("call", PluginCall), ("free_buffer", Free), ("shutdown", Shutdown)]


def dumps(value):
    return json.dumps(value, separators=(",", ":")).encode()


def b64(value):
    return base64.b64encode(value).decode()


def stamp(ns):
    return dt.datetime.fromtimestamp(ns / 1e9, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{ns % 1_000_000_000:09d}Z"


def until(condition):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError("timed out")


def main():
    lib_path = str(pathlib.Path(sys.argv[1]).resolve())
    context = tempfile.TemporaryDirectory(prefix="cpa-relay-abi-") if len(sys.argv) == 2 else contextlib.nullcontext(sys.argv[3])
    with context as tmp:
        root = pathlib.Path(tmp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(key), "-out", str(cert),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(key, 0o600)
        os.environ["SSL_CERT_FILE"] = str(cert)
        bearer = os.environ.get("CPA_RELAY_ABI_SECRET") or secrets.token_urlsafe(32)
        os.environ["CPA_RELAY_ABI_SECRET"] = bearer
        # Go's native runtime snapshots process environment. Exercise the same
        # startup contract as CPA, rather than Python's late setenv/dlopen case.
        if len(sys.argv) == 2:
            subprocess.run([sys.executable, __file__, lib_path, "--child", tmp], check=True, env=os.environ.copy())
            return
        now = time.time_ns()
        fake_token = "e30." + base64.urlsafe_b64encode(dumps({"exp": now // 1_000_000_000 + 7200})).decode().rstrip("=") + ".test-signature"
        credential = {"type": "codex", "account_id": "acct-a", "access_token": fake_token,
                      "expired": stamp(now + 3600 * 1_000_000_000), "disabled": False,
                      "refresh_token": "NEVER-RELAY", "id_token": "NEVER-RELAY", "metadata": {"secret": "NEVER-RELAY"}}
        lock = threading.Lock()
        buffers, runtime, calls, callback_errors = {}, {}, [], []
        control = {"fail_disabled": 0, "disabled_attempts": 0, "models_missing": True,
                   "source_path": str(root / "source" / "chosen.json"), "extra": False, "runtime_states": {}}
        second = dict(credential, email="second@example.invalid")
        auth = root / "auth"
        auth.mkdir(mode=0o700)
        main_thread = threading.get_ident()

        @HostCall
        def callback(_ctx, method, ptr, size, out):
            try:
                method = method.decode()
                request = json.loads(C.string_at(ptr, size))
                assert "callback_id" not in request
                with lock:
                    calls.append((method, threading.get_ident()))
                if method == "host.auth.list":
                    with lock:
                        result = {"files": [{"auth_index": "index-a", "type": "codex", "name": "chosen.json",
                                              "path": control["source_path"]}] + ([{"auth_index": "index-b", "type": "codex", "name": "second.json", "path": str(root / "source/second.json")}] if control["extra"] else []) + [
                            {"id": n, "name": n, "path": str(auth / n), "auth_index": "runtime-"+n,
                             "provider": "codex", "status": "active", "disabled": a["disabled"],
                             **control["runtime_states"].get(n, {})}
                            for n, a in runtime.items()]}
                elif method == "host.auth.models":
                    with lock:
                        result = {"credentials": [{"id": n, "auth_index": "runtime-"+n,
                            "provider": "codex", "models": [] if a["disabled"] or control["models_missing"] else ["test-model"]}
                            for n, a in runtime.items()]}
                elif method == "host.auth.get":
                    index = request["auth_index"]
                    path = control["source_path"] if index == "index-a" else str(root / "source/second.json")
                    result = {"auth_index": index, "name": pathlib.Path(path).name.strip(), "path": path,
                              "json": credential if index == "index-a" else second}
                elif method == "host.auth.save":
                    name, data = request["name"], request["json"]
                    assert pathlib.Path(name).name == name
                    assert "refresh_token" not in data and "siwc" not in data
                    path = auth / name
                    path.write_bytes(dumps(data))
                    os.chmod(path, 0o600)
                    with lock:
                        if data["disabled"]:
                            control["disabled_attempts"] += 1
                            if control["fail_disabled"]:
                                control["fail_disabled"] -= 1
                                return 1  # intentional failure after the non-atomic disk write
                        runtime[name] = data
                    result = {"name": name, "path": str(path)}
                else:
                    raise AssertionError("unexpected callback")
                raw = dumps({"ok": True, "result": result})
                buf = C.create_string_buffer(raw)
                address = C.addressof(buf)
                with lock:
                    buffers[address] = buf
                out[0].ptr, out[0].len = address, len(raw)
                return 0
            except Exception as exc:
                with lock:
                    callback_errors.append(type(exc).__name__)
                return 1

        @Free
        def free_host(ptr, _size):
            with lock:
                buffers.pop(ptr, None)

        lib = C.CDLL(lib_path)
        lib.cliproxy_plugin_init.argtypes = [C.POINTER(Host), C.POINTER(Plugin)]
        lib.cliproxy_plugin_init.restype = C.c_int
        host = Host(1, None, callback, free_host)
        plugin = Plugin()
        assert lib.cliproxy_plugin_init(C.byref(host), C.byref(plugin)) == 0
        assert plugin.abi_version == 1

        def rpc(method, payload, okay=True):
            raw = dumps(payload)
            buf = C.create_string_buffer(raw)
            out = Buffer()
            rc = plugin.call(method.encode(), C.cast(buf, C.c_void_p), len(raw), C.byref(out))
            try:
                assert rc == 0 and out.ptr
                envelope = json.loads(C.string_at(out.ptr, out.len))
                assert envelope["ok"] == okay
                return envelope.get("result", {})
            finally:
                if out.ptr:
                    plugin.free_buffer(out.ptr, out.len)

        def configure(config, method="plugin.reconfigure"):
            result = rpc(method, {"schema_version": 10, "config_yaml": b64(dumps(config))})
            assert result["capabilities"]["request_interceptor"]
            assert result["schema_version"] == 10

        def management(path, headers=None, method="GET"):
            result = rpc("management.handle", {"Method": method, "Path": path, "Headers": headers or {}})
            return result["StatusCode"], base64.b64decode(result["Body"])

        def ready():
            return management("/v0/resource/plugins/cpa-relay/ready")[0] == 200

        common = {"enabled": True, "secret_env": "CPA_RELAY_ABI_SECRET", "poll_seconds": 15}
        configure(dict(common, role="exporter", state_dir=str(root / "exporter")), "plugin.register")
        assert management("/v0/resource/plugins/cpa-relay/snapshot")[0] == 401
        status, body = management("/v0/resource/plugins/cpa-relay/snapshot", {"Authorization": ["Bearer " + bearer]})
        assert status == 200 and b"NEVER-RELAY" not in body, (status, management("/v0/management/cpa-relay/status")[1], callback_errors)
        snapshot = json.loads(body)
        assert set(snapshot["accounts"][0]) == {"credential_id", "type", "account_id", "access_token", "expired", "disabled"}
        assert not any(method == "host.auth.save" for method, _ in calls)
        assert b"chosen.json" not in body and b"/source/" not in body
        with lock:
            gets = sum(method == "host.auth.get" for method, _ in calls)
            control["source_path"] = str(root / "source" / "chosen.json ")
        assert management("/v0/resource/plugins/cpa-relay/snapshot", {"Authorization": ["Bearer " + bearer]})[0] == 503
        with lock:
            assert sum(method == "host.auth.get" for method, _ in calls) == gets
            control["source_path"] = str(root / "source" / "chosen.json")
            control["extra"] = True
        status, body = management("/v0/resource/plugins/cpa-relay/snapshot", {"Authorization": ["Bearer " + bearer]})
        snapshot = json.loads(body)
        assert status == 200 and len(snapshot["accounts"]) == 2
        assert len({a["credential_id"] for a in snapshot["accounts"]}) == 2
        assert len({a["account_id"] for a in snapshot["accounts"]}) == 1
        routes = rpc("management.register", {})
        assert len(routes["resources"]) == 3 and len(routes["routes"]) == 3

        serve = threading.Event()
        remote = {"status": 200, "body": body}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if not serve.wait(5):
                    return
                if self.headers.get("Authorization") != "Bearer " + bearer:
                    self.send_error(401)
                    return
                with lock:
                    status, response = remote["status"], remote["body"]
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            config = dict(common, role="receiver", state_dir=str(root / "receiver"), auth_dir=str(auth), receiver_id="secondary",
                          endpoint=f"https://127.0.0.1:{server.server_port}/v0/resource/plugins/cpa-relay/snapshot")
            configure(config)
            gate = rpc("request.intercept_before", {"Stream": True})
            assert gate["Terminate"] and gate["StatusCode"] == 503
            assert not ready()
            serve.set()
            until(lambda: json.loads(management("/v0/management/cpa-relay/status")[1])["last_attempt"] == "models_pending")
            assert not ready()  # save acknowledgement alone does not prove routes
            assert rpc("request.intercept_before", {"Stream": True})["Terminate"]
            with lock:
                control["models_missing"] = False
            until(ready)
            assert not rpc("request.intercept_before", {"Stream": True})["Terminate"]
            with lock:
                assert any(m == "host.auth.save" and ident != main_thread for m, ident in calls)
                assert len(runtime) == 2 and all(not a["disabled"] for a in runtime.values())
                assert any(m == "host.auth.models" and ident != main_thread for m, ident in calls)

            def relay_status():
                return json.loads(management("/v0/management/cpa-relay/status")[1])

            # Raw upstream errors must not veto an independently active account.
            # Elapsed retries also occur on rejected tokens; never infer recovery.
            with lock:
                names = sorted(runtime)
                old_error = {"status": "error", "unavailable": True,
                             "next_retry_after": stamp(time.time_ns() - 3600 * 1_000_000_000)}
                control["runtime_states"][names[0]] = old_error
            until(lambda: relay_status().get("reason") == "degraded")
            state = relay_status()
            assert state["ready"] and state["accounts"] == state["synchronized_accounts"] == 2
            assert state["available_accounts"] == 1
            assert not rpc("request.intercept_before", {"Stream": True})["Terminate"]
            with lock:
                control["runtime_states"][names[1]] = old_error
            until(lambda: relay_status().get("reason") == "no_available_accounts")
            state = relay_status()
            assert not state["ready"] and state["synchronized_accounts"] == 2 and state["available_accounts"] == 0
            assert rpc("request.intercept_before", {"Stream": True})["Terminate"]
            with lock:
                control["runtime_states"] = {names[0]: {"disabled": True}}
            until(lambda: relay_status().get("reason") == "runtime_disabled")
            assert not ready()
            with lock:
                control["runtime_states"].clear()
            until(ready)

            def publish(accounts):
                generation = time.time_ns()
                snapshot.update(generation=generation, generated_at=stamp(generation), accounts=accounts)
                with lock:
                    remote["body"] = dumps(snapshot)
                assert management("/v0/management/cpa-relay/poll", method="POST")[0] == 202
                until(lambda: json.loads((root / "receiver/state.json").read_text())["watermark"] == generation and ready())

            with lock:
                saves_before = sum(m == "host.auth.save" for m, _ in calls)
            mtimes = {p: p.stat().st_mtime_ns for p in auth.glob("*.json")}
            publish(snapshot["accounts"])
            with lock:
                assert sum(m == "host.auth.save" for m, _ in calls) == saves_before
            assert all(p.stat().st_mtime_ns == mtime for p, mtime in mtimes.items())
            refreshed = [dict(a) for a in snapshot["accounts"]]
            refreshed[0]["access_token"] = "e30." + base64.urlsafe_b64encode(dumps({"exp": now // 1_000_000_000 + 7201})).decode().rstrip("=") + ".refreshed"
            publish(refreshed)
            with lock:
                assert sum(m == "host.auth.save" for m, _ in calls) == saves_before + 2
            assert sum(p.stat().st_mtime_ns != mtime for p, mtime in mtimes.items()) == 1
            publish(refreshed[1:])
            assert len(list(auth.glob("*.json"))) == 1
            with lock:
                assert sum(not a["disabled"] for a in runtime.values()) == 1
            publish(refreshed)  # rediscovery/addition restores both independent IDs
            assert len(list(auth.glob("*.json"))) == 2
            with lock:
                control["fail_disabled"] = 6
                before = control["disabled_attempts"]
            rpc("plugin.quiesce", {}, okay=False)
            assert not ready()
            assert json.loads(management("/v0/management/cpa-relay/status")[1])["state"] == "cleanup_failed"
            configure(config)  # must retry the retained engine, not replace it
            assert not ready()
            assert management("/v0/management/cpa-relay/drain", method="POST")[0] == 503
            with lock:
                assert control["disabled_attempts"] == before + 6
                assert any(not a["disabled"] for a in runtime.values())
            assert management("/v0/management/cpa-relay/drain", method="POST")[0] == 200
            with lock:
                assert control["disabled_attempts"] == before + 8
                assert all(a["disabled"] for a in runtime.values())
            assert not list(auth.glob("*.json"))
            assert json.loads((root / "receiver/state.json").read_text())["managed"] == []
            snapshot.update(generation=time.time_ns())
            snapshot["generated_at"] = stamp(snapshot["generation"])
            with lock:
                remote["body"] = dumps(snapshot)
            configure(config)
            assert not ready() and not list(auth.glob("*.json"))  # Explicit drain survives same-config reload.
            configure(config, "plugin.register")  # Deliberate new registration requires a newer live snapshot.
            until(ready)
            with lock:
                remote["status"] = 500
            management("/v0/management/cpa-relay/poll", method="POST")
            until(lambda: json.loads(management("/v0/management/cpa-relay/status")[1])["last_attempt"] == "fetch_failed")
            assert ready() and len(list(auth.glob("*.json"))) == 2
            before = json.loads((root / "receiver/state.json").read_text())
            mtimes = {p: p.stat().st_mtime_ns for p in auth.glob("*.json")}
            with lock:
                saves_before = sum(m == "host.auth.save" for m, _ in calls)
            for _ in range(3):
                configure(config)  # Same effective config during upstream outage.
                assert ready() and not rpc("request.intercept_before", {"Stream": True})["Terminate"]
            assert json.loads((root / "receiver/state.json").read_text()) == before
            assert all(p.stat().st_mtime_ns == mtime for p, mtime in mtimes.items())
            with lock:
                assert sum(m == "host.auth.save" for m, _ in calls) == saves_before
            generation = time.time_ns()
            empty = {"version": 2, "generation": generation, "generated_at": stamp(generation), "accounts": []}
            with lock:
                remote.update(status=200, body=dumps(empty))
            management("/v0/management/cpa-relay/poll", method="POST")
            until(lambda: not ready() and not list(auth.glob("*.json")))
            with lock:
                assert all(a["disabled"] and not a["access_token"] for a in runtime.values())
            rpc("plugin.quiesce", {})
            configure(config, "plugin.register")  # New instance cannot authorize cached state.
            until(lambda: json.loads(management("/v0/management/cpa-relay/status")[1])["last_attempt"] == "replay_rejected")
            assert not ready()
            publish(refreshed)
            contaminated = next(auth.glob("*.json"))
            bad = json.loads(contaminated.read_text())
            bad["refresh_token"] = "SYNTHETIC_CONTAMINATION"
            contaminated.write_bytes(dumps(bad))
            until(lambda: json.loads(management("/v0/management/cpa-relay/status")[1])["last_attempt"] == "integrity_failed")
            configure(config)  # No-op must preserve terminal quarantine, not clean/restart it.
            assert not ready() and rpc("request.intercept_before", {})["Terminate"]
            assert management("/v0/management/cpa-relay/poll", method="POST")[0] == 409
            assert json.loads(management("/v0/management/cpa-relay/status")[1])["last_attempt"] == "integrity_failed"
            for path in ("/v0/resource/plugins/cpa-relay/ready", "/v0/resource/plugins/cpa-relay/status", "/v0/management/cpa-relay/status"):
                public = management(path)[1]
                assert fake_token.encode() not in public and bearer.encode() not in public and b"acct-a" not in public
            assert management("/v0/resource/plugins/cpa-relay/drain", method="POST")[0] == 404
            assert management("/v0/management/cpa-relay/drain", method="POST")[0] == 200
            rpc("plugin.quiesce", {})
            assert not ready()
            plugin.shutdown()
            with lock:
                assert not buffers and not callback_errors
        finally:
            serve.set()
            plugin.shutdown()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
        print("PASS: native C ABI, automatic same-workspace discovery, export sanitization/auth, HTTPS pull, background save/models, unchanged no-write/offline reconfigure, preserved drain/quarantine, isolated refresh, add/remove/delete-all, delayed routes, gate, cold-start replay, failed quiesce/reconfigure retained cleanup, authenticated drain, lifecycle, buffer ownership")


if __name__ == "__main__":
    main()
