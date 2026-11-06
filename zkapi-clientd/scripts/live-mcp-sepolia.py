#!/usr/bin/env python3
"""Opt-in live check of `zkapi-clientd mcp` against a running Sepolia daemon.

Spends real (test) zkAPI balance: each zkapi_delegate call is one paid
completion. It never retries a paid call, never starts or configures the
daemon, and records only sanitized evidence (no prompt/answer text, keys,
tokens or wallet identifiers).

    ZKAPI_LIVE_SEPOLIA_MCP=1 python3 -I live-mcp-sepolia.py \
        --binary /abs/zkapi-clientd --config-dir /abs/profile \
        --model provider/model --evidence /abs/live-sepolia/mcp-evidence.json

Use --list-only first for free model discovery.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import select
import stat
import subprocess
import sys
import time

TASK = ("In two sentences, explain why the sum of the first n odd numbers "
        "equals n squared. Plain text only.")
CALL_TIMEOUT = 11.5 * 60
STATUS_TIMEOUT = 10
MAX_STATUS_BYTES = 64 << 10
# The deployment this source tree pins for Sepolia; the running daemon must
# report the same one before any paid call.
PINNED_DEPLOYMENTS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "..", "internal", "zkapi", "deployments", "sepolia.json")


def fail(message):
    print("live-mcp-sepolia: " + message, file=sys.stderr)
    sys.exit(2)


def preflight(config_dir):
    path = os.path.join(config_dir, "config.json")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        fail("config.json must be an owner-only regular file")
    with open(path) as f:
        config = json.load(f)
    if config.get("zkapi", {}).get("network") != "sepolia":
        fail("profile network must be sepolia")
    host, _, port = config.get("listen", "").rpartition(":")
    try:
        if not ipaddress.ip_address(host.strip("[]")).is_loopback or not 0 < int(port) < 65536:
            raise ValueError
    except ValueError:
        fail("listen must be a numeric loopback address")
    if not config.get("relay_url", "").startswith("tor://"):
        fail("relay_url must be tor:// for strict delegation")
    if config.get("rewriter"):
        fail("disable the rewriter for this test (it would see the task outside Tor)")
    return {"listen": config["listen"], "default_model": config.get("default_model", ""),
            "key_reuse_window_seconds": config.get("key_reuse_window_seconds")}, config.get("api_key", "")


def pinned_sepolia_deployment():
    with open(PINNED_DEPLOYMENTS) as f:
        pinned = json.load(f)
    if pinned.get("network") != "sepolia" or pinned.get("chain_id") != 11155111 or not pinned.get("deployment_id"):
        fail("pinned Sepolia deployment manifest is not usable")
    return pinned["deployment_id"]


def running_daemon_status(listen, api_key, connection=http.client.HTTPConnection):
    """Ask the running daemon itself which network it serves.

    Numeric loopback only; http.client uses no proxy and follows no redirect.
    The local API key stays in memory and is never printed.
    """
    host, _, port = listen.rpartition(":")
    conn = connection(host.strip("[]"), int(port), timeout=STATUS_TIMEOUT)
    try:
        conn.request("GET", "/admin/status", headers={"Authorization": "Bearer " + api_key,
                                                      "Accept": "application/json"})
        response = conn.getresponse()
        body = response.read(MAX_STATUS_BYTES + 1)
        status = response.status
        media = (response.getheader("Content-Type") or "").split(";")[0].strip()
    except (OSError, http.client.HTTPException, ValueError):
        fail("the running daemon's status could not be read; no paid call was made")
    finally:
        conn.close()
    if status != 200 or media != "application/json" or len(body) > MAX_STATUS_BYTES:
        fail("the running daemon's status was refused or invalid (HTTP %d); no paid call was made" % status)
    try:
        value = json.loads(body)
    except ValueError:
        fail("the running daemon's status is not JSON; no paid call was made")
    if not isinstance(value, dict):
        fail("the running daemon's status is not an object; no paid call was made")
    return value


def check_running_daemon(listen, api_key, connection=http.client.HTTPConnection):
    if not api_key:
        fail("profile has no local API key")
    expected = pinned_sepolia_deployment()
    status = running_daemon_status(listen, api_key, connection)
    observed = {key: status.get(key) for key in ("backend", "network", "deployment_id")}
    if observed != {"backend": "zkapi", "network": "sepolia", "deployment_id": expected}:
        fail("the running daemon is not the pinned Sepolia zkAPI deployment (%s); no paid call was made"
             % json.dumps(observed))
    return observed


class Session:
    def __init__(self, binary, config_dir):
        self.proc = subprocess.Popen([binary, "--config-dir", config_dir, "mcp"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=0)
        self.buffer = b""
        self.next_id = 1

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def request(self, method, params, timeout=60):
        ident = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                frame = json.loads(line)  # stdout must carry only JSON-RPC
                if frame.get("jsonrpc") != "2.0":
                    fail("non-JSON-RPC output on MCP stdout")
                if frame.get("id") == ident:
                    if "error" in frame:
                        fail("protocol error from %s: %s" % (method, frame["error"].get("message", "")[:200]))
                    return frame["result"]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("timed out waiting for %s (not retried)" % method)
            ready, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if ready:
                chunk = os.read(self.proc.stdout.fileno(), 1 << 16)
                if not chunk:
                    fail("MCP server exited during %s" % method)
                self.buffer += chunk

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return self.proc.stderr.read().decode(errors="replace")


def text_of(result):
    return "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config-dir", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--max-tokens", type=int, default=200)
    parser.add_argument("--reasoning-effort", choices=["low", "medium", "high"])
    parser.add_argument("--calls", type=int, choices=[0, 1, 2], default=1,
                        help="paid zkapi_delegate calls; a second runs only after a successful first")
    parser.add_argument("--list-only", action="store_true", help="free discovery only (same as --calls 0)")
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if os.environ.get("ZKAPI_LIVE_SEPOLIA_MCP") != "1":
        fail("set ZKAPI_LIVE_SEPOLIA_MCP=1 to run this paid live test")
    if not 1 <= args.max_tokens <= 256:
        fail("--max-tokens must be between 1 and 256 for this test")
    for path in (args.binary, args.config_dir):
        if not os.path.isabs(path):
            fail("use absolute paths")
    calls = 0 if args.list_only else args.calls
    profile, api_key = preflight(args.config_dir)
    # The saved profile is not proof of what is running: the daemon listening
    # there must itself report Sepolia before MCP is spawned.
    daemon = check_running_daemon(profile["listen"], api_key)
    del api_key
    evidence = {"profile": profile, "running_daemon": daemon, "model": args.model,
                "max_output_tokens": args.max_tokens, "reasoning_effort": args.reasoning_effort,
                "task_sha256": hashlib.sha256(TASK.encode()).hexdigest(), "calls": []}

    session = Session(args.binary, args.config_dir)
    try:
        init = session.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                              "clientInfo": {"name": "live-mcp-sepolia", "version": "1"}})
        session.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        evidence["protocol_version"] = init.get("protocolVersion")
        evidence["server_version"] = init.get("serverInfo", {}).get("version")
        tools = {t["name"]: t.get("annotations", {}) for t in session.request("tools/list", {})["tools"]}
        evidence["tool_annotations"] = tools
        listed = session.request("tools/call", {"name": "zkapi_list_models",
                                                "arguments": {"search": args.model}}, timeout=300)
        models = (listed.get("structuredContent") or {}).get("models", [])
        match = [m for m in models if m.get("id") == args.model]
        evidence["list_models"] = {"is_error": bool(listed.get("isError")), "matched": len(models),
                                   "selected_cap_usd": match[0]["per_query_cap_usd"] if match else None}
        if listed.get("isError"):
            evidence["list_models"]["error"] = text_of(listed)[:400]
            calls = 0
        elif not match:
            evidence["list_models"]["error"] = "selected model not in catalog"
            calls = 0

        for n in range(calls):
            arguments = {"task": TASK, "model": args.model, "max_output_tokens": args.max_tokens}
            if args.reasoning_effort:
                arguments["reasoning_effort"] = args.reasoning_effort
            started = time.monotonic()
            result = session.request("tools/call", {"name": "zkapi_delegate", "arguments": arguments},
                                     timeout=CALL_TIMEOUT)
            record = {"call": n + 1, "elapsed_s": round(time.monotonic() - started, 1),
                      "is_error": bool(result.get("isError"))}
            answer = text_of(result)
            if record["is_error"]:
                record["error"] = answer[:600]  # adapter errors are fixed, redacted text
            else:
                structured = result.get("structuredContent") or {}
                body = structured.get("answer", "")
                lowered = body.lower()
                record.update({
                    "answer_sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "answer_chars": len(body),
                    "answer_plausible": bool(body.strip()) and ("square" in lowered or "n^2" in lowered
                                                                 or "n²" in lowered or "n*n" in lowered),
                    "model": structured.get("model"),
                    "finish_reason": structured.get("finish_reason"),
                    "truncated": structured.get("truncated"),
                    "usage": structured.get("usage"),
                    "credential_verification": structured.get("credential_verification"),
                })
            evidence["calls"].append(record)
            if record["is_error"]:
                break  # never retry or continue after a paid-call failure
    finally:
        stderr = session.close()
        evidence["mcp_stderr_bytes"] = len(stderr)

    fd = os.open(args.evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")
    print(json.dumps(evidence, indent=2))
    ok = not evidence.get("list_models", {}).get("error") and \
        all(not c["is_error"] and c.get("answer_plausible") for c in evidence["calls"])
    sys.exit(0 if ok and len(evidence["calls"]) == calls else 1)


if __name__ == "__main__":
    main()
