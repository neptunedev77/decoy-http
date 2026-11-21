# decoy-http

decoy-http is a low-interaction HTTP honeypot written in Python, using only the
standard library. It poses as a misconfigured Apache/PHP server on Ubuntu, exposes a
few fake files that attackers commonly look for (`.env`, `.git/config`, `config.json`,
`wp-login.php`, phpMyAdmin) and records every request it receives.

The goal is to see what automated scanners and bots actually do when they find a
fresh server on the internet: which paths they probe, which exploits they try, which
tools they use and how quickly they show up.

The honeypot was deployed for a single 2-hour session on a disposable Azure VM, which
was deleted afterwards. Aggregated and anonymised results are in [`results/`](results/) and in the
[Results](#results) section.

## Features

- Convincing fake endpoints with Apache-style headers and error pages
- Structured JSON Lines logging of every request (headers, query, body, timing)
- Automatic tagging of requests: file probes, WordPress, SQL injection, command
  injection, Log4Shell, Shellshock, IoT exploits, proxy attempts and more
- Hardened against abuse: timeouts, size limits, connection caps and rate limiting
- Runs in a locked-down, non-root Docker container
- Scripts to analyse the logs and export anonymised results safely

## Security model

Everything the server receives is untrusted. It is parsed into plain strings and
logged, and never used for anything else.

- **No code execution.** No `eval`, `exec`, `subprocess`, `pickle`, YAML loading, shell
  calls or templates built from client input.
- **No outbound connections.** URLs in payloads are never followed, hostnames are never
  resolved and the server never acts as a proxy. `CONNECT` returns 405 and
  absolute-URI requests return 400.
- **No real files served.** Every response is static content defined in `config.py` and
  looked up by exact path. The requested path never reaches the filesystem, so path
  traversal is not possible.
- **No uploads stored.** Request bodies are written to the log only, truncated to 8 KB
  and base64-encoded when they are not valid UTF-8.
- **No reflected input.** Responses never echo client data, and `TRACE` is disabled.
- **No real secrets.** All credentials in the fake files are clearly fake
  (`decoy_not_a_real_secret`) and don't match any real key format.
- **Safe logs.** Control characters and ANSI escape sequences are escaped before
  writing, so viewing the logs in a terminal is safe and each request stays on one line.
- **Resilient.** Per-read timeouts and an overall request deadline (against slowloris),
  limits on request line, headers and body, caps on concurrent connections (global and
  per IP), per-IP rate limiting and size-based log rotation. An error in one request
  never stops the server.
- **Contained.** The container runs as a non-root user with a read-only filesystem, all
  Linux capabilities dropped, `no-new-privileges` and memory, CPU and PID limits. Only
  the log directory is writable.

## How it works

```
trap.py                     HTTP server, parsing, classification and logging
config.py                   fake endpoints, responses, detection rules and limits
analyze.py                  log statistics
export_results.py           anonymised export to results/
tests/                      unittest suite
Dockerfile
docker-compose.yml          deployment (host port 80 -> container 8080)
docker-compose.local.yml    local override, binds to 127.0.0.1 only
```

Request lifecycle in `trap.py`:

1. The connection is accepted if a slot is free (64 in total, 8 per IP). If not, it is
   closed straight away.
2. The request line and headers are read under strict size limits, with a 10 s timeout
   per read and a 20 s deadline for the whole request.
3. Clients above 120 requests per minute get a 429 and only a short log entry.
4. Up to 8 KB of the body is kept. The rest is discarded and the request is flagged as
   truncated.
5. The request is tagged using the regex rules in `config.py`.
6. The event is appended to `logs/requests.jsonl`, and a one-line summary is printed
   to stdout.
7. A static response is sent with headers such as `Server: Apache/2.4.52 (Ubuntu)` and
   `X-Powered-By: PHP/7.4.3`.

**Fake endpoints:** `/`, `/robots.txt`, `/.env`, `/api/.env`, `/.git/config`,
`/.git/HEAD`, `/config.json`, `/wp-login.php` (login attempts always fail),
`/phpmyadmin/`, `/admin` and `/server-status`. Any other path returns an Apache-style 404.

**Categories:** `sensitive-file-probe`, `wordpress-probe`, `phpmyadmin-probe`,
`admin-discovery`, `path-traversal`, `sqli-attempt`, `command-injection`, `log4shell`,
`shellshock`, `router-iot-exploit`, `proxy-attempt` and `unknown`.

## Getting started

Requires Python 3.11 or later. There are no third-party dependencies.

```bash
# run the tests
python -m unittest discover -v

# start the server on 127.0.0.1:8080 only
python trap.py --local
curl -i http://127.0.0.1:8080/.env
```

With Docker, also bound to 127.0.0.1 only:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
```

| Variable | Default | Description |
|---|---|---|
| `DECOY_HOST` | `0.0.0.0` | Bind address (ignored with `--local`) |
| `DECOY_PORT` | `8080` | Listening port |
| `DECOY_LOG_DIR` | `logs` | Log directory |

The server refuses to start as root.

## Deploying on Azure

The steps below describe a short, time-boxed deployment on Azure (Azure for Students
works fine). A B1s VM running for a few hours costs very little. The important part is deleting the whole resource
group at the end, since a stopped VM still keeps its disk and public IP.

### 1. Create the VM

- Create a dedicated resource group, e.g. `rg-decoy-http`.
- Create an Ubuntu Server 24.04 LTS VM, size B1s, using **SSH key authentication only**.
- In the network security group, allow port 22 **from your own IP only** and leave
  port 80 closed for now.
- Optionally, enable auto-shutdown shortly after the planned end time as a safety net.

### 2. Install and start the honeypot

```bash
ssh azureuser@<vm-ip>

sudo apt update && sudo apt -y upgrade
sudo apt install -y docker.io docker-compose-v2 git
sudo usermod -aG docker "$USER" && newgrp docker

git clone https://github.com/neptunedev77/decoy-http.git
cd decoy-http
docker compose up -d --build
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1/   # expect 200
```

The container runs as UID 1000, the default user on the VM, which owns `./logs`.

### 3. Go live

Add an inbound NSG rule allowing TCP port 80 from any source, then schedule the
container to stop after 2 hours:

```bash
sudo systemd-run --on-active=2h --unit=decoy-stop \
  docker compose --project-directory /home/azureuser/decoy-http stop
```

Follow the traffic live:

```bash
docker compose logs -f
tail -f logs/requests.jsonl
```

### 4. Collect and clean up

1. Remove the port 80 rule and confirm the container has stopped.
2. Copy the logs to your machine. The repo's `logs/` folder is ignored by git:
   ```bash
   scp "azureuser@<vm-ip>:~/decoy-http/logs/requests.jsonl*" ./logs/
   ```
3. Delete the resource group and check that it no longer exists.
4. Analyse and export the results locally:
   ```bash
   python analyze.py logs
   python export_results.py logs --region "<region>" --name "Session 1"
   ```

**Good practice:** don't use SSH agent forwarding (`ssh -A`), don't store personal
credentials or tokens on the VM, and never open or download URLs found in payloads.

## Analysing the logs

Each line of `logs/requests.jsonl` is one JSON event:

| Field | Description |
|---|---|
| `ts` | UTC timestamp (ISO 8601) |
| `src_ip`, `src_port` | Client address |
| `method`, `target`, `path`, `http_version` | Request line |
| `query_raw`, `query` | Query string, raw and parsed |
| `headers`, `user_agent` | All request headers |
| `body`, `body_encoding`, `body_length` | Body (truncated, UTF-8 or base64) and declared size |
| `categories` | Detected categories |
| `status`, `duration_ms` | Response status and handling time |
| `flags` | `truncated`, `rate_limited`, `malformed`, `timeout` |

`analyze.py` prints totals, a breakdown by category, top paths, user agents and source
IPs, a per-minute timeline and examples of the most interesting payloads. URLs are
defanged (`hxxp://example[.]com`) so they can't be opened by accident.

```bash
python analyze.py logs --top 30 --payloads 10
```

`export_results.py` produces the files that are safe to publish:

- `results/summary.json`: aggregated statistics and session metadata
- `results/sample.jsonl`: a small sample of requests with masked IPs (`203.0.x.x`,
  truncated IPv6), no headers, payloads capped at 300 characters and defanged URLs

No complete IP address is written to `results/`, including addresses embedded in
paths or payloads.

## Results

### Session 1 (2 h)

| | |
|---|---|
| Date | 2026-11-21 |
| Azure region | Denmark East (`denmarkeast`) |
| Exposure window | 15:54 to 17:54 UTC (2 h) |
| Total requests | 15 |
| Unique source IPs | 9 |
| Malformed requests | 5 |

The operator's own test requests were excluded with `--exclude-ip`. The full export
is in [`results/summary.json`](results/summary.json) and
[`results/sample.jsonl`](results/sample.jsonl).

**Requests by category**

A request can have more than one category.

| Category | Requests |
|---|---|
| `unknown` | 13 |
| `admin-discovery` | 2 |
| `sensitive-file-probe` | 1 |
| `router-iot-exploit` | 1 |

**Most requested paths**

| Path | Requests |
|---|---|
| `/` | 6 |
| `/favicon.ico` | 2 |
| `/admin/config.php` | 1 |
| `/boaform/adminformLogout//boaform/admin/login.asp` | 1 |

The 5 malformed requests have no path (see below).

**Notable findings**

- **First contact within 2 minutes.** The first external request arrived at 15:56:32 UTC,
  two minutes after port 80 was opened: a `HEAD /` with the user-agent `mirai-rs`, a
  name associated with Mirai-style botnets.
- **Mostly fingerprinting.** Most traffic was a plain `GET /` (sometimes followed by
  `/favicon.ico`) from internet-wide scanners, one of which identified itself as
  `ModatScanner`. These requests map exposed services rather than attack them.
- **TLS on a plain HTTP port.** A third of all requests (5 of 15) were TLS ClientHello
  handshakes sent to port 80, from two sources. Scanners try HTTPS on every open port,
  and the honeypot logged these as malformed and answered with a 400.
- **Router exploit probe.** One request targeted `/boaform/admin/login.asp`, the login
  form of the Boa web server found on many fibre routers and ONTs, which is a common
  target for IoT botnets.
- **Config file probe.** One request looked for `/admin/config.php`.
- **No targeted attacks.** No request tried `.env`, `.git/config`, WordPress or
  phpMyAdmin, and there were no SQL injection, command injection or Log4Shell payloads.
  Over a 2-hour window on a fresh IP the server was found by scanners but had not yet
  been listed as a target. Longer sessions would be needed to see exploitation attempts.
- **Stable under real traffic.** The container ran for the whole session with no
  restarts, and the rate limit was never triggered.

## Ethics and privacy

The honeypot only observes. It never attacks, scans or interacts with the systems
that connect to it. Raw logs contain IP addresses, which are personal data, so they
are kept private and deleted after the analysis. Only aggregated, anonymised data
is published.

## License

Released under the [MIT License](LICENSE).
