# Plan: nginx HTTP/2 advisory checks (NGINX2Root)

Date: 2026-11-19 — profile: `scira scan nginx [--live]`

## Advisory

F5/Rapid7 disclosed two unauthenticated memory-safety flaws in nginx's HTTP/2
module on 2026-11-18 (NGINX2Root):

- CVE-2026-123007 (CVSS 9.2): integer underflow in HTTP/2 flow control → OOB
  heap write during stream cancellation. Public PoC; unauth RCE demonstrated
  on official images with TLS+HTTP/2 static files, no backend. 1.9.5–1.31.8.
- CVE-2026-123633 (CVSS 8.1): use-after-free when HTTP/2 connections drain
  while connecting upstream and the worker is low on worker_connections.
  Primarily DoS; code execution with ASLR bypass. 1.19.7–1.31.8 + proxy.

Fixed in 1.30.7 / 1.31.9 (+ USN-9159-1 etc. for distros; Plus 37.0.8.1/37.3.0.1).
Mitigation: `http2 off;` / remove `http2` from listen directives.

## Brainstorm: how nginx ends up vulnerable (detection surfaces)

1. Install surfaces: host dpkg (nginx/nginx-core/full/light), source builds
   (/usr/local/nginx, /opt/nginx, caught via /proc exe), running docker
   containers, image metadata (NGINX_VERSION env — verify-tier, inherited env
   can be stale), forks (OpenResty/Tengine/Kong pin old cores), k8s
   ingress-nginx (own release cadence), NGINX Plus (own scheme).
2. Version sources: `nginx -v` (stderr!), dpkg-query (backport caveat),
   docker exec, image env, process→exe.
3. Real exposure conditions: client-facing HTTP/2 listener (listen …http2 or
   http2 on, incl. h2c) AND http_v2 module compiled in (not in bare
   ./configure builds); 123633 additionally needs an upstream
   (proxy_pass/fastcgi/uwsgi/scgi/grpc_pass). Plain h1 or h1-behind-h2-LB is
   not exposed.
4. Distro backport trap: Ubuntu fixed noble as 1.24.0-2ubuntu7.20 (USN-9159-1)
   without an upstream bump → naive version strings false-positive; OSV
   distro datasets encode the fixed package versions.

## Checks implemented

- Version verdict: lines 1.30→1.30.7, 1.31→1.31.9; 1.9.5–1.29.x compromised
  (no fix on line); <1.9.5 "verify" (only resolver UAF reaches that far back).
- Host: PATH + standard prefixes + /proc-based process discovery (canonicalized
  to dedupe usrmerge symlinks); dpkg nginx*; `nginx -V` fork markers (Tengine/
  OpenResty) and `--with-http_v2_module` absence → CVEs unreachable → verify.
- Docker: running containers via `nginx -v` + config analysis; images via
  NGINX_VERSION env (verify-tier).
- Exposure analysis: `nginx -T` dump → grep -r fallback over /etc/nginx;
  comment-stripped matching for `listen…http2` / `http2 on` and the five
  *_pass directives; each hit annotated EXPOSED / verify-includes / not-h2.
- k8s: `kubectl get pods -A` → ingress-nginx images → controller-upgrade note.
- `--live`: two-query OSV protocol (api.osv.dev/v1/query) — (1) installed
  package+version: our CVEs matching ⇒ still affected; (2) if absent, package
  query: CVE known but version excluded ⇒ BackportConfirmed (downgrades dpkg
  and same-version host-binary hits to safe); unknown ⇒ version-string verdict
  stands (never downgrade on absence of evidence).

## Validation

- e2e container (ubuntu:24.04 + nginx 1.24.0-2ubuntu7.20): offline →
  likely_affected with "re-run with --live"; `--live` → both hits safe via
  USN-9159-1, status no_indicators_found (exit 0).
- Exposure e2e (listen 8080 http2 + proxy_pass): hits annotated
  "HTTP/2 ENABLED — EXPOSED (CVE-2026-123007); proxied backend present, so
  CVE-2026-123633 also applies".
- secrig host: no host/running nginx; image excalidraw (NGINX_VERSION=1.27.5)
  flagged verify-tier; kubectl-absent noted.
