# Host Runtime Security Response Skill (October 2026 wave)

Use this skill when responding to the October 2026 host-runtime security wave that
combines four related advisories: the PHP "PHP2Shell" critical RCEs, the Node.js
October 21 security releases, the Google Brotli decoder RCE (CVE-2026-111497), and
the eMudhra emSign intermediate CA key compromise.

SCIRA detects each of these host-wide: installed runtime binaries (including
per-user nvm/volta installs), distro packages (dpkg), running Docker containers,
Docker image metadata, Python environments, and TLS trust stores.

## Advisory 1: PHP "PHP2Shell" (CVE-2026-109618, CVE-2026-109619)

- Two critical (CVSS 9.2) unauthenticated RCEs in PHP itself, fixed 2026-10-21.
  - CVE-2026-109618 / GHSA-w8hw-w9fx-j79w: RCE via out-of-memory corruption
    (`memory_limit` bailout leaves partially initialized state).
  - CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp: RCE via stale global state retained
    across requests in a worker.
- Fixed versions: 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP <= 8.1 (EOL) and 7.x are
  unfixed; migrate to a supported fixed release.
- Unauthenticated exploitation under default settings was demonstrated on Apache
  with mod_php; active scanning was observed in the wild within days of disclosure.
- Suppressing warnings or disabling `display_errors` is NOT a mitigation.

## Advisory 2: Node.js October 21, 2026 security releases

- Fixes ship in 22.23.4, 24.22.1, 26.12.1. EOL lines are always affected.
- High severity: CVE-2026-111497 (bundled Brotli decoder OOB write -> RCE),
  CVE-2026-105482 (dns.resolve NUL truncation), CVE-2026-105483 (fullwidth-digit
  IP TLS bypass, 24.x/26.x), CVE-2026-106069 (leading-zero octal IP TLS bypass).
- Medium/low: CVE-2026-105481 (keep-alive response smuggling),
  CVE-2026-106072 (DNS SAN authenticates IP endpoints),
  CVE-2026-106074 (snapshot entropy reuse), CVE-2026-106071/-106073 (Permission
  Model bypasses), plus a 26.x-only zlib.ZipFile content confusion issue.
- The release also refreshes bundled CA certificates for the eMudhra intermediate
  CA compromise, so unpatched Node runtimes keep trusting the compromised
  emSign G3 hierarchy in addition to the RCEs above.

## Advisory 3: Brotli decoder OOB write (CVE-2026-111497)

- Out-of-bounds write in `c/dec/decode.c` of Google Brotli (also tracked as
  "Node2Shell" / "HTTP2Shell" / "Brotli2Shell", GHSA-9v8h-qqgm-4m35,
  PYSEC-2026-4322). An attacker who can get a process to decompress crafted
  Brotli data (including fetched `Content-Encoding: br` HTTP responses) can
  corrupt memory: crash, disclosure, or RCE.
- Affected: 1.0.3 through 1.2.0. Fixed: 1.0.10 / 1.1.1 / 1.2.1
  (upstream commits b418fa8, da98063, 50a9b70).
- Beyond Node.js this affects anything bundling the decoder: PyPI `Brotli` /
  `brotlicffi`, Bun, .NET, Envoy, and distro `libbrotli` packages. Ubuntu 24.04
  `libbrotli1 1.1.0-2build2` is affected and was still "needs evaluation" (no
  fix) as of 2026-10-25; Debian shipped 1.1.0-2+deb13u1.
- Compressing data is not the vulnerable path; the risk is decompressing
  untrusted streams.

## Advisory 4: eMudhra emSign intermediate CA compromise

- 2026-10-17: researcher "Wayne" showed eight emSign G3 intermediate CA private
  keys (P-384, weak entropy) are recoverable by anyone from the public certs.
  Anyone can forge trusted TLS/code-signing certificates for any name against
  clients that still trust the hierarchy.
- Affected intermediates: EM DV/OV/EV TLS CA - G3B and - G3C, EM OV CS CA - G3B
  and - G3C (the CS pair are code-signing CAs; each key also exists as a
  Sectigo/Comodo cross-sign).
- eMudhra revoked all eight on 2026-10-18 and states no end-entity certificates
  had been issued from them.
- Browsers blocked via OneCRL/CRLSets. Mozilla removed `emSign ECC Root CA - G3`
  from NSS 3.131.1; Chrome removed it from the Chrome Root Store (rolling out
  2026-10-27). Non-browser clients with static trust stores (containers, SDKs,
  runtimes with bundled CA bundles such as unpatched Node.js) remain exposed
  until their store is refreshed.
- eMudhra's digital-signature/eSign services (emSigner) were not affected.

## Response priorities

1. Inventory first: enumerate every PHP/Node/Brotli install on the host,
   including per-user installs (nvm/volta/.local), dpkg packages, running
   containers, and image metadata.
2. Patch runtimes: upgrade Node to 22.23.4 / 24.22.1 / 26.12.1+, PHP to
   8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+, and brotli to 1.0.10 / 1.1.1 / 1.2.1+
   (or your vendor's backport). Internet-facing PHP is the top priority.
3. Refresh trust: update ca-certificates / base images so no client still
   trusts emSign ECC Root CA - G3 or the revoked emSign G3 intermediates.
4. If exposure is confirmed (internet-facing unpatched PHP, or a service that
   decompressed attacker-controlled Brotli), treat as compromised: preserve
   evidence, rotate credentials reachable from the process, rebuild.
