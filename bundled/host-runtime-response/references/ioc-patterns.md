# IOC patterns: October 2026 host-runtime wave

## Compromised / vulnerable version ranges

| Component | Vulnerable | Fixed | Advisory |
|---|---|---|---|
| PHP | < 8.2.35, 8.2.x<8.2.35, 8.3.x<8.3.36, 8.4.x<8.4.27, 8.5.x<8.5.12, <= 8.1/7.x EOL | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | CVE-2026-109618, CVE-2026-109619 (CVSS 9.2) |
| Node.js | 22.x<22.23.4, 24.x<24.22.1, 26.x<26.12.1, EOL lines | 22.23.4 / 24.22.1 / 26.12.1 | CVE-2026-111497, CVE-2026-105482, CVE-2026-105483, CVE-2026-106069, CVE-2026-105481, CVE-2026-106072, CVE-2026-106074, CVE-2026-106071, CVE-2026-106073 |
| Google Brotli | 1.0.3 – 1.2.0 (unfixed branch releases) | 1.0.10 / 1.1.1 / 1.2.1 | CVE-2026-111497, GHSA-9v8h-qqgm-4m35, PYSEC-2026-4322 |
| PyPI Brotli / brotlicffi | 1.0.3 – 1.2.0 | 1.1.1 / 1.2.1 (or vendor backport) | PYSEC-2026-4322 |

## Distro package notes

- Ubuntu 24.04 (noble): `libbrotli1 1.1.0-2build2` is affected; Ubuntu tracker
  status was "needs evaluation" (no fix shipped) as of 2026-10-25.
- Debian 13: fixed as `1.1.0-2+deb13u1` (DSA 6582-1).
- Ubuntu nodejs (jammy+) links the system brotli; nvm/volta/source installs
  bundle their own (fixed only by the Node security releases).

## eMudhra / emSign certificate IOCs

Distrusted root (removed from Mozilla NSS 3.131.1 and the Chrome Root Store):

- Subject: `emSign ECC Root CA - G3`

Compromised intermediate CA subjects (keys recoverable; revoked 2026-10-18):

- `EM DV TLS CA - G3B` / `EM DV TLS CA - G3C`
- `EM OV TLS CA - G3B` / `EM OV TLS CA - G3C`
- `EM EV TLS CA - G3B` / `EM EV TLS CA - G3C`
- `EM OV CS CA - G3B` / `EM OV CS CA - G3C` (code-signing)

Compromised intermediate SPKI SHA-256 hashes (block/monitor):

- `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` EM DV TLS CA - G3B
- `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` EM DV TLS CA - G3C
- `43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b` EM OV TLS CA - G3B
- `63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8` EM OV TLS CA - G3C
- `e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41` EM EV TLS CA - G3B
- `5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0` EM EV TLS CA - G3C
- `ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6` EM OV CS CA - G3B
- `92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30` EM OV CS CA - G3C

Still-trusted emSign roots that legitimately remain in trust stores (context
only, not an incident): `emSign Root CA - G1`, `emSign Root CA - C1`,
`emSign ECC Root CA - C3`.

## Reference links

- PHP: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- PHP GHSA-6wmf-4rv5-p3rp: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CISA alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Node.js releases: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- Brotli upstream fix: https://github.com/google/brotli/releases (v1.2.1)
- Ubuntu tracker: https://ubuntu.com/security/CVE-2026-111497
- Mozilla eMudhra post: https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
- Chrome Root Program: https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/
- Kudelski analysis: https://kudelskisecurity.com/research/emudhra-intermediate-ca-private-key-compromise
- eMudhra statement: https://emudhra.com/en/post/certificate-security-incident
