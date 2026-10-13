# RFC Backlog: Exfil-Hardening — Capability Broker & Canonical Matcher

> **Document Status**: Proposed — Backlog (belum diimplementasi, menunggu review)
> **Date**: 2026-09-24
> **Context**: v0.5.11 (`perf/in-process-exec-and-benchmark-calibrations`), temuan uji empiris 2026-09-24
> **Reviewers**: maintainer + GPT (review eksternal)

## 1. Problem statement

Uji empiris terhadap `sanitizeStreamOutput` / `createStreamSanitizer` (`cli/vault/exec.mjs`) menunjukkan:

| Case | Hasil |
|---|---|
| Raw `<secret>` di stdout, termasuk split antar chunk | Redacted → `secretRef:<id>` (PASS, sesuai `VERIFY-SEC-001`) |
| Transformasi sepele (`D U M M Y ...`, sisip whitespace) | **Lolos** filter exact-match, mudah direkonstruksi |
| `base64(secret)` / `lowercase(secret)` pada dummy | Kebetulan tertangkap heuristik entropi (`secretRef:candidate-secret`), **tidak dijamin** |
| Tulis file, network/IPC, debugger, direct `/dev/tty`, proses unmanaged | Di luar interceptor **by design** (boundary di `scripts/verify-evidence.mjs:94`, `README.md:105`) |
| Child `--allow-raw-unmediated` | Secret memang ada di memory anak — bisa ditransform/di-exfil |
| Same-user disk/process (`~/.hetzer/grimoire.key`, `/proc/$pid/mem`) | Bisa dibaca tanpa sandbox |

Redaksi stdout sempurna bersifat undecidable. Prinsip RFC ini: **buat bocoran tidak berguna**, bukan kejar deteksi total.

## 2. Backlog items

### B1. Broker-first: capability, bukan secret (prioritas: HIGH)

Perluas pola HTTP broker (`cli/vault/http-broker.mjs`) — anak tidak pernah pegang plaintext:

- B1a. **DB protocol-aware proxy** (Postgres/Redis/Mongo): anak konek ke loopback, broker inject kredensial upstream.
- B1b. **Cloud signing sidecar** (mis. SigV4): anak bawa request unsigned + kapabilitas macaroon, broker yang sign.
- B1c. Jadikan broker sebagai **default** untuk kredensial mediatable; raw injection (`--allow-raw-unmediated`) tetap sebagai exception teraudit.

Acceptance:
- Child env/memory tidak berisi secret untuk kredensial brokered (uji: `env`, `/proc/self/environ` tidak bocor).
- `base64($SECRET)` mati dengan sendirinya karena tidak ada `$SECRET`.
- Batas tetap didokumentasikan: child bisa abaikan broker via jalur network lain; bukan network sandbox.

### B2. Lease pendek + audience-bound (prioritas: HIGH) [IMPLEMENTED & VERIFIED]

- TTL singkat (default 60 detik di `validateBrokerPolicy`), quota atomik, loopback/sandbox binding, catat event di audit ledger (`BROKER_LEASE_ISSUED`, `BROKER_LEASE_EXPIRED`, `BROKER_CAPABILITY_INVALID`, `BROKER_LIMIT_REACHED` di `cli/vault/audit.mjs`).
- Kalaupun bocor via transform, blast radius kecil.

Acceptance: token curian kedaluwarsa/ditolak di luar audience; uji kedaluwarsa, invalid capability, lease issuance, dan quota limit (BROKER_LIMIT_REACHED) terverifikasi di `cli/vault/http-broker.test.mjs` (28/28 tests passing).

### B3. Canonical matcher terbatas untuk known secrets (prioritas: MEDIUM) [IMPLEMENTED & VERIFIED]

Tambahkan normalisasi **hanya untuk secret yang diinject** (biaya bounded, bukan generic scan):

- Normalisasi spasi/tab (`\s+`), NFKC/case-folding, decode `base64`/`hex`/`url`/`unicode-escape` (`\u002F`, `%2F`, `%3D`) per secret pada `sanitizeStreamOutput` dan `checkForCanaries` di `cli/vault/exec.mjs`.
- Jaga budget `VERIFY-PERF-001` (<5ms; terukur ~0.028ms).
- Dokumentasikan: menutup transformasi known-secret umum, **tanpa klaim** menangkap unknown secret (heuristik tetap bisa false positive/negatif).

Acceptance: uji `spasi`, `base64`, `hex`, `%2F`, `\u002F`, dan honeytoken canary terverifikasi di `cli/vault/exec.test.mjs`; benchmark latensi tetap <5ms median (~0.028ms).

### B4. Auto-sandbox untuk ancestry agent + egress allowlist (prioritas: MEDIUM)

- Jika `detectAgentAncestor()` true → default ke `hetzer exec --sandbox` (lanjutkan `HETZER_AUTO_SANDBOX` di `cli/modules/cli.mjs`), dengan `--cap-drop=ALL`, tanpa mount host AppData, egress hanya ke broker + upstream di-policy.
- File/network/`/dev/tty` exfil tertahan di level OS/container, bukan level string-match.

Acceptance: matriks uji win/linux/mac + Docker/Podman-absent (graceful degrade dengan warning, bukan crash).

### B5. Default-deny exec policy profiles untuk mode agent (prioritas: LOW)

- Perketat `cli/vault/exec-policy.mjs` saat mode agent: blokir interpreter `-c`/`iex` downloader (sebagian sudah ada), tulis path sensitif (sudah ada), tambah blokir socket langsung kecuali via broker. Mode developer interaktif tetap longgar.

Acceptance: uji policy allow/deny + bypass attempt (`;`, `$()`,分裂 argv) tetap ditolak; developer flow tidak regresi.

## 3. Non-goals (eksplisit tidak dikerjakan)

- DLP network penuh / inspeksi semua egress — butuh firewall/EDR OS, di luar scope (delegasi ke Jagdpanzer/OS controls).
- Redaksi semua output generik tanpa false positive/negatif — mustahil; fokus known-injected secrets + canary tripwire (exit 43) sebagai deteksi.
- Klaim "zero plaintext" absolut — lihat perbaikan wording `hardware-root-of-trust-roadmap.md:91-94` (2026-09-24).

## 4. Pertanyaan untuk reviewer (GPT)

1. Apakah B1a/B1b realistis dengan constraint **0 external npm deps** + stdlib Node saja? Protokol DB mana yang didahulukan?
2. Apakah desain macaroon/audience-binding B2 cukup tanpa menambah dependency crypto baru (sudah ada `node:crypto`)?
3. Apakah canonical decoding B3 membuka risiko ReDoS/CPU-amplifikasi dari output anak yang adversarial? Batas biaya apa yang perlu ditambahkan?
4. Apakah auto-sandbox B4 berisiko memecah developer flow (false positive ancestry)? Mekanisme opt-out yang aman?
5. Adakah vektor exfil yang terlewat dari tabel §1?

## 5. Release gate (ikuti `docs/system-logic-and-progress.md`)

- `npm run check && npm test && npm run verify` hijau di Windows, Linux, macOS.
- Tidak ada klaim absolut baru di docs (cek kata: `guarantee`, `zero leakage`, `cannot`, `100%`).
- Bukti uji tiap item berupa file uji + baris boundary di `verify-evidence` bila relevan.
