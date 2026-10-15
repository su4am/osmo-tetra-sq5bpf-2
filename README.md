# osmo-tetra-sq5bpf-2 — TETRA receiver with TEA1 cipher research support (CVE-2022-24402)

This is a fork of [sq5bpf/osmo-tetra-sq5bpf](https://github.com/sq5bpf/osmo-tetra-sq5bpf),
which is itself a fork of the upstream
[Osmocom TETRA MAC/PHY stack](https://gitea.osmocom.org/tetra/osmo-tetra).

The primary goal of this fork is to integrate **TEA1 cipher research support** into
the `tetra-rx` pipeline, including support for the CVE-2022-24402 reduced-keyspace
(32-bit) attack, per-subscriber key lookup, and a dual-socket architecture that lets
[telive-2](https://github.com/sq5bpf/telive-2) monitor both decrypted and unencrypted
traffic simultaneously.

---

## What is new in this fork

### 1. TEA1 cipher support (CVE-2022-24402)

ETSI TEA1, the cipher used in many public-safety TETRA networks, was found in 2022 to
have a key-scheduling weakness that reduces the effective keyspace from 2^80 to 2^32
([CVE-2022-24402, Midnightblue Labs](https://tetraburst.com/)).  
A 32-bit key can be brute-forced on a commodity GPU in under a minute once you have
three or more hyperframe/multiframe/frame collision pairs from the air.

This fork wires the
[MidnightBlueLabs TETRA_crypto](https://github.com/MidnightBlueLabs/TETRA_crypto)
library directly into `tetra-rx` so that recovered 32-bit keys are applied
**on the fly** to every encrypted traffic burst.

`key_type 16` (`KEYTYPE_SHORT32`) was added to the key store: a 4-byte (8 hex digit)
key loaded into a `keyfile.txt` entry with `key_type 16` is treated as the 32-bit
reduced TEA1 key and passed straight into the cipher without the full 80-bit
key-derivation path.

### 2. Dual-socket TRA output

Upstream `tetra-rx` sends a single UDP stream (socket on `TETRA_HACK_PORT`) to telive.
This fork opens a **second socket on `TETRA_HACK_PORT + 1`** that carries only
**unencrypted frames** — i.e., calls that were never encrypted in the first place.  
Socket 1 (`TETRA_HACK_PORT`) carries **decrypted frames only**.

This lets you run two telive-2 instances: one for decrypted encrypted calls, one as a
passive monitor for cleartext traffic, without interference.

### 3. Extended TRA frame header (20 bytes)

The upstream TRA header was 13 bytes: `TRA:%2.2x RX:%2.2x\0`.  
This fork extends it to **20 bytes**: `TRA:%2.2x RX:%2.2x DECR:%i\0`

The `DECR` field is `1` when the voice frame was successfully decrypted, `0` otherwise.
telive-2 uses this to gate audio playback: encrypted-but-not-decrypted calls are
silenced automatically.  
**Important**: update `telive.c` in your telive-2 tree with the matching 20-byte offset
patch before using this receiver.

### 4. Per-usage-marker SSI tracking

TETRA channels are multiplexed by usage marker (0–63).  
This fork tracks the SSI (subscriber identity) and encryption mode per usage marker
slot (`ssi_idx[64]`, `voice_encr_idx[64]`), set from D-MLE RESOURCE assignment
messages.  This ensures the correct per-subscriber key is used when multiple
calls share the same physical channel.

### 5. CCK hyperframe-number guard (`cck_valid_no_hf`)

Some networks encode CCK_ID in the hyperframe-number field of SYSINFO rather than the
actual hyperframe number.  Without a guard the keystream derivation uses the wrong HN
and decryption silently fails.

This fork only updates `tcs->hn` from SYSINFO when `sid.cck_valid_no_hf == 0`:

```c
if (!sid.cck_valid_no_hf)
    tcs->hn = sid.hyperframe_number;
```

### 6. SIGHUP key-store hot reload

Send `SIGHUP` to a running `tetra-rx` process to reload `keyfile.txt` without
restarting the pipeline:

```bash
kill -HUP $(pgrep tetra-rx)
```

Useful when you recover a new key mid-session and want to start decrypting immediately.

### 7. Keystream injected into 5th ACELP segment

Voice keystream bits are written into positions 461–529 of the 690-sample ACELP block
(the 5th codec segment).  The patched
[install-tetra-codec](https://github.com/sq5bpf/install-tetra-codec) reads this field
and applies the keystream during decode.  This keeps all crypto logic inside `tetra-rx`
and avoids modifying the codec pipeline beyond the injection point.

### 8. Frequency helper library (`tetra_common.c`)

`src/tetra_common.c` provides:
- `tetra_dl_carrier_hz(arfcn, offset)` — downlink frequency in Hz for any ARFCN
- `tetra_ul_carrier_hz(arfcn, offset)` — uplink frequency in Hz

These are used by the frequency-info socket messages sent to telive.

---

## Build

```bash
# install dependencies (Debian/Ubuntu)
sudo apt install build-essential libtalloc-dev libosmocore-dev socat

# build
autoreconf -i
./configure
make -j$(nproc)
```

The main binary is `src/tetra-rx`.

---

## Configuration

### keyfile.txt

Create a key store file (see `keyfile.txt.example`):

```
network mcc YOUR_MCC mnc YOUR_MNC ksg_type 1 security_class 2
key mcc YOUR_MCC mnc YOUR_MNC addr 00000000 key_type 16 key_num YOUR_CCK_ID key AABBCCDD000000000000
```

`key_type 16` = `KEYTYPE_SHORT32` (32-bit reduced TEA1 key, 8 hex digits, zero-padded to 20).  
`addr 00000000` = CCK (network-wide broadcast key).  
Individual per-subscriber keys use the ISSI as `addr`.

### cell_keys.txt

Optional: map physical cells (CN/LA/CC) to their recovered keys.  
See `cell_keys.txt.example`.

### Environment variables

| Variable | Description |
|---|---|
| `TETRA_HACK_IP` | IP address for telive UDP output (default `127.0.0.1`) |
| `TETRA_HACK_PORT` | Base UDP port. tetra-rx binds PORT (decrypted) and PORT+1 (unencrypted). |
| `TETRA_HACK_RXID` | Receiver ID embedded in every TRA header (0–255). Use distinct values per SDR. |
| `TETRA_HACK_CARRIER` | ARFCN of the downlink carrier (used for FREQINFO display only). |

### tetra-rx flags used in this fork

| Flag | Description |
|---|---|
| `-k <keyfile>` | Load key store file. Reloads on SIGHUP. |
| `-r` | Enable key recovery candidate output. |
| `-s` | Enable per-cell synchronisation output. |
| `-d <dir>` | Dump raw ACELP frames to directory (one file per SSI). |

---

## Typical pipeline

```
GNURadio (SDR source)
    │ UDP floats (one per symbol, 195312 samples/s)
    ▼
simdemod3_py3.py  (osmo-tetra-sq5bpf demodulator)
    │ unpacked bits (1 bit per byte)
    ▼
tetra-rx  (this repo)
    │ UDP TRA frames: PORT (decrypted) + PORT+1 (unencrypted)
    ▼
telive-2  (audio player / display)
```

Run one decoder instance per physical carrier. Use a separate shell or tmux pane for
each; the included `run_ch_example.sh` shows the pattern with auto-restart on silence.

---

## Relationship to other tools

| Tool | Role |
|---|---|
| [osmo-tetra-sq5bpf](https://github.com/sq5bpf/osmo-tetra-sq5bpf) | Upstream fork (demodulator); unchanged in this fork |
| [telive-2](https://github.com/sq5bpf/telive-2) | Audio front-end; requires the 20-byte header patch |
| [install-tetra-codec](https://github.com/sq5bpf/install-tetra-codec) | ACELP codec patcher; requires the keystream injection patch |
| [TETRA_crypto](https://github.com/MidnightBlueLabs/TETRA_crypto) | TEA1 cipher implementation (AGPL-3.0, vendored in `src/crypto/`) |
| [teatime](https://github.com/sq5bpf/teatime) | TEA1 key recovery (brute-force on GPU after capturing collision pairs) |

---

## Key recovery overview

1. Capture TETRA downlink with GNURadio + this receiver.
2. Collect "key recovery candidate" lines from `tetra-rx` stdout (`-r` flag).
   Each line contains a (HN, MN, FN, IV, ciphertext) tuple.
3. Pass ≥ 3 tuples with the same (HN, MN) but different FN to
   [teatime](https://github.com/sq5bpf/teatime).
4. teatime brute-forces the 32-bit reduced TEA1 keyspace (~57 s on an RTX 2060).
5. Add the recovered 32-bit key to `keyfile.txt` as `key_type 16`.
6. Send SIGHUP to reload keys; decryption starts immediately on the next voice burst.

---

## License

`src/crypto/tetra_crypto.[ch]` — © 2023 MidnightBlueLabs, **AGPL-3.0**.  
All other new/modified files in this fork — **AGPL-3.0** (same as upstream osmo-tetra).  

The ETSI TEA1 specification is subject to ETSI copyright.
This code does not implement TEA1 from scratch; it relies on the published
CVE-2022-24402 analysis and the MidnightBlueLabs reference implementation.

---

## Credits

- **Jacek Lipkowski / SQ5BPF** — osmo-tetra-sq5bpf, telive, teatime, install-tetra-codec
- **MidnightBlueLabs** — CVE-2022-24402 TEA1 analysis, TETRA_crypto library
- **Harald Welte / Osmocom** — original osmo-tetra MAC/PHY stack

---

> **Note**: This code does not break encryption.  You still need to recover or obtain
> the keys for your target network through lawful means before decryption is possible.
> The authors provide this software for security research and authorized testing only.
