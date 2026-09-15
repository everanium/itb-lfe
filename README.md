## ITB LFE Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the ITB Erlang binding's Triple Pipeline surface
(`bindings/erlang`) via **native BEAM bytecode interop** — the LFE
layer calls the Erlang `itb3` module directly and adds no FFI hop of
its own. The only native code in the stack is the Erlang binding's
NIF shim, consumed here as a rebar3 checkout dependency (the
committed `_checkouts/libitb3` symlink). Every hash-name / MAC-name /
cipher-name / profile-name is an opaque string passed through to Go
for validation; the binding carries no ITB construction logic.

The public surface is the `itb3-lfe` module (`init` / `load` /
`load-f` / `save` / `save-f` / `rekey` / `max-workers` / `free`,
Single Message encrypt / decrypt, incremental stream sessions with
`stream-write` / `stream-end` / `stream-read`), the profile
catalogue (`inspect` / `register` / `lookup` / `profiles`), and the
Go runtime knobs — the Erlang surface under LFE-idiomatic kebab-case
names. The module is named `itb3-lfe`
rather than `itb3` because the Erlang binding's `itb3` module shares
the code path; a same-named module would collide on load. Handles
are opaque NIF resources; the cipher entries run on dirty CPU
schedulers so multi-megabyte calls never stall the regular BEAM
schedulers.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make erlang rebar3
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, Erlang/OTP
27+, and rebar3. The LFE compiler is **not** a system prerequisite —
it arrives as the `lfe` hex dependency and the `rebar3_lfe` plugin
drives it. macOS: the same via Homebrew; libitb3 builds as
`libitb3.dylib`.

## Build the shared library

The convenience driver builds `libitb3.so`, the C binding's static
archive, the Erlang backend (NIF shim included), and the rebar3
project in one step:

```bash
./bindings/lfe/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
make -C bindings/c build/libitb3_c.a
cd bindings/lfe && rebar3 compile
```

## Add to an LFE project

The binding is a standard rebar3 + `rebar3_lfe` project that pulls
the Erlang binding through the `_checkouts/libitb3` symlink. From
another rebar3 project, consume both the same way — symlink
`bindings/erlang` as `_checkouts/libitb3` and `bindings/lfe` as
`_checkouts/libitb3_lfe`, and declare bare `itb` / `itb_lfe` deps.

The compiled NIF (`bindings/erlang/priv/libitb3_nif.so`) resolves
`libitb3.so` through its embedded RPATH into the repo `dist/`
directory, so no `LD_LIBRARY_PATH` is needed at runtime.

## Usage example

```lisp
(let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
       (`#(ok ,blob) (itb3-lfe:save sender))
       (`#(ok ,receiver) (itb3-lfe:load blob))
       (`#(ok ,wire) (itb3-lfe:encrypt-message sender
                                              #"any text or binary data"))
       (`#(ok ,plain) (itb3-lfe:decrypt-message receiver wire)))
  (itb3-lfe:free receiver)
  (itb3-lfe:free sender)
  plain)

;; File-backed equivalent (persist across processes):
;; (let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
;;        ('ok (itb3-lfe:save-f sender "session.blob"))
;;        (`#(ok ,receiver) (itb3-lfe:load-f "session.blob")))
;;   ...)
```

Opts override the profile default at `init/2` (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap) as a map. The resolved shape is written into the blob, so the
receiver loads it with no opts of its own:

```lisp
(let* ((opts (map #"chunkSize" 65536 #"withWrapper" 'false))
       (`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1" opts))
       (`#(ok ,blob) (itb3-lfe:save sender))
       (`#(ok ,receiver) (itb3-lfe:load blob)))
  ...)
```

`rekey/3` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design) and returns the refreshed blob; the receiver picks up the new
masters through a fresh `load/1`:

```lisp
(let ((`#(ok ,blob2) (itb3-lfe:rekey sender (binary:copy #b(#x11) 32)
                                           (binary:copy #b(#x22) 32))))
  (itb3-lfe:load blob2))
```

### Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```lisp
(itb3-lfe:save sender)                   ; #(ok blob) — current blob
(itb3-lfe:save-f sender "session.blob")  ; written by libitb3, mode 0600
(itb3-lfe:load blob)                     ; reopen from bytes
(itb3-lfe:load-f "session.blob")         ; reopen from file
(itb3-lfe:load blob perm wrap)           ; override the masters
(itb3-lfe:inspect blob)                  ; #(ok record) — no Pipeline
```

`inspect/1` returns the record as a binary-keyed map decoded with the
OTP `json` module; absent keys are optional fields at their zero
value.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load/1` such a blob
through this binding returns `#(error #(recipe_primitive_unknown _))`.

### Profile registry

```lisp
(itb3-lfe:profiles)                          ; sorted list of binaries
(itb3-lfe:lookup #"singlemsg-triple-mac-v1") ; #(ok record); unknown -> unknown_profile
(itb3-lfe:register #"my-profile"
  (map #"mode" #"singlemsg-nomac"
       #"width" 256
       #"hashes" (list #"blake3" #"blake2s" #"areion256" #"blake2b256"
                       #"chacha20" #"blake3" #"blake2s" #"areion256")
       #"keybits" 1024
       #"parallax" 'false
       #"wrapper" 'false))
(itb3-lfe:init #"my-profile")
```

`register/2` takes the same record shape `inspect` / `lookup` return
(a map, or an already-encoded JSON binary); a `name` key inside it,
if present, must be empty or equal to the name argument. Every rule
— name pattern, reserved prefixes, field constraints, primitive
names — is enforced by libitb3; a duplicate name returns
`#(error #(profile_exists _))`.

### Runtime tuning

`max-workers/2` sets the worker cap on a live Pipeline (`n =< 0`
selects auto, values above 256 are clamped). The cap is per-machine
tuning and is never written to the blob, so the receiver may pick
its own worker cap after `load/1`. The `maxWorkers` opts key sets
the same cap at `init/2`.

### One-shot streams

`encrypt-stream-one-shot/2` / `decrypt-stream-one-shot/2` put a
whole in-memory payload through the stream chain in a single call:

```lisp
(let* ((`#(ok ,wire) (itb3-lfe:encrypt-stream-one-shot sender plain))
       (`#(ok ,back) (itb3-lfe:decrypt-stream-one-shot receiver wire)))
  back)
```

### Caller-driven stream sessions

```lisp
(let ((`#(ok ,session) (itb3-lfe:encrypt-stream sender)))
  (itb3-lfe:stream-write session chunk1)
  (itb3-lfe:stream-write session chunk2)
  (itb3-lfe:stream-end session)
  ;; Drain until #(ok data true):
  (let ((`#(ok ,wire-piece ,finished) (itb3-lfe:stream-read session 1048576)))
    ...)
  (itb3-lfe:stream-free session))
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as
`#(error #(status detail))` — `status` an atom mirroring the C
binding's status table (e.g. `mac_failure`, `bad_input`,
`profile_exists`), `detail` the Go-side diagnostic binary. Opts are
a map or property list (`(map #"keyBits" 1024 #"nonceBits" 512)`)
rendered into the URL-query string libitb3 consumes.

Handle lifetime is garbage-collected: dropping every term reference
releases the Go-side state through the NIF resource destructor, and
`free/1` / `stream-free/1` release eagerly (both idempotent). A
stream session pins its parent pipeline resource, so the pipeline is
never collected under a live session.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```lisp
(itb3-lfe:set-memory-limit (* 4 1024 1024 1024)) ;; 4 GiB soft cap
(itb3-lfe:set-gc-percent 100)                     ;; balanced GC
```

## Testing

```bash
./bindings/lfe/run_tests.sh
```

The harness builds `libitb3.so` + the C archive + the Erlang backend
+ the rebar3 project, then invokes `rebar3 eunit` (the LFE test
module is written with the ltest macros and registered explicitly in
`rebar.config` — EUnit cannot auto-discover `.lfe` sources). The
suite covers the Single Message round trip, stream pumps, the profile
catalogue, runtime knobs, profile registration, and error mapping
(unknown profile, tampered wire, freed handles) — surface parity
checks; the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/lfe/run_bench.sh
```

Micro-benches: `message` (encrypt-message) and `stream_pump`
(incremental encrypt session) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` defaults (respecting caller
overrides) and the bench module applies the same caps
programmatically. `./run_bench.sh message` / `./run_bench.sh
stream` runs one shape.

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `itb3-lfe:load-f/1`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

An executable script under `bindings/lfe/eitb/` mirrors the shipped
Go `tools/eitb` scope for shell smoke tests (build the binding
first):

```bash
cd bindings/lfe
./eitb/eitb version
./eitb/eitb profiles
./eitb/eitb inspect <blob-hex>
./eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `detail` text in an error tuple comes from a process-global
  last-write-wins store on the Go side; under concurrent use it may
  belong to a different call. The status atom is always
  attributable.
- `rekey/3` must not run concurrently with cipher calls or open
  stream sessions on the same Pipeline.
- Single-owner discipline per handle: do not call `free/1` /
  `stream-free/1` while another process is mid-call on the same
  handle — free from the owning process, or drop every reference
  and let the resource destructor release.
- After `stream-end/1`, an empty-spool `stream-read/2` blocks (on a
  dirty scheduler) until the terminal bytes arrive or the session
  errors; the regular schedulers are unaffected.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
