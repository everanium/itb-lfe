;;;; itb3-lfe — public API of the ITB LFE binding.
;;;;
;;;; Thin proxy over the ITB Erlang binding's `itb3` module via native
;;;; BEAM bytecode interop — the LFE layer adds no FFI hop of its
;;;; own. No ITB construction logic lives in this binding: profile
;;;; names, opts keys, and every primitive name are opaque strings
;;;; passed through to Go for validation.
;;;;
;;;; The module is named `itb3-lfe` (not `itb3`) because the Erlang
;;;; binding's `itb3` module shares the code path; a same-named module
;;;; would collide on load.
;;;;
;;;; Quick start:
;;;;
;;;;     (let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
;;;;            (`#(ok ,blob) (itb3-lfe:save sender))
;;;;            (`#(ok ,receiver) (itb3-lfe:load blob))
;;;;            (`#(ok ,wire) (itb3-lfe:encrypt-message sender #"hi"))
;;;;            (`#(ok ,plain) (itb3-lfe:decrypt-message receiver wire)))
;;;;       (itb3-lfe:free receiver)
;;;;       (itb3-lfe:free sender)
;;;;       plain)
;;;;
;;;; Handles are opaque NIF resources owned by the Erlang layer:
;;;; dropping every term reference lets the garbage collector release
;;;; the Go-side state (libitb3 zeroes key material internally), and
;;;; `free/1` / `stream-free/1` release eagerly. A stream session
;;;; pins its parent pipeline, so the pipeline can never be collected
;;;; under a live session. Do not call `free/1` on a handle another
;;;; process is concurrently using — single-owner discipline per
;;;; handle, or drop references and let the collector free.
;;;;
;;;; Errors follow the `#(ok result) | #(error #(status detail))`
;;;; idiom: `status` is an atom mirroring the C binding's status
;;;; table (e.g. `mac_failure`, `bad_input`, `profile_exists`) and
;;;; `detail` the Go-side diagnostic binary.

(defmodule itb3-lfe
  (export
    ;; Pipeline lifecycle
    (init 1) (init 2)
    (load 1) (load 3)
    (load-f 1) (load-f 3)
    (save 1)
    (save-f 2)
    (max-workers 2)
    (rekey 3)
    (free 1)
    ;; Single Message encrypt / decrypt
    (encrypt-message 2)
    (decrypt-message 2)
    ;; One-shot stream encrypt / decrypt
    (encrypt-stream-one-shot 2)
    (decrypt-stream-one-shot 2)
    ;; Incremental stream sessions
    (encrypt-stream 1)
    (decrypt-stream 1)
    (stream-write 2)
    (stream-end 1)
    (stream-read 1) (stream-read 2)
    (stream-free 1)
    ;; Profile catalogue
    (inspect 1)
    (register 2)
    (lookup 1)
    (profiles 0)
    ;; Runtime + diagnostics
    (version 0)
    (last-error 0)
    (set-memory-limit 1)
    (set-gc-percent 1)))

;;; ------------------------------------------------------------------
;;; Pipeline lifecycle
;;; ------------------------------------------------------------------

(defun init (profile)
  "As init/2 with pure profile defaults."
  (itb3:init profile (map)))

(defun init (profile opts)
  "Constructs a fresh Pipeline against the named profile. Opts may be
  an empty map / property list for pure profile defaults; keys and
  values accumulate into the URL-query string consumed by libitb3 (the
  binding performs no validation — Go rejects unknown keys and bad
  values with a diagnostic in the error detail)."
  (itb3:init profile opts))

(defun load (blob)
  "Reconstructs a Pipeline from a blob produced by save/1 or rekey/3,
  using the blob-embedded masters. The blob's embedded profile record
  is the sole structural source — no profile name, no opts."
  (itb3:load blob))

(defun load (blob perm-master wrap-master)
  "As load/1 with explicit master overrides. Both masters must be
  supplied (a half-supplied pair is rejected Go-side); pass
  #\"\" / #\"\" for the blob-embedded masters."
  (itb3:load blob perm-master wrap-master))

(defun load-f (path)
  "load/1 for a blob stored in a file; the file is read inside the
  library."
  (itb3:load_f path))

(defun load-f (path perm-master wrap-master)
  "As load-f/1 with explicit master overrides."
  (itb3:load_f path perm-master wrap-master))

(defun save (pipeline)
  "The current serialised session blob — the bytes init produced, the
  bytes load re-marshalled, or the bytes of the latest rekey/3."
  (itb3:save pipeline))

(defun save-f (pipeline path)
  "Writes the current session blob to path inside the library (mode
  0600; the containing directory must exist)."
  (itb3:save_f pipeline path))

(defun max-workers (pipeline n)
  "Sets the worker cap for every subsequent cipher call. n is
  clamped, never rejected: n =< 0 selects auto, 1..256 pins the cap,
  larger values are treated as 256. The cap is per-machine tuning and
  is never written to the blob."
  (itb3:max_workers pipeline n))

(defun rekey (pipeline perm-master wrap-master)
  "Rotates the parallax + wrapper masters and returns the refreshed
  session blob as #(ok blob) (also observable through save/1). Must
  not run concurrently with cipher calls or open stream sessions on
  the same Pipeline."
  (itb3:rekey pipeline perm-master wrap-master))

(defun free (pipeline)
  "Eagerly closes (zeroing key material Go-side) and releases the
  handle. Idempotent; subsequent calls on the handle fail with
  #(error #(bad_handle _)). Garbage collection of the last term
  reference is the release backstop."
  (itb3:free pipeline))

;;; ------------------------------------------------------------------
;;; Single Message encrypt / decrypt
;;; ------------------------------------------------------------------

(defun encrypt-message (pipeline plain)
  "One call, one self-contained wire."
  (itb3:encrypt_message pipeline plain))

(defun decrypt-message (pipeline wire)
  "Receive-side counterpart of encrypt-message/2."
  (itb3:decrypt_message pipeline wire))

;;; ------------------------------------------------------------------
;;; One-shot stream encrypt / decrypt
;;; ------------------------------------------------------------------

(defun encrypt-stream-one-shot (pipeline plain)
  "One-shot stream encrypt for callers holding the whole plaintext in
  memory: a single call through the Pipeline's stream chain. For
  bounded-memory streaming use the incremental encrypt-stream/1
  session."
  (itb3:encrypt_stream_one_shot pipeline plain))

(defun decrypt-stream-one-shot (pipeline wire)
  "Receive-side counterpart of encrypt-stream-one-shot/2."
  (itb3:decrypt_stream_one_shot pipeline wire))

;;; ------------------------------------------------------------------
;;; Incremental stream sessions
;;; ------------------------------------------------------------------

(defun encrypt-stream (pipeline)
  "Opens an incremental encrypt session (plaintext in, wire out). The
  session must not outlive its Pipeline (it pins the pipeline term,
  so dropping the pipeline reference alone never frees it early)."
  (itb3:encrypt_stream pipeline))

(defun decrypt-stream (pipeline)
  "Receive-side counterpart (wire in, plaintext out)."
  (itb3:decrypt_stream pipeline))

(defun stream-write (stream data)
  "Feeds data into the session. Blocks (on a dirty scheduler) until
  the cipher chain accepts the bytes; errors are sticky."
  (itb3:stream_write stream data))

(defun stream-end (stream)
  "Signals end-of-input. Idempotent; a write after end fails with
  #(error #(bad_input _))."
  (itb3:stream_end stream))

(defun stream-read (stream)
  "As stream-read/2 with a 1 MiB drain slice."
  (itb3:stream_read stream))

(defun stream-read (stream max-bytes)
  "Drains up to max-bytes produced bytes. Returns
  #(ok data finished) — data may be #\"\" when nothing is currently
  available, and finished is 'true once the session has ended AND the
  output is fully drained. Partial drains are the normal mode. After
  stream-end/1, an empty-spool read blocks until the terminal bytes
  arrive or the session errors."
  (itb3:stream_read stream max-bytes))

(defun stream-free (stream)
  "Cancels (if still running) and eagerly releases the session. Safe
  from any state — mid-flight, mid-error, or after a clean drain.
  Idempotent; garbage collection is the release backstop."
  (itb3:stream_free stream))

;;; ------------------------------------------------------------------
;;; Profile catalogue
;;; ------------------------------------------------------------------

(defun inspect (blob)
  "Decodes the blob's embedded profile record without opening a
  Pipeline and returns #(ok record) — a binary-keyed map decoded with
  the OTP json module; absent keys are optional fields at their zero
  value. No registry read, no primitive probe."
  (itb3:inspect blob))

(defun register (name profile)
  "Registers a profile record under name so subsequent init / lookup
  calls resolve it. profile is the record as a map (the shape inspect
  / lookup return) or an already-encoded JSON binary; a name key
  inside it, if present, must be empty or equal to name. Validation
  is performed by libitb3; a duplicate name fails with
  #(error #(profile_exists _))."
  (itb3:register name profile))

(defun lookup (name)
  "The profile record registered under name (a shipped catalogue
  entry or a prior register/2). An unknown name fails with
  #(error #(unknown_profile _))."
  (itb3:lookup name))

(defun profiles ()
  "The sorted list of every registered profile name."
  (itb3:profiles))

;;; ------------------------------------------------------------------
;;; Runtime + diagnostics
;;; ------------------------------------------------------------------

(defun version ()
  "The libitb3 library version string (e.g. #\"0.5.1\")."
  (itb3:version))

(defun last-error ()
  "The Go-side diagnostic recorded by the most recent failing libitb3
  call (process-global last-write-wins; #\"\" when none). The error
  tuples already carry this detail — direct use is for ad-hoc
  debugging only."
  (itb3:last_error))

(defun set-memory-limit (bytes)
  "Sets the Go runtime's soft heap limit in bytes; returns the
  previous limit. A negative value queries without changing."
  (itb3:set_memory_limit bytes))

(defun set-gc-percent (pct)
  "Sets the Go GC trigger percentage; returns the previous value. A
  negative value queries without changing."
  (itb3:set_gc_percent pct))
