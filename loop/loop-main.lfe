;;;; Long-run stress harness. The loop utility holds one
;;;; Pipeline handle per exercised cipher surface for minutes, hammers
;;;; it with concurrent encrypt -> decrypt -> compare round-trips from
;;;; N worker processes, rotates the outer masters and reopens the
;;;; handle from its session blob on a schedule, and reports whether
;;;; the process survived with every byte intact. It is the LFE
;;;; binding's counterpart of the Go harness under tools/loop: the
;;;; same flags, the same round structure, the same summary in both
;;;; renderings.
;;;;
;;;; The default shape is full production: the Streaming AEAD profile
;;;; with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
;;;; inner hash, 1024-bit keys, and the compile-in 512-bit nonce
;;;; width, driven through a stream session by three workers for five
;;;; minutes on 16 MiB plaintexts. Every worker owns a distinct
;;;; CSPRNG-generated plaintext held for the whole run, so any
;;;; cross-call state leakage inside the Pipeline surfaces as a data
;;;; mismatch between workers rather than cancelling out.
;;;;
;;;; A failure is one of two things. A cipher, rekey or load call that
;;;; returns a non-OK status is a worker error: the run stops, the
;;;; summary lists it, the verdict is FAIL and the exit code 1. A
;;;; round-trip that returns without error but with different bytes is
;;;; a data mismatch: the process terminates on the spot with exit
;;;; code 3, printing the worker, the iteration and the first
;;;; differing offset, and no summary — the state that produced the
;;;; wrong bytes is the evidence. A crash inside the shared library or
;;;; the emulator has no exit code of its own here; surfacing it is
;;;; what the utility is for.
;;;;
;;;; Usage:
;;;;
;;;;   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512
;;;;          --mac hmac-blake3 --payload-size 16MB --memlimit auto
;;;;          --parallax on --wrapper on
;;;;
;;;; Ctrl-C triggers a graceful shutdown: in-flight iterations
;;;; complete, then the partial summary prints.

(defmodule loop-main
  (behaviour gen_event)
  (export (start 0) (log 2) (emit 2) (closed-pipe-filter 2) (on-off 1)
          (policy-label 1) (status-text 2))
  ;; Graceful stop. The signal handler below is installed into the
  ;; emulator's signal server in place of the default one, so a
  ;; termination signal sets the run's stop request instead of halting
  ;; the node from under an in-flight cipher call.
  (export (init 1) (handle_event 2) (handle_call 2) (handle_info 2)
          (terminate 2) (code_change 3)))

(defmacro MAX-WORKERS () 10)
(defmacro CONCURRENCY () "shared-handle")
(defmacro DEFAULT-STREAM-PROFILE () "streaming-aead-triple-mac-v1")
(defmacro DEFAULT-MESSAGE-PROFILE () "singlemsg-triple-mac-v1")
;; The primitive supplied for the parallax palette and the outer
;; cipher when a profile leaves them unnamed.
(defmacro KEYSTREAM-FILL-CIPHER () "aescmac")

;;; ------------------------------------------------------------------
;;; Logging
;;; ------------------------------------------------------------------

;; Prints one prefixed status line to stdout.
;;
;; LFE-specific. The line and its newline are handed to the io server
;; as one request: workers log concurrently during maintenance, and a
;; routine that emitted the text and the newline as two requests would
;; let another worker's line land between them.
(defun log (format args)
  (emit 'standard_io (list "[loop] " (io_lib:format format args) "\n")))

(defun err (format args)
  (emit 'standard_error (list "loop: " (io_lib:format format args) "\n")))

;; Writes data to device as one request, and ends the process when the
;; device is gone. Every write of this utility goes through here.
;;
;; LFE-specific. The emulator ignores SIGPIPE, so a consumer that stops
;; reading does not end the run the way it ends the reference: the io
;; server behind the closed descriptor exits, the write raises, and the
;; node would halt on its own terms with exit 1. The failed write is
;; answered with the exit code the signal would have produced, 141,
;; with nothing further printed and nothing flushed.
(defun emit (device data)
  (try
    (io:put_chars device data)
    (catch
      ((tuple _ _ _) (erlang:halt 141 (list #(flush false)))))))

;; Keeps the emulator's own report about the closed pipe off stderr.
;;
;; LFE-specific. When stdout is a closed pipe the emulator's stdout
;; writer dies of epipe, and the terminal driver files an error report
;; about it before it stops; only then does the io server go away and
;; the failed write above end the process. The report therefore leaves
;; the driver ahead of the halt, and whether the default handler gets
;; it onto stderr first is a race the utility cannot win from the
;; failing write. The primary filter installed at start runs inside
;; the driver before the report reaches any handler and drops that one
;; report — the stdout writer, reason epipe — and no other, so every
;; other event the emulator files still prints.
(defun install-closed-pipe-filter ()
  (let (('ok (logger:add_primary_filter
               'loop_closed_pipe
               (tuple (fun loop-main closed-pipe-filter 2) 'none))))
    'ok))

(defun closed-pipe-filter
  (((map 'msg (tuple format (list 'epipe))
         'meta (map 'mfa (tuple 'user_drv _ _)))
    _)
   (case (string:prefix format "Writer crashed")
     ('nomatch 'ignore)
     (_ 'stop)))
  ((_event _) 'ignore))

(defun on-off (b) (if b "on" "off"))

;; "status <code>: <sentence>" — the numeric code the binding resolves
;; from the status the failing call returned, and the diagnostic that
;; call left behind, with nothing composed on this side of the
;; boundary. The sentence is taken whole however long it is: the
;; binding hands it over as a term the runtime owns, so no buffer
;; bounds it here.
(defun status-text (status detail)
  (loop-size:fmt "status ~B: ~ts" (list (itb3-lfe:status-code status) detail)))

;; Renders an encoder policy env value for the summary: the raw string
;; when set, "default" when the shipped ladder applies.
(defun policy-label (name)
  (case (os:getenv name)
    ('false "default")
    (value (let ((trimmed (string:trim value 'leading " \t")))
             (if (=:= trimmed "") "default" trimmed)))))

;;; ------------------------------------------------------------------
;;; Flags
;;; ------------------------------------------------------------------

;; One command-line flag: its name, the type label the usage prints,
;; the kind that governs parsing and the default suffix, and its help
;; text. Values are validated after the whole line is parsed. The
;; table is in alphabetical order, the order the usage prints.
(defun flag-table ()
  (list
   (tuple "barrier-fill" "int" 'int
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)")
   (tuple "blob-cycle-every" "int" 'int64
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never")
   (tuple "blob-mode" "int" 'int
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)")
   (tuple "chunk-size" "string" 'string
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape")
   (tuple "drbg" "string" 'string
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)")
   (tuple "duration" "duration" 'string
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0")
   (tuple "gogc" "int" 'int
     "GC trigger percentage; 0 = leave the runtime default")
   (tuple "gomaxprocs" "int" 'int
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment")
   (tuple "goroutines" "int" 'int
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1")
   (tuple "hash" "string" 'string "inner ITB hash primitive name")
   (tuple "iterations" "int" 'int64
     "fixed per-worker iteration count; 0 = duration-based")
   (tuple "json-output" "" 'bool
     "print the final summary as one compact JSON object instead of log lines")
   (tuple "key-bits" "int" 'int
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)")
   (tuple "mac" "string" 'string "MAC primitive name")
   (tuple "memlimit" "string" 'string
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)")
   (tuple "memprofile" "string" 'string
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none")
   (tuple "nonce-bits" "int" 'int
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)")
   (tuple "parallax" "string" 'string "parallax layer: on | off")
   (tuple "payload-mode" "string" 'string
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii")
   (tuple "payload-size" "string" 'string
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)")
   (tuple "profile" "string" 'string
     "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair")
   (tuple "rekey-every" "int" 'int64
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never")
   (tuple "seed" "uint" 'uint64
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")
   (tuple "shape" "string" 'string
     "cipher surface to exercise: stream | message | stream_one_shot | both")
   (tuple "wrapper" "string" 'string "wrapper layer: on | off")))

(defun defaults ()
  (map "barrier-fill" 0 "blob-cycle-every" 0 "blob-mode" 1 "chunk-size" "0"
       "drbg" "" "duration" "5m" "gogc" 0 "gomaxprocs" 0 "goroutines" 3
       "hash" "areion512" "iterations" 0 "json-output" 'false
       "key-bits" 0 "mac" "hmac-blake3" "memlimit" "auto"
       "memprofile" "" "nonce-bits" 0 "parallax" "on"
       "payload-mode" "fixed" "payload-size" "16MB" "profile" ""
       "rekey-every" 0 "seed" 0 "shape" "stream" "wrapper" "on"))

(defun usage ()
  (let ((d (defaults)))
    (emit
     'standard_error
     (cons "Usage of loop:\n"
           (lists:map (lambda (e)
                        (flag-usage (element 1 e) (element 2 e) (element 3 e)
                                    (element 4 e) (maps:get (element 1 e) d)))
                      (flag-table))))))

(defun flag-usage (name label kind help default)
  (let ((head (if (=:= label "")
                (list "  -" name "\n")
                (list "  -" name " " label "\n")))
        ;; LFE-specific. The default-value suffix is composed by hand;
        ;; a flag library that appends its own renders it itself.
        (suffix (cond ((andalso (=:= kind 'int) (=/= default 0))
                       (loop-size:fmt " (default ~B)" (list default)))
                      ((andalso (=:= kind 'string) (=/= default ""))
                       (loop-size:fmt " (default \"~s\")" (list default)))
                      ('true ""))))
    (list head "    \t" help suffix "\n")))

;; Parses argv into the raw flag values. Accepts -name value,
;; --name value, -name=value and --name=value; a boolean flag takes no
;; value unless given as -name=true / -name=false. Returns
;; #(ok Values), 'help, or 'error after printing the message.
(defun parse-argv (args)
  (parse-argv args (defaults)))

(defun parse-argv
  (('() values) `#(ok ,values))
  (((cons arg rest) values)
   (case arg
     ((cons 45 (cons _ _)) (parse-flag arg rest values))
     (_ (err "unexpected positional arguments: [~s]" (list arg)) 'error))))

(defun parse-flag (arg rest values)
  (let ((name0 (strip-dashes arg)))
    (cond
     ((orelse (=:= name0 "h") (=:= name0 "help")) 'help)
     ('true
      (let ((`#(,name ,inline) (split-inline name0)))
        (case (lists:keyfind name 1 (flag-table))
          ('false
           (err "flag provided but not defined: -~s" (list name))
           (usage)
           'error)
          (entry (take-value name (element 3 entry) inline rest values))))))))

(defun strip-dashes (arg)
  (case arg
    ((cons 45 (cons 45 name)) name)
    ((cons 45 name) name)))

(defun split-inline (arg)
  (case (string:split arg "=")
    (`(,name ,value) `#(,name #(value ,value)))
    (`(,name) `#(,name none))))

(defun take-value (name kind inline rest values)
  (case (value-of kind inline rest)
    ('needs-argument
     (err "flag needs an argument: -~s" (list name))
     'error)
    (`#(,value ,rest1)
     (case (assign kind value)
       ('error
        (err "invalid value \"~s\" for flag -~s" (list value name))
        'error)
       (`#(ok ,parsed) (parse-argv rest1 (maps:put name parsed values)))))))

(defun value-of
  ((_kind `#(value ,v) rest) `#(,v ,rest))
  (('bool 'none rest) `#("true" ,rest))
  ((_kind 'none (cons v rest)) `#(,v ,rest))
  ((_kind 'none '()) 'needs-argument))

(defun assign
  (('string value) `#(ok ,value))
  (('bool "true") #(ok true))
  (('bool "false") #(ok false))
  (('bool _) 'error)
  (('uint64 (cons 45 _)) 'error)
  (('uint64 value) (integer-value value))
  (('int64 value) (integer-value value))
  (('int value)
   (case (integer-value value)
     (`#(ok ,v) (when (andalso (=< v 2147483647) (>= v -2147483647))) `#(ok ,v))
     (_ 'error))))

(defun integer-value (value)
  (case (string:to_integer value)
    (`#(,v ,"") (when (is_integer v)) `#(ok ,v))
    (_ 'error)))

;;; ------------------------------------------------------------------
;;; Validation
;;; ------------------------------------------------------------------

;; Builds the resolved config from the parsed values. Returns
;; #(ok Cfg) or 'error after printing "loop: <message>" for the first
;; failing rule.
(defun resolve (v)
  (let ((duration (maps:get "duration" v)))
    (case (loop-size:parse-duration duration)
      (`#(ok ,ns) (when (> ns 0)) (resolve-iterations v (map 'duration-ns ns)))
      (_ (err "--duration must be positive, got ~s" (list duration)) 'error))))

(defun resolve-iterations (v cfg)
  (let ((n (maps:get "iterations" v)))
    (if (< n 0)
      (progn (err "--iterations must be >= 0, got ~B" (list n)) 'error)
      (resolve-workers v (maps:put 'iterations n cfg)))))

(defun resolve-workers (v cfg)
  (let ((g (maps:get "goroutines" v)))
    (if (orelse (< g 1) (> g (MAX-WORKERS)))
      (progn (err "--goroutines must be in 1..~B, got ~B" (list (MAX-WORKERS) g)) 'error)
      (resolve-shape v (maps:merge cfg (map 'workers-requested g 'workers g))))))

(defun resolve-shape (v cfg)
  (let ((shape (maps:get "shape" v)))
    (case (loop-worker:parse-shape shape)
      ('error
       (err "--shape must be stream | message | stream_one_shot | both, got \"~s\"" (list shape))
       'error)
      (`#(ok ,s) (resolve-hash v (maps:put 'shape s cfg))))))

(defun resolve-hash (v cfg)
  (let ((hash (maps:get "hash" v)))
    (if (lists:member (list_to_binary hash) (itb3-lfe:hash-names))
      ;; The MAC name is validated by Init: no registry enumeration
      ;; for MAC primitives crosses the boundary.
      (resolve-payload v (maps:merge cfg (map 'hash hash 'mac (maps:get "mac" v))))
      (progn (err "--hash \"~s\" is not a registered hash primitive" (list hash)) 'error))))

(defun resolve-payload (v cfg)
  (let ((size (maps:get "payload-size" v)))
    (case (loop-size:parse-size size)
      ('error (err "--payload-size: invalid size \"~s\"" (list size)) 'error)
      (`#(ok ,n)
       (if (< n 1)
         (progn (err "--payload-size must be at least 1 byte" '()) 'error)
         (resolve-memlimit v (maps:put 'payload n cfg)))))))

(defun resolve-memlimit (v cfg)
  (let ((size (maps:get "memlimit" v)))
    (if (=:= size "auto")
      (resolve-gogc v (maps:merge cfg
                        (map 'memlimit-auto 'true
                             'memlimit (if (=< (maps:get 'workers cfg) 3)
                                         (bsl 1 30)
                                         (bsl 256 20)))))
      (case (loop-size:parse-size size)
        ('error (err "--memlimit: invalid size \"~s\"" (list size)) 'error)
        (`#(ok ,n) (resolve-gogc v (maps:merge cfg (map 'memlimit-auto 'false 'memlimit n))))))))

(defun resolve-gogc (v cfg)
  (let ((g (maps:get "gogc" v)))
    (if (< g 0)
      (progn (err "--gogc must be >= 0, got ~B" (list g)) 'error)
      (resolve-layers v (maps:put 'gogc g cfg)))))

(defun resolve-layers (v cfg)
  (case (on-off-value (maps:get "parallax" v))
    ('error (err "--parallax must be on | off, got \"~s\"" (list (maps:get "parallax" v))) 'error)
    (`#(ok ,p)
     (case (on-off-value (maps:get "wrapper" v))
       ('error (err "--wrapper must be on | off, got \"~s\"" (list (maps:get "wrapper" v))) 'error)
       (`#(ok ,w) (resolve-profile v (maps:merge cfg (map 'parallax p 'wrapper w))))))))

(defun on-off-value
  (("on") #(ok true))
  (("off") #(ok false))
  ((_) 'error))

(defun resolve-profile (v cfg)
  (let ((name (maps:get "profile" v)))
    (if (=:= name "")
      (resolve-key-bits v (maps:put 'profile "" cfg))
      (case (profile-surface name)
        ('error 'error)
        (`#(ok ,surface)
         (resolve-key-bits v (maps:merge cfg
                               (map 'profile name
                                    'shape (narrow-shape (maps:get 'shape cfg) surface)))))))))

;; Resolves a registered profile to the shape family its record's mode
;; exposes by reading the record through the binding's lookup: a mode
;; beginning with "streaming" exposes the stream surfaces, one
;; beginning with "singlemsg" the message surface, "blob-only" none.
(defun profile-surface (name)
  (case (itb3-lfe:lookup (list_to_binary name))
    (`#(error ,_)
     (err "--profile \"~s\" is not a registered triple profile" (list name))
     'error)
    (`#(ok ,record)
     (let* ((mode (maps:get #"mode" record #""))
            (head (binary_part mode 0 (min 9 (byte_size mode)))))
       (cond ((=:= head #"streaming") #(ok stream))
             ((=:= head #"singlemsg") #(ok message))
             ('true
              (err "--profile \"~s\" carries no cipher surface (blob-only mode)" (list name))
              'error))))))

;; Applies a --profile's surface to the requested shape: a
;; message-surface profile forces message; a stream-surface profile
;; keeps stream or stream_one_shot as requested and turns message or
;; both into stream.
(defun narrow-shape (requested surface)
  (cond ((=:= surface 'message) 'message)
        ((=:= requested 'stream_one_shot) 'stream_one_shot)
        ('true 'stream)))

(defun resolve-key-bits (v cfg)
  (let ((k (maps:get "key-bits" v)))
    (if (lists:member k '(0 512 1024 2048))
      (resolve-nonce-bits v (maps:put 'key-bits k cfg))
      (progn (err "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got ~B"
                  (list k))
             'error))))

(defun resolve-nonce-bits (v cfg)
  (let ((n (maps:get "nonce-bits" v)))
    (if (lists:member n '(0 128 256 512))
      (resolve-blob-mode v (maps:put 'nonce-bits n cfg))
      (progn (err "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got ~B"
                  (list n))
             'error))))

(defun resolve-blob-mode (v cfg)
  (let ((m (maps:get "blob-mode" v)))
    (if (lists:member m '(1 2))
      (resolve-barrier-fill v (maps:put 'blob-mode m cfg))
      (progn (err "--blob-mode must be 1 (per-region) | 2 (per-container), got ~B" (list m))
             'error))))

(defun resolve-barrier-fill (v cfg)
  (let ((b (maps:get "barrier-fill" v)))
    (if (lists:member b '(0 1 2 4 8 16 32))
      ;; The DRBG name is validated by Init: the C ABI enumerates no
      ;; DRBG names.
      (resolve-chunk-size v (maps:merge cfg (map 'barrier-fill b 'drbg (maps:get "drbg" v))))
      (progn (err "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got ~B"
                  (list b))
             'error))))

(defun resolve-chunk-size (v cfg)
  (let ((size (maps:get "chunk-size" v)))
    (case (loop-size:parse-size size)
      ('error (err "--chunk-size: invalid size \"~s\"" (list size)) 'error)
      (`#(ok ,n) (resolve-gomaxprocs v (maps:put 'chunk-size n cfg))))))

(defun resolve-gomaxprocs (v cfg)
  (let ((g (maps:get "gomaxprocs" v)))
    (if (< g 0)
      (progn (err "--gomaxprocs must be > 0 when specified, got ~B" (list g)) 'error)
      (resolve-rekey v (maps:put 'gomaxprocs g cfg)))))

(defun resolve-rekey (v cfg)
  (let ((r (maps:get "rekey-every" v)))
    (if (< r 0)
      (progn (err "--rekey-every must be >= 0, got ~B" (list r)) 'error)
      (resolve-blob-cycle v (maps:put 'rekey-every r cfg)))))

(defun resolve-blob-cycle (v cfg)
  (let ((b (maps:get "blob-cycle-every" v)))
    (if (< b 0)
      (progn (err "--blob-cycle-every must be >= 0, got ~B" (list b)) 'error)
      (resolve-payload-mode v (maps:put 'blob-cycle-every b cfg)))))

(defun resolve-payload-mode (v cfg)
  (let ((mode (maps:get "payload-mode" v)))
    (case (loop-payload:parse-mode mode)
      ('error
       (err (++ "--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | "
                "pattern-ascii, got \"~s\"")
            (list mode))
       'error)
      (`#(ok ,m)
       `#(ok ,(maps:merge cfg (map 'payload-mode m
                                   'seed (maps:get "seed" v)
                                   'json-output (maps:get "json-output" v)
                                   'memprofile (maps:get "memprofile" v))))))))

;;; ------------------------------------------------------------------
;;; Pipelines
;;; ------------------------------------------------------------------

;; Folds a keystream primitive into opts for any layer the named
;; profile leaves unfilled but the operator asked for.
;;
;; A profile built around a primitive that is safe only inside the
;; Interlocked Barrier ships with no parallax palette and no outer
;; cipher: both layers run outside the barrier, where that primitive
;; would stand bare, so the recipe leaves them unnamed rather than
;; naming a primitive that must not key them. Engaging either layer
;; therefore needs a keystream-capable primitive supplied from outside
;; the recipe; without it construction fails on a palette below its
;; minimum or an unnamed outer cipher, and the primitive that most
;; deserves stressing becomes the one that cannot be stressed with
;; those layers engaged.
;;
;; AES-CMAC is PRF-grade, so it is sound outside the Interlocked
;; Barrier, and it is the closest relative of the AES-based inner
;; primitive whose profiles need this fill. Overrides fold into the
;; resolved record the blob carries, so the receiver rebuilds the same
;; shape from the blob alone.
(defun fill-keystream-layers (name want-parallax want-wrapper)
  (case (itb3-lfe:lookup (list_to_binary name))
    (`#(error ,_)
     (err "--profile \"~s\" is not a registered triple profile" (list name))
     'error)
    (`#(ok ,record)
     (let* ((palette-opts
             (if (andalso want-parallax (not (maps:is_key #"palette" record)))
               (let ((palette (list (tuple 'parallaxPalette
                                           (string:join (lists:duplicate
                                                         3 (KEYSTREAM-FILL-CIPHER))
                                                        ",")))))
                 ;; A recipe that never carried a palette never carried
                 ;; a segment size either, and the schedule rejects
                 ;; zero.
                 (if (maps:is_key #"segment" record)
                   palette
                   (++ palette (list #(parallaxSegmentSize "4093")))))
               '()))
            (outer-opts
             (if (andalso want-wrapper (not (maps:is_key #"outer" record)))
               (list (tuple 'outerCipher (KEYSTREAM-FILL-CIPHER)))
               '())))
       `#(ok ,(++ palette-opts outer-opts))))))

;; Constructs one Pipeline against Profile with every flag-carried
;; override in the opts list (zero values included — the shared
;; library treats zero as "profile default"), then obtains the Init
;; blob once through save: the binding's init entry does not hand the
;; blob back, and the bytes are the ones Init produced. Later blob
;; reopens use the retained blob; save is never called again.
(defun build-pipeline (cfg profile)
  (let ((base (list (tuple 'innerHash (maps:get 'hash cfg))
                    (tuple 'macName (maps:get 'mac cfg))
                    (tuple 'withParallax (on-true-false (maps:get 'parallax cfg)))
                    (tuple 'withWrapper (on-true-false (maps:get 'wrapper cfg)))
                    (tuple 'keyBits (integer_to_list (maps:get 'key-bits cfg)))
                    (tuple 'nonceBits (integer_to_list (maps:get 'nonce-bits cfg)))
                    (tuple 'barrierFill (integer_to_list (maps:get 'barrier-fill cfg)))
                    (tuple 'drbg (maps:get 'drbg cfg))
                    (tuple 'chunkSize (integer_to_list (maps:get 'chunk-size cfg)))))
        (extra (if (=:= (maps:get 'profile cfg) "")
                 #(ok ())
                 (fill-keystream-layers (maps:get 'profile cfg)
                                        (maps:get 'parallax cfg)
                                        (maps:get 'wrapper cfg)))))
    (case extra
      ('error 'error)
      (`#(ok ,fill)
       (if (=/= fill '())
         (err "~s leaves the requested keystream layers unnamed; ~s supplied for them"
              (list (maps:get 'profile cfg) (KEYSTREAM-FILL-CIPHER))))
       (case (itb3-lfe:init (list_to_binary profile) (++ base fill))
         (`#(error #(,status ,detail))
          (err "Init(~s): ~s" (list profile (status-text status detail)))
          'error)
         (`#(ok ,pipe)
          (case (itb3-lfe:save pipe)
            (`#(error #(,status ,detail))
             (err "Save(~s): ~s" (list profile (status-text status detail)))
             (itb3-lfe:free pipe)
             'error)
            (`#(ok ,blob)
             (apply-blob-mode (maps:get 'blob-mode cfg) profile pipe blob)))))))))

;; The sizing mode is not an opts knob: under --blob-mode 2 the Init
;; blob is edited and the pipeline reopened from it, so the retained
;; blob (the one blob-cycle reopens from) carries the edited mode.
(defun apply-blob-mode
  ((1 profile pipe blob)
   (log-pipeline-initialised profile blob)
   `#(ok ,pipe ,blob))
  ((mode profile pipe blob)
   (itb3-lfe:free pipe)
   (case (edit-inner-blob-mode blob mode)
     (`#(error ,detail)
      (err "rewrite blob mode: ~ts" (list detail))
      'error)
     (`#(ok ,edited)
      (case (itb3-lfe:load edited)
        (`#(error #(,status ,detail))
         (err "reload Mode 2 blob: ~s" (list (status-text status detail)))
         'error)
        (`#(ok ,reloaded)
         (log-pipeline-initialised profile edited)
         `#(ok ,reloaded ,edited)))))))

;; Sets the inner blob's integer "mode" (1 = per-region, 2 =
;; per-container) of a session blob through the OTP json module. The
;; profile record "p" carries its own string "mode"; the target is the
;; one under "ib". Integers and strings round-trip unchanged; only the
;; key order may differ.
(defun edit-inner-blob-mode (blob mode)
  (try
    (case (json:decode blob)
      ((= (map #"ib" (= (map #"mode" m) inner)) session) (when (is_integer m))
       `#(ok ,(iolist_to_binary
               (json:encode (maps:put #"ib" (maps:put #"mode" mode inner) session)))))
      (_ #(error "inner blob mode field not found")))
    (catch
      ((tuple 'error reason _)
       `#(error ,(io_lib:format "~p" (list reason)))))))

(defun on-true-false (b) (if b "true" "false"))

;; Prints the construction line with the recipe read back from the
;; blob the Pipeline handed out, not echoed from the flags: every
;; construction override is proven to have reached the library by the
;; value the receiver would see. Record values that are empty (a No
;; MAC profile's MAC, a mixed profile's single hash) print as "-".
(defun log-pipeline-initialised (profile blob)
  (case (itb3-lfe:inspect blob)
    (`#(error #(,_status ,detail))
     (log "pipeline initialised: profile=~s blob=~B bytes (inspect: ~ts)"
          (list profile (byte_size blob) detail)))
    (`#(ok ,record)
     (log (++ "pipeline initialised: profile=~s blob=~B bytes hash=~s key-bits=~B "
              "nonce-bits=~B barrier-fill=~B chunk-size=~B mac=~s parallax=~s wrapper=~s~s~s")
          (list profile (byte_size blob)
                (record-str record #"hash") (record-int record #"keybits")
                (record-int record #"nonce_bits") (record-int record #"barrier_fill")
                (record-int record #"chunk") (record-str record #"mac")
                (on-off (record-bool record #"parallax"))
                (on-off (record-bool record #"wrapper"))
                (if (=:= (record-int record #"container_mode") 2) " container-mode=2" "")
                (case (record-str record #"drbg")
                  ("-" "")
                  (drbg (++ " drbg=" drbg))))))))

(defun record-int (record key)
  (let ((v (maps:get key record 0)))
    (if (is_integer v) v 0)))

(defun record-str (record key)
  (let ((v (maps:get key record #"")))
    (cond ((=:= v #"") "-")
          ((is_binary v) (unicode:characters_to_list v))
          ('true "-"))))

(defun record-bool (record key)
  (=:= (maps:get key record 'false) 'true))

;;; ------------------------------------------------------------------
;;; Signals
;;; ------------------------------------------------------------------

;; Graceful stop. A termination signal sets the run's stop request,
;; which every worker checks before starting an iteration, so the
;; signal interrupts nothing mid-call — the in-flight encrypt /
;; decrypt / compare completes, the worker returns, and the partial
;; summary prints with the verdict the completed iterations earned.
;; The emulator's own handler is removed first: it halts the node on
;; SIGTERM, which would end the run before the summary.
;;
;; LFE-specific. SIGINT never reaches BEAM code: the emulator's break
;; handler owns it below the signal server, and os:set_signal/2 does
;; not accept it at all. The launcher closes that gap by trapping the
;; interrupt itself and sending the emulator a termination signal,
;; which arrives here.
(defun install-signals (flags)
  (gen_event:delete_handler 'erl_signal_server 'erl_signal_handler '())
  (gen_event:add_handler 'erl_signal_server 'loop-main (list flags))
  (os:set_signal 'sigterm 'handle)
  (os:set_signal 'sigquit 'handle)
  'ok)

(defun init (args)
  `#(ok ,(car args)))

(defun handle_event (signal flags)
  (if (orelse (=:= signal 'sigterm) (=:= signal 'sigquit))
    (loop-state:request-stop flags))
  `#(ok ,flags))

(defun handle_call (_request flags) `#(ok ok ,flags))
(defun handle_info (_info flags) `#(ok ,flags))
(defun terminate (_reason _flags) 'ok)
(defun code_change (_old flags _extra) `#(ok ,flags))

;;; ------------------------------------------------------------------
;;; Run
;;; ------------------------------------------------------------------

(defun start ()
  (install-closed-pipe-filter)
  (erlang:halt (run (init:get_plain_arguments)) (list #(flush true))))

(defun run (args)
  (case (parse-argv args)
    ('help (usage) 0)
    ('error 2)
    (`#(ok ,values)
     (case (resolve values)
       ('error 2)
       (`#(ok ,cfg) (shape-runtime cfg))))))

;; Runtime shaping. A long run under allocation churn grows the Go
;; heap inside the shared library without bound unless a soft limit
;; paces the collector, so a limit is always in force: an explicit
;; --memlimit is set as given, and auto caps the heap only when the
;; runtime reports no limit at all (a limit already installed from the
;; environment is left standing). The GC percentage and GOMAXPROCS are
;; set only when their flag is non-zero — a zero flag skips the setter
;; rather than calling it with zero, because zero is a real value to
;; the GC-percent setter, and a call would clobber whatever the
;; environment installed. All of it lands before any Pipeline exists
;; so the baselines are taken under the shaped runtime.
(defun shape-runtime (cfg0)
  (if (maps:get 'memlimit-auto cfg0)
    (if (=:= (itb3-lfe:set-memory-limit -1) #x7FFFFFFFFFFFFFFF)
      (itb3-lfe:set-memory-limit (maps:get 'memlimit cfg0)))
    (itb3-lfe:set-memory-limit (maps:get 'memlimit cfg0)))
  (let ((cfg (maps:put 'memlimit (itb3-lfe:set-memory-limit -1) cfg0)))
    (if (> (maps:get 'gogc cfg) 0)
      (itb3-lfe:set-gc-percent (maps:get 'gogc cfg)))
    (if (> (maps:get 'gomaxprocs cfg) 0)
      (itb3-lfe:set-gomaxprocs (maps:get 'gomaxprocs cfg)))
    (start-lines cfg)
    (build cfg)))

(defun start-lines (cfg)
  (log (++ "start: duration=~s iterations=~B goroutines=~B workers=~B concurrency=~s "
           "shape=~s hash=~s mac=~s payload=~s memlimit=~s parallax=~s wrapper=~s")
       (list (loop-size:human-duration (maps:get 'duration-ns cfg))
             (maps:get 'iterations cfg) (maps:get 'workers-requested cfg)
             (maps:get 'workers cfg) (CONCURRENCY)
             (loop-worker:shape-name (maps:get 'shape cfg))
             (maps:get 'hash cfg) (maps:get 'mac cfg)
             (loop-size:human-bytes (maps:get 'payload cfg))
             (loop-size:human-bytes (maps:get 'memlimit cfg))
             (on-off (maps:get 'parallax cfg)) (on-off (maps:get 'wrapper cfg))))
  (log (++ "overrides: profile=\"~s\" key-bits=~B nonce-bits=~B chunk-size=~s "
           "barrier-fill=~B gomaxprocs=~B rekey-every=~B blob-cycle-every=~B "
           "payload-mode=~s seed=~B json-output=~s~s~s")
       (list (maps:get 'profile cfg) (maps:get 'key-bits cfg) (maps:get 'nonce-bits cfg)
             (loop-size:human-bytes (maps:get 'chunk-size cfg))
             (maps:get 'barrier-fill cfg) (maps:get 'gomaxprocs cfg)
             (maps:get 'rekey-every cfg) (maps:get 'blob-cycle-every cfg)
             (loop-payload:mode-name (maps:get 'payload-mode cfg))
             (maps:get 'seed cfg)
             (if (maps:get 'json-output cfg) "true" "false")
             (case (maps:get 'blob-mode cfg)
               (1 "")
               (mode (++ " blob-mode=" (integer_to_list mode))))
             (case (maps:get 'drbg cfg)
               ("" "")
               (drbg (++ " drbg=" drbg)))))
  (log "policy: microbatch-tiers=~s hashpool-starters=~s"
       (list (policy-label "ITB_MICROBATCH_TIERS") (policy-label "ITB_HASHPOOL_STARTERS"))))

;; Pipeline construction — one shared handle per exercised shape.
;; stream and stream_one_shot share the streaming handle.
(defun build (cfg)
  (let* ((named (maps:get 'profile cfg))
         (stream-profile (if (=:= named "") (DEFAULT-STREAM-PROFILE) named))
         (msg-profile (if (=:= named "") (DEFAULT-MESSAGE-PROFILE) named))
         (shape (maps:get 'shape cfg))
         (want-stream (lists:member shape '(stream stream_one_shot both)))
         (want-msg (lists:member shape '(message both))))
    (case (build-optional want-stream cfg stream-profile)
      ('error 1)
      (`#(ok ,stream-pipe ,stream-blob)
       (case (build-optional want-msg cfg msg-profile)
         ('error 1)
         (`#(ok ,msg-pipe ,msg-blob)
          (launch cfg `#(,stream-profile ,stream-pipe ,stream-blob)
                  `#(,msg-profile ,msg-pipe ,msg-blob))))))))

(defun build-optional (want cfg profile)
  (if want (build-pipeline cfg profile) #(ok undefined #"")))

(defun launch (cfg stream-side msg-side)
  (let* ((`#(,stream-profile ,stream-pipe ,stream-blob) stream-side)
         (`#(,msg-profile ,msg-pipe ,msg-blob) msg-side)
         (flags (loop-state:new-flags))
         (counts (loop-state:new-counts))
         (state (loop-state:start stream-pipe msg-pipe stream-blob msg-blob))
         (run (map 'cfg cfg 'state state 'flags flags 'counts counts
                   'stream-profile stream-profile 'msg-profile msg-profile))
         (_ (install-signals flags))
         (workers-n (maps:get 'workers cfg))
         ;; Allocation posture. Per-worker plaintexts are built once
         ;; and held for the whole run (rotating mode rebuilds them per
         ;; iteration); the pump accumulator is a per-iteration iolist
         ;; the collector reclaims, and the message and one-shot
         ;; outputs are binaries the binding returns per call. Under
         ;; the default fixed CSPRNG mode every worker's buffer is
         ;; distinct, so cross-worker data crossover is detectable;
         ;; pattern modes trade that property for content edge-case
         ;; coverage.
         (plaintexts
          (lists:map (lambda (i)
                       (element 1 (loop-payload:fill
                                   (maps:get 'payload-mode cfg)
                                   (=/= (maps:get 'seed cfg) 0)
                                   (loop-payload:seed-worker (maps:get 'seed cfg) i)
                                   (maps:get 'payload cfg))))
                     (lists:seq 0 (- workers-n 1))))
         ;; Warmup barrier. Every worker runs one iteration and waits;
         ;; the clock starts only once all of them have paid their
         ;; first-call costs (pool warm-up, lazy kernel dispatch, page
         ;; faults on the payload buffers), and the RSS and pool
         ;; baselines taken here describe a process that has already
         ;; run the whole cipher path once per worker.
         (warmup-start (loop-size:now-ns))
         (workers (lists:map
                   (lambda (i)
                     (let ((pid (loop-worker:start run i (lists:nth (+ i 1) plaintexts)
                                                   (self))))
                       (erlang:monitor 'process pid)
                       `#(,pid ,i)))
                   (lists:seq 0 (- workers-n 1))))
         (_ (await-warmup workers))
         (`#(,rss-warmup ,rss-peak0) (loop-summary:read-rss))
         (pool-warmup (loop-summary:pool-snapshot))
         (warmup-ns (- (loop-size:now-ns) warmup-start))
         (_ (log "warmup: ~B workers x 1 iter completed in ~s (baseline rss=~s)"
                 (list workers-n
                       (loop-size:human-duration
                        (* (div (+ warmup-ns 50000000) 100000000) 100000000))
                       (loop-size:human-bytes rss-warmup))))
         ;; Open the gate; in duration mode a timer asks the workers to
         ;; stop once the deadline passes.
         (start-ns (loop-size:now-ns))
         (_ (lists:foreach (lambda (e) (! (element 1 e) 'release)) workers))
         (timer (if (=:= (maps:get 'iterations cfg) 0)
                  (erlang:send_after (div (maps:get 'duration-ns cfg) 1000000)
                                     (self) 'deadline)
                  'undefined))
         (stats (collect workers flags '()))
         (_ (if (=/= timer 'undefined) (erlang:cancel_timer timer)))
         (finish-ns (lists:max (cons start-ns
                                     (lists:map (lambda (s) (maps:get 'finish-ns s)) stats))))
         (elapsed-ns (- finish-ns start-ns))
         (`#(,rss-final ,rss-peak) (loop-summary:read-rss))
         (pool-steady (loop-summary:pool-snapshot))
         (_ (write-memprofile (maps:get 'memprofile cfg)))
         (ordered (lists:sort (lambda (a b) (=< (maps:get 'id a) (maps:get 'id b))) stats))
         (rc (loop-summary:final run ordered elapsed-ns
                                 `#(,rss-warmup ,(max rss-peak0 rss-peak) ,rss-final)
                                 `#(,pool-warmup ,pool-steady)))
         (`#(,live-stream ,live-msg) (loop-state:handles state)))
    (free-pipe live-stream)
    (free-pipe live-msg)
    (loop-state:stop-process state)
    rc))

(defun write-memprofile (path)
  (if (=/= path "")
    (case (itb3-lfe:write-heap-profile path)
      ('ok (log "memprofile: heap profile written to ~s" (list path)))
      (`#(error #(,_status ,detail)) (err "memprofile: ~ts" (list detail))))
    'ok))

(defun free-pipe (pipe)
  (if (=/= pipe 'undefined) (itb3-lfe:free pipe) 'ok))

;; Every worker reports its warmup iteration before the clock starts.
;; A worker that died instead of reporting is not waited for: the
;; monitor turns its exit into the same arrival, and the run goes on
;; to the summary that will carry the failure.
(defun await-warmup (workers)
  (if (=:= workers '())
    'ok
    (receive
      (`#(warmup-done ,pid) (await-warmup (lists:keydelete pid 1 workers)))
      (`#(DOWN ,_mref process ,pid ,reason)
       (! (self) `#(worker-died ,pid ,reason))
       (await-warmup (lists:keydelete pid 1 workers))))))

;; Waits for every worker, turning the duration deadline into the stop
;; request the workers poll. A worker that dies without reporting is
;; recorded as a worker error so the run cannot hang on it.
(defun collect (workers flags acc)
  (if (=:= workers '())
    acc
    (receive
      ('deadline
       (loop-state:request-stop flags)
       (collect workers flags acc))
      (`#(worker-done ,pid ,stats)
       (flush-down pid)
       (collect (lists:keydelete pid 1 workers) flags (cons stats acc)))
      (`#(worker-died ,pid ,reason) (collect-death workers flags acc pid reason))
      (`#(DOWN ,_mref process ,pid ,reason) (collect-death workers flags acc pid reason)))))

(defun collect-death (workers flags acc pid reason)
  (case (lists:keyfind pid 1 workers)
    ('false (collect workers flags acc))
    (entry
     (loop-state:request-stop flags)
     (collect (lists:keydelete pid 1 workers) flags
              (cons (died (element 2 entry) pid reason) acc)))))

(defun died (id pid reason)
  (map 'id id 'iters 0 'bytes-enc 0 'bytes-dec 0 'nanos-enc 0 'nanos-dec 0
       'finish-ns (loop-size:now-ns) 'failed 'true
       'error (loop-size:fmt "g~B exited: ~p ~p" (list id pid reason))))

(defun flush-down (pid)
  (receive
    (`#(DOWN ,_mref process ,p ,_reason) (when (=:= p pid)) 'ok)
    (after 0 'ok)))
