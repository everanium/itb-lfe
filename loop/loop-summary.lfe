;;;; The final summary in both renderings, and the two
;;;; measurements it folds in that are not per-worker counters: the
;;;; process resident set and the shared library's pool counters.

(defmodule loop-summary
  (export (read-rss 0) (pool-snapshot 0) (final 5)))

(defmacro CONCURRENCY () "shared-handle")

;;; ------------------------------------------------------------------
;;; Resident set
;;; ------------------------------------------------------------------

;; The process's current resident set and its high-water mark in
;; bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
;; Both are zero on a platform without that file; the figures are
;; informational and never enter the verdict.
(defun read-rss ()
  (case (file:read_file "/proc/self/status")
    (`#(ok ,bin)
     (lists:foldl #'status-line/2 #(0 0) (binary:split bin #"\n" '(global))))
    (_ #(0 0))))

(defun status-line (line acc)
  (let ((`#(,cur ,peak) acc))
    (cond ((=:= (binary_part line 0 (min 6 (byte_size line))) #"VmRSS:")
           `#(,(status-kb line) ,peak))
          ((=:= (binary_part line 0 (min 6 (byte_size line))) #"VmHWM:")
           `#(,cur ,(status-kb line)))
          ('true acc))))

(defun status-kb (line)
  (let ((rest (binary_part line 6 (- (byte_size line) 6))))
    (case (string:to_integer (string:trim (unicode:characters_to_list rest)))
      (`#(,kb ,_) (when (is_integer kb)) (* kb 1024))
      (_ 0))))

;;; ------------------------------------------------------------------
;;; Pool counters
;;; ------------------------------------------------------------------

;; Pool counters. The shared library keeps process-wide monotonic
;; totals at every pool checkout of its cipher core: per hash-array
;; tier the starter width, checkouts, constructor misses, regrow
;; replacements and bytes allocated; for the scratch byte pool and the
;; parallax chunk pool the checkouts, constructor misses, regrows and
;; regrow bytes. Two snapshots bracketing the main loop are
;; differenced into per-run hit / miss figures that tell whether a
;; pool keeps its items warm between calls or evicts them across GC
;; cycles. The slot layout is read from the library: slot 0 carries
;; the tier count T, tier i occupies the five slots at 1 + 5*i, and
;; the two byte pools occupy the eight slots at 1 + 5*T; the vector is
;; sized by the binding's length query, never by a constant.
(defun pool-snapshot ()
  (case (itb3-lfe:pool-stats)
    (`#(ok ,slots) slots)
    (_ '())))

(defun zero-pool ()
  (map 'get 0 'new 0 'regrow 0 'regrow-bytes 0))

(defun pool-diff (warmup steady)
  (if (orelse (< (length warmup) 9) (< (length steady) 9))
    `#(() ,(zero-pool) ,(zero-pool))
    (let* ((w (list_to_tuple warmup))
           (s (list_to_tuple steady))
           (tiers (element 1 s)))
      (if (orelse (< tiers 0) (> (+ (* 5 tiers) 9) (tuple_size s)))
        `#(() ,(zero-pool) ,(zero-pool))
        (let* ((tier-list
                (lists:map
                 (lambda (i)
                   (map 'tier i
                        'starter (element (+ 2 (* 5 i)) s)
                        'get (- (element (+ 3 (* 5 i)) s) (element (+ 3 (* 5 i)) w))
                        'new (- (element (+ 4 (* 5 i)) s) (element (+ 4 (* 5 i)) w))
                        'regrow (- (element (+ 5 (* 5 i)) s) (element (+ 5 (* 5 i)) w))
                        'new-bytes (- (element (+ 6 (* 5 i)) s) (element (+ 6 (* 5 i)) w))))
                 (lists:seq 0 (- tiers 1))))
               (tail (+ 1 (* 5 tiers))))
          `#(,(lists:filter (lambda (t) (=/= (maps:get 'starter t) 0)) tier-list)
             ,(byte-pool w s tail)
             ,(byte-pool w s (+ tail 4))))))))

(defun byte-pool (w s base)
  (map 'get (- (element (+ base 1) s) (element (+ base 1) w))
       'new (- (element (+ base 2) s) (element (+ base 2) w))
       'regrow (- (element (+ base 3) s) (element (+ base 3) w))
       'regrow-bytes (- (element (+ base 4) s) (element (+ base 4) w))))

;; Misses over checkouts as a percentage; zero when nothing was
;; checked out.
(defun miss-percent (miss get)
  (if (=< get 0) 0.0 (/ (* 100.0 miss) get)))

;;; ------------------------------------------------------------------
;;; Summary
;;; ------------------------------------------------------------------

;; Output contract. Both renderings are shared with the Go harness and
;; every other binding's loop utility field for field: the same lines
;; in the same order, the same keys in the same order, floats with a
;; fixed number of decimals so the JSON is byte-identical across
;; implementations. The Go harness alone adds its runtime-internal
;; lines after rss: and its runtime-internal keys after
;; parallax_chunk_pool; nothing here reproduces them because nothing
;; they read is reachable through the binding.
(defun final (run stats elapsed-ns rss pools)
  (let* ((cfg (maps:get 'cfg run))
         (`#(,rss-warmup ,rss-peak ,rss-final) rss)
         (`#(,pool-warmup ,pool-steady) pools)
         (total-iters (sum stats 'iters))
         (total-enc (sum stats 'bytes-enc))
         (total-dec (sum stats 'bytes-dec))
         (nanos-enc (sum stats 'nanos-enc))
         (nanos-dec (sum stats 'nanos-dec))
         (errors (lists:map (lambda (s) (maps:get 'error s))
                            (lists:filter (lambda (s) (maps:get 'failed s)) stats)))
         (workers (maps:get 'workers cfg))
         ;; Throughput. Per-direction throughput divides the sum of
         ;; every worker's wall time in that direction by the worker
         ;; count — the equivalent single-stream wall time under N-way
         ;; concurrency — so each direction reports the aggregate rate
         ;; it sustained rather than collapsing to combined/2 (every
         ;; iteration moves equal encrypt and decrypt bytes, so a
         ;; total-elapsed denominator would give both directions the
         ;; same figure). The combined rate keeps total elapsed as the
         ;; one-glance overall figure.
         (avg-enc (if (> nanos-enc 0) (div nanos-enc workers) 0))
         (avg-dec (if (> nanos-dec 0) (div nanos-dec workers) 0))
         (rss-delta (- rss-final rss-warmup))
         (rss-growth (if (> rss-warmup 0) (/ (* 100.0 rss-delta) rss-warmup) 0.0))
         (`#(,tiers ,buf ,chunk) (pool-diff pool-warmup pool-steady))
         (pass (=:= errors '()))
         (`#(,stream-pipe ,msg-pipe) (loop-state:handles (maps:get 'state run)))
         (f (map 'total-iters total-iters 'total-enc total-enc 'total-dec total-dec
                 'avg-enc avg-enc 'avg-dec avg-dec 'elapsed elapsed-ns
                 'errors errors 'pass pass
                 'rekeys (loop-state:count (maps:get 'counts run) 'rekeys)
                 'cycles (loop-state:count (maps:get 'counts run) 'blob-cycles)
                 'gomaxprocs (itb3-lfe:set-gomaxprocs 0)
                 'stream-profile (if (=:= stream-pipe 'undefined) ""
                                   (maps:get 'stream-profile run))
                 'msg-profile (if (=:= msg-pipe 'undefined) ""
                                (maps:get 'msg-profile run))
                 'rss-warmup rss-warmup 'rss-peak rss-peak 'rss-final rss-final
                 'rss-delta rss-delta 'rss-growth rss-growth
                 'tiers tiers 'buf buf 'chunk chunk 'stats stats)))
    (if (maps:get 'json-output cfg) (json cfg f) (human cfg f))
    (if pass 0 1)))

(defun sum (stats key)
  (lists:sum (lists:map (lambda (s) (maps:get key s)) stats)))

;;; ------------------------------------------------------------------

(defun json (cfg f)
  (loop-main:emit
   'standard_io
   (list
    "{\"duration_seconds\":" (f3 (/ (maps:get 'elapsed f) 1.0e9))
    ",\"iterations\":" (i (maps:get 'total-iters f))
    ",\"per_worker_iterations\":["
    (lists:join "," (lists:map (lambda (s) (i (maps:get 'iters s))) (maps:get 'stats f))) "]"
    ",\"bytes_encrypted\":" (i (maps:get 'total-enc f))
    ",\"bytes_decrypted\":" (i (maps:get 'total-dec f))
    ",\"encrypt_mb_per_sec\":"
    (f1 (loop-size:mb-per-sec (maps:get 'total-enc f) (maps:get 'avg-enc f)))
    ",\"decrypt_mb_per_sec\":"
    (f1 (loop-size:mb-per-sec (maps:get 'total-dec f) (maps:get 'avg-dec f)))
    ",\"combined_mb_per_sec\":"
    (f1 (loop-size:mb-per-sec (+ (maps:get 'total-enc f) (maps:get 'total-dec f))
                              (maps:get 'elapsed f)))
    ",\"rekeys\":" (i (maps:get 'rekeys f))
    ",\"blob_cycles\":" (i (maps:get 'cycles f))
    ",\"worker_errors\":["
    (lists:join "," (lists:map #'jstr/1 (maps:get 'errors f))) "]"
    ",\"verdict\":" (jstr (if (maps:get 'pass f) "PASS" "FAIL"))
    ",\"shape\":" (jstr (loop-worker:shape-name (maps:get 'shape cfg)))
    ",\"stream_profile\":" (jstr (maps:get 'stream-profile f))
    ",\"message_profile\":" (jstr (maps:get 'msg-profile f))
    ",\"hash\":" (jstr (maps:get 'hash cfg))
    ",\"mac\":" (jstr (maps:get 'mac cfg))
    ",\"payload_bytes\":" (i (maps:get 'payload cfg))
    ",\"payload_mode\":" (jstr (loop-payload:mode-name (maps:get 'payload-mode cfg)))
    ",\"seed\":" (i (maps:get 'seed cfg))
    ",\"key_bits\":" (i (maps:get 'key-bits cfg))
    ",\"nonce_bits\":" (i (maps:get 'nonce-bits cfg))
    ",\"blob_mode\":" (i (maps:get 'blob-mode cfg))
    ",\"drbg\":" (jstr (maps:get 'drbg cfg))
    ",\"drbg_auto_tier\":" (jstr (drbg-auto-tier))
    ",\"chunk_size_bytes\":" (i (maps:get 'chunk-size cfg))
    ",\"barrier_fill\":" (i (maps:get 'barrier-fill cfg))
    ",\"parallax\":" (jstr (loop-main:on-off (maps:get 'parallax cfg)))
    ",\"wrapper\":" (jstr (loop-main:on-off (maps:get 'wrapper cfg)))
    ",\"goroutines_requested\":" (i (maps:get 'workers-requested cfg))
    ",\"goroutines\":" (i (maps:get 'workers cfg))
    ",\"concurrency\":" (jstr (CONCURRENCY))
    ",\"gogc\":" (jstr (integer_to_list (effective-gogc (maps:get 'gogc cfg))))
    ",\"memlimit_bytes\":" (i (maps:get 'memlimit cfg))
    ",\"gomaxprocs\":" (i (maps:get 'gomaxprocs f))
    ",\"microbatch_tiers\":" (jstr (loop-main:policy-label "ITB_MICROBATCH_TIERS"))
    ",\"hashpool_starters\":" (jstr (loop-main:policy-label "ITB_HASHPOOL_STARTERS"))
    ",\"rss_warmup_bytes\":" (i (maps:get 'rss-warmup f))
    ",\"rss_peak_bytes\":" (i (maps:get 'rss-peak f))
    ",\"rss_final_bytes\":" (i (maps:get 'rss-final f))
    ",\"rss_growth_percent\":" (f2 (maps:get 'rss-growth f))
    ",\"hash_pool_tiers\":["
    (lists:join "," (lists:map #'json-tier/1 (maps:get 'tiers f))) "]"
    ",\"buf_pool\":" (json-byte-pool (maps:get 'buf f))
    ",\"parallax_chunk_pool\":" (json-byte-pool (maps:get 'chunk f))
    "}\n")))

(defun json-tier (t)
  (list "{\"tier\":" (i (maps:get 'tier t))
        ",\"starter\":" (i (maps:get 'starter t))
        ",\"get\":" (i (maps:get 'get t))
        ",\"new\":" (i (maps:get 'new t))
        ",\"regrow\":" (i (maps:get 'regrow t))
        ",\"new_bytes\":" (i (maps:get 'new-bytes t))
        ",\"miss_percent\":"
        (f2 (miss-percent (+ (maps:get 'new t) (maps:get 'regrow t)) (maps:get 'get t)))
        "}"))

(defun json-byte-pool (p)
  (list "{\"get\":" (i (maps:get 'get p))
        ",\"new\":" (i (maps:get 'new p))
        ",\"regrow\":" (i (maps:get 'regrow p))
        ",\"regrow_bytes\":" (i (maps:get 'regrow-bytes p))
        ",\"miss_percent\":" (f2 (miss-percent (maps:get 'regrow p) (maps:get 'get p)))
        "}"))

(defun i (n) (integer_to_list n))

(defun f1 (v) (loop-size:fmt "~.1f" (list (* v 1.0))))
(defun f2 (v) (loop-size:fmt "~.2f" (list (* v 1.0))))
(defun f3 (v) (loop-size:fmt "~.3f" (list (* v 1.0))))

;; The fill cipher the auto DRBG tier selected on this host; empty
;; when the library cannot report it.
(defun drbg-auto-tier ()
  (case (itb3-lfe:drbg-auto-tier)
    (`#(ok ,tier) tier)
    (`#(error ,_) "")))

;; One JSON string literal with the escapes JSON requires.
(defun jstr (s)
  (list #\" (lists:map #'json-char/1 (unicode:characters_to_list
                                      (erlang:iolist_to_binary s))) #\"))

(defun json-char (c)
  (cond ((=:= c #\") "\\\"")
        ((=:= c #\\) "\\\\")
        ((=:= c 10) "\\n")
        ((=:= c 13) "\\r")
        ((=:= c 9) "\\t")
        ((< c 32) (loop-size:fmt "\\u~4.16.0b" (list c)))
        ('true c)))

;; The effective GC percentage as the runtime reports it: the query
;; form of the setter (a set-and-restore round trip inside the
;; library) so the field is the same whether the value came from the
;; flag, the environment, or the runtime default.
(defun effective-gogc (flag)
  (if (> flag 0) flag (itb3-lfe:set-gc-percent -1)))

;;; ------------------------------------------------------------------

(defun human (cfg f)
  (loop-main:log "=== FINAL ===" '())
  (loop-main:log "  duration: ~s"
                 (list (loop-size:human-duration
                        (* (div (+ (maps:get 'elapsed f) 500000) 1000000) 1000000))))
  (loop-main:log "  iterations: ~s = ~B total"
                 (list (lists:join " + " (lists:map (lambda (s) (integer_to_list (maps:get 'iters s)))
                                                    (maps:get 'stats f)))
                       (maps:get 'total-iters f)))
  (loop-main:log "  throughput: encrypt ~s, decrypt ~s, combined ~s"
                 (list (loop-size:human-rate (maps:get 'total-enc f) (maps:get 'avg-enc f))
                       (loop-size:human-rate (maps:get 'total-dec f) (maps:get 'avg-dec f))
                       (loop-size:human-rate (+ (maps:get 'total-enc f) (maps:get 'total-dec f))
                                             (maps:get 'elapsed f))))
  (loop-main:log "  bytes: ~s encrypted, ~s decrypted"
                 (list (loop-size:human-bytes (maps:get 'total-enc f))
                       (loop-size:human-bytes (maps:get 'total-dec f))))
  (loop-main:log "  data integrity: ~B/~B PASS"
                 (list (maps:get 'total-iters f) (maps:get 'total-iters f)))
  (loop-main:log "  concurrency: ~s, workers ~B (requested ~B)"
                 (list (CONCURRENCY) (maps:get 'workers cfg) (maps:get 'workers-requested cfg)))
  (loop-main:log "  rss: warmup ~s, peak ~s, final ~s (delta ~s, ~s% growth)"
                 (list (loop-size:human-bytes (maps:get 'rss-warmup f))
                       (loop-size:human-bytes (maps:get 'rss-peak f))
                       (loop-size:human-bytes (maps:get 'rss-final f))
                       (loop-size:human-bytes-signed (maps:get 'rss-delta f))
                       (f1 (maps:get 'rss-growth f))))
  (lists:foreach #'human-tier/1 (maps:get 'tiers f))
  (human-byte-pool "  buf pool" (maps:get 'buf f))
  (human-byte-pool "  parallax chunk pool" (maps:get 'chunk f))
  (if (> (maps:get 'rekeys f) 0)
    (loop-main:log "  rekeys: ~B" (list (maps:get 'rekeys f))))
  (if (> (maps:get 'cycles f) 0)
    (loop-main:log "  blob cycles: ~B" (list (maps:get 'cycles f))))
  (lists:foreach (lambda (e) (loop-main:log "  ERROR: ~s" (list e))) (maps:get 'errors f))
  (if (maps:get 'pass f)
    (loop-main:log "  verdict: PASS" '())
    (loop-main:log "  verdict: FAIL (errors=~B)" (list (length (maps:get 'errors f))))))

(defun human-tier (t)
  (loop-main:log
   (++ "  hash pool tier ~B (starter ~B): get ~B, miss ~B (new ~B + regrow ~B), "
       "miss ~s%, ~s allocated")
   (list (maps:get 'tier t) (maps:get 'starter t) (maps:get 'get t)
         (+ (maps:get 'new t) (maps:get 'regrow t))
         (maps:get 'new t) (maps:get 'regrow t)
         (f2 (miss-percent (+ (maps:get 'new t) (maps:get 'regrow t)) (maps:get 'get t)))
         (loop-size:human-bytes (maps:get 'new-bytes t)))))

(defun human-byte-pool (label p)
  (loop-main:log "~s: get ~B, regrow ~B (of which fresh ~B), miss ~s%, ~s regrown"
                 (list label (maps:get 'get p) (maps:get 'regrow p) (maps:get 'new p)
                       (f2 (miss-percent (maps:get 'regrow p) (maps:get 'get p)))
                       (loop-size:human-bytes (maps:get 'regrow-bytes p)))))
