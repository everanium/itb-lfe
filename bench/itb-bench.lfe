;;;; itb-bench — Message + Stream throughput micro-benches for the
;;;; LFE binding at 1 MiB / 16 MiB / 64 MiB, ported from the Erlang
;;;; binding's bench_message.erl / bench_stream.erl.
;;;;
;;;; message: encrypt-message throughput (Single Message profile).
;;;; stream:  stream-pump throughput (Streaming Non-AEAD profile) —
;;;;          each iteration runs a full incremental session (begin
;;;;          -> write 1 MiB slices, draining the spool after each
;;;;          write -> end -> drain until finished -> free).
;;;;
;;;; Env-var overrides (defaults match the root Go BENCH3.md pin so
;;;; the numbers are directly comparable):
;;;;
;;;;   ITB_PROFILE        singlemsg-triple-nomac-v1 /
;;;;                      streaming-noaead-triple-v1
;;;;   ITB_INNER_HASH     areion512
;;;;   ITB_KEY_BITS       1024
;;;;   ITB_NONCE_BITS     512
;;;;   ITB_WITH_PARALLAX  false
;;;;   ITB_WITH_WRAPPER   false
;;;;   ITB_BENCH_MIN_SEC  5
;;;;
;;;; Invocation (from bindings/lfe, after ./build.sh; run_bench.sh
;;;; wraps this):
;;;;   erl -noshell -pa _build/default/checkouts/itb/ebin \
;;;;       -pa _build/default/lib/libitb3_lfe/ebin -pa bench \
;;;;       -run itb-bench main message -run init stop

(defmodule itb-bench
  (export (main 1)))

(defmacro MIN-ITERS () 3)
(defmacro PUMP-BUF () `,(bsl 1 20))

(defun main
  (('("message")) (run-message))
  (('("stream")) (run-stream))
  (('("stream_one_shot")) (run-stream-one-shot))
  (('("all")) (run-message) (run-stream) (run-stream-one-shot))
  ((_)
    (io:format 'standard_error
               "usage: itb-bench [message|stream|stream_one_shot|all]~n"
               '())
    (erlang:halt 2)))

;;; ------------------------------------------------------------------
;;; Shapes
;;; ------------------------------------------------------------------

(defun run-message ()
  (cap-go-runtime)
  (let* ((profile (env "ITB_PROFILE" "singlemsg-triple-nomac-v1"))
         (`#(ok ,pipe) (itb3-lfe:init (list_to_binary profile)
                                     (bench-opts))))
    (header)
    (lists:foreach
      (lambda (size)
        ;; CSPRNG-fill so plaintext content matches the root Go bench
        ;; (crypto/rand). Not in the timing loop.
        (let ((plain (crypto:strong_rand_bytes size)))
          (bench-case "message" size
            (lambda ()
              (let ((`#(ok ,_wire) (itb3-lfe:encrypt-message pipe plain)))
                'ok)))
          ;; Pre-encrypt one wire outside the decrypt timing loop.
          (let ((`#(ok ,dec-wire) (itb3-lfe:encrypt-message pipe plain)))
            (bench-case "message-dec" size
              (lambda ()
                (let ((`#(ok ,_p) (itb3-lfe:decrypt-message pipe dec-wire)))
                  'ok))))))
      (list (bsl 1 20) (bsl 16 20) (bsl 64 20)))
    (let ((`ok (itb3-lfe:free pipe)))
      'ok)))

(defun run-stream ()
  (cap-go-runtime)
  (let* ((profile (env "ITB_PROFILE" "streaming-noaead-triple-v1"))
         (`#(ok ,pipe) (itb3-lfe:init (list_to_binary profile)
                                     (bench-opts))))
    (header)
    (lists:foreach
      (lambda (size)
        (let ((plain (crypto:strong_rand_bytes size)))
          (bench-case "stream_pump" size
            (lambda () (pump pipe plain)))
          ;; Pre-encrypt one wire outside the decrypt timing loop.
          (let ((dec-wire (pump-all pipe plain)))
            (bench-case "stream_pump-dec" size
              (lambda () (pump-dec pipe dec-wire))))))
      (list (bsl 1 20) (bsl 16 20) (bsl 64 20)))
    (let ((`ok (itb3-lfe:free pipe)))
      'ok)))

;; Whole-buffer stream: one FFI round trip through
;; encrypt-stream-one-shot / decrypt-stream-one-shot per iteration.
(defun run-stream-one-shot ()
  (cap-go-runtime)
  (let* ((profile (env "ITB_PROFILE" "streaming-noaead-triple-v1"))
         (`#(ok ,pipe) (itb3-lfe:init (list_to_binary profile)
                                     (bench-opts))))
    (header)
    (lists:foreach
      (lambda (size)
        (let ((plain (crypto:strong_rand_bytes size)))
          (bench-case "stream_one_shot" size
            (lambda ()
              (let ((`#(ok ,_wire)
                      (itb3-lfe:encrypt-stream-one-shot pipe plain)))
                'ok)))
          ;; Pre-encrypt one wire outside the decrypt timing loop.
          (let ((`#(ok ,dec-wire)
                  (itb3-lfe:encrypt-stream-one-shot pipe plain)))
            (bench-case "stream_one_shot-dec" size
              (lambda ()
                (let ((`#(ok ,_p)
                        (itb3-lfe:decrypt-stream-one-shot pipe dec-wire)))
                  'ok))))))
      (list (bsl 1 20) (bsl 16 20) (bsl 64 20)))
    (let ((`ok (itb3-lfe:free pipe)))
      'ok)))

;; Bench-scale allocation churn leaks Go scratch heap unboundedly
;; without a soft memory cap + aggressive GC; the return values
;; report the previous settings, not an error.
(defun cap-go-runtime ()
  (itb3-lfe:set-memory-limit (bsl 4 30)) ;; 4 GiB soft cap
  (itb3-lfe:set-gc-percent 100)           ;; balanced GC
  'ok)

(defun header ()
  (io:format "~-17s ~-8s ~s~n" (list "bench" "size" "mb_per_sec")))

;;; ------------------------------------------------------------------
;;; Pump: full incremental encrypt session over one buffer.
;;; ------------------------------------------------------------------

(defun pump (pipe plain)
  (let* ((`#(ok ,stream) (itb3-lfe:encrypt-stream pipe))
         (`ok (feed stream plain))
         (`ok (itb3-lfe:stream-end stream))
         (`ok (drain stream))
         (`ok (itb3-lfe:stream-free stream)))
    'ok))

(defun feed (stream data)
  (if (=:= data #"")
    'ok
    (let* ((n (erlang:min (byte_size data) (PUMP-BUF)))
           (slice (binary:part data 0 n))
           (rest (binary:part data n (- (byte_size data) n)))
           (`ok (itb3-lfe:stream-write stream slice))
           (`ok (drain-ready stream)))
      (feed stream rest))))

;; A read before end never blocks; drain whatever the chain has
;; produced so far to bound the Go-side spool.
(defun drain-ready (stream)
  (case (itb3-lfe:stream-read stream (PUMP-BUF))
    (`#(ok #"" ,_) 'ok)
    (`#(ok ,_ true) 'ok)
    (`#(ok ,_ false) (drain-ready stream))))

(defun drain (stream)
  (case (itb3-lfe:stream-read stream (PUMP-BUF))
    (`#(ok ,_ true) 'ok)
    (`#(ok ,_ false) (drain stream))))

;; Encrypt whole plain, collecting wire. Uses feed-noread so no
;; encoder-produced bytes are lost to drain-ready's read-and-discard
;; pattern: drain-ready's job in the `pump` shape is to bound the
;; Go-side spool during a throwaway encrypt, so it reads chunks off
;; the spool and drops them. In pump-all the wire needs to be
;; preserved, so any drain-ready call landing after a real encoder
;; chunk has been produced would silently drop that chunk. At small
;; plaintext sizes (single-chunk plaintexts fitting in the 16 MiB
;; DefaultChunkSize) the encoder emits nothing until stream-end and
;; drain-ready during feed is a no-op — but at multi-chunk sizes
;; (64 MiB and above) the encoder produces one output per full chunk
;; consumed, and drain-ready between feed slices can catch and drop
;; those chunks before drain-collect at end sees them.
;;
;; Go core wrapper-nonce batching fix (streams.go +
;; wrapper.NewWrapWriter) closes the earlier wrapper-nonce
;; split-write race so a single-chunk pump-all with plain feed would
;; now produce a wire whose nonce is not stranded, but drain-ready's
;; byte-dropping behaviour remains fundamentally incompatible with
;; wire collection across chunk boundaries.
(defun pump-all (pipe plain)
  (let* ((`#(ok ,stream) (itb3-lfe:encrypt-stream pipe))
         (`ok (feed-noread stream plain))
         (`ok (itb3-lfe:stream-end stream))
         (wire (drain-collect stream '())))
    (itb3-lfe:stream-free stream)
    wire))

(defun feed-noread (stream data)
  (if (=:= data #"")
    'ok
    (let* ((n (erlang:min (byte_size data) (PUMP-BUF)))
           (slice (binary:part data 0 n))
           (rest (binary:part data n (- (byte_size data) n)))
           (`ok (itb3-lfe:stream-write stream slice)))
      (feed-noread stream rest))))

(defun drain-collect (stream acc)
  (case (itb3-lfe:stream-read stream (PUMP-BUF))
    (`#(ok ,chunk true) (erlang:iolist_to_binary (lists:reverse (cons chunk acc))))
    (`#(ok ,chunk false) (drain-collect stream (cons chunk acc)))))

(defun pump-dec (pipe wire)
  (let* ((`#(ok ,stream) (itb3-lfe:decrypt-stream pipe))
         (`ok (feed stream wire))
         (`ok (itb3-lfe:stream-end stream))
         (`ok (drain stream))
         (`ok (itb3-lfe:stream-free stream)))
    'ok))

;;; ------------------------------------------------------------------
;;; Timing loop: one untimed warm-up, then iterate until the
;;; wall-clock budget is spent (with an iteration floor); print one
;;; table row.
;;; ------------------------------------------------------------------

(defun bench-case (name size run)
  (funcall run) ;; warm-up
  (let* ((budget (min-seconds))
         (start (erlang:monotonic_time 'microsecond))
         (iters (loop run start budget 0))
         (elapsed (/ (- (erlang:monotonic_time 'microsecond) start) 1.0e6))
         (mb (/ (* size iters) (* 1024 1024))))
    (io:format "~-17s ~-8s ~.1f~n"
               (list name (size-label size) (/ mb elapsed)))
    'ok))

(defun loop (run start budget iters)
  (funcall run)
  (let ((elapsed (/ (- (erlang:monotonic_time 'microsecond) start) 1.0e6)))
    (if (orelse (< elapsed budget) (< (+ iters 1) (MIN-ITERS)))
      (loop run start budget (+ iters 1))
      (+ iters 1))))

(defun size-label (size)
  (if (>= size (bsl 1 20))
    (++ (integer_to_list (bsr size 20)) " MiB")
    (++ (integer_to_list (bsr size 10)) " KiB")))

(defun min-seconds ()
  (case (os:getenv "ITB_BENCH_MIN_SEC")
    ('false 5.0)
    ("" 5.0)
    (raw
      (case (string:to_float raw)
        (`#(,f ,_) (when (is_float f) (> f 0)) f)
        (_
          (case (string:to_integer raw)
            (`#(,i ,_) (when (is_integer i) (> i 0)) (float i))
            (_ 5.0)))))))

;;; ------------------------------------------------------------------
;;; Bench-shape opts from env (defaults per bindings/BENCH.md).
;;; ------------------------------------------------------------------

(defun bench-opts ()
  (let ((base (list
                (tuple #"nonceBits"
                       (list_to_binary (env "ITB_NONCE_BITS" "512")))
                (tuple #"keyBits"
                       (list_to_binary (env "ITB_KEY_BITS" "1024")))
                (tuple #"withParallax"
                       (flag (env "ITB_WITH_PARALLAX" "false")))
                (tuple #"withWrapper"
                       (flag (env "ITB_WITH_WRAPPER" "false"))))))
    (let ((base1 (case (env "ITB_INNER_HASH" "")
                   ("" base)
                   (hash (cons (tuple #"innerHash" (list_to_binary hash)) base)))))
      (case (env "ITB_MAC_NAME" "")
        ("" base1)
        (mac (cons (tuple #"macName" (list_to_binary mac)) base1))))))

(defun flag
  (("true") #"true")
  (("1") #"true")
  ((_) #"false"))

(defun env (name default)
  (case (os:getenv name)
    ('false default)
    ("" default)
    (value value)))
