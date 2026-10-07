;;;; The worker: its process body (one warmup iteration,
;;;; the warmup barrier, the main loop), one iteration, the session
;;;; pump loop the stream shape drives, and the round-trip comparison
;;;; that decides between a worker error and a data mismatch.

(defmodule loop-worker
  (export (shape-name 1) (parse-shape 1) (start 4)))

;; Largest slice fed to a stream session per write; the drain after
;; every write uses the same bound.
(defmacro PUMP-SLICE () (bsl 1 20))

(defun shape-name
  (('stream) "stream")
  (('message) "message")
  (('stream_one_shot) "stream_one_shot")
  (('both) "both"))

(defun parse-shape
  (("stream") #(ok stream))
  (("message") #(ok message))
  (("stream_one_shot") #(ok stream_one_shot))
  (("both") #(ok both))
  ((_) 'error))

;; Concurrency mode. This binding runs shared-handle: BEAM processes
;; call the NIF beneath the LFE wrapper concurrently on dirty
;; schedulers, and one Pipeline handle serves all of them, which the
;; shared library permits after construction. --goroutines is
;; therefore the process count verbatim and is never clamped. The
;; handles are not captured here: every iteration receives them with
;; its read-lock grant, because a blob reopen replaces them mid-run.
(defun start (run id plaintext parent)
  (let* ((cfg (maps:get 'cfg run))
         (w (map 'id id 'run run 'plaintext plaintext
                 'payload-mode (maps:get 'payload-mode cfg)
                 'seeded (=/= (maps:get 'seed cfg) 0)
                 'rng (loop-payload:seed-worker (maps:get 'seed cfg) id)
                 'iters 0 'bytes-enc 0 'bytes-dec 0
                 'nanos-enc 0 'nanos-dec 0
                 'failed 'false 'error "")))
    (spawn (lambda () (body w parent)))))

;; The worker process body: one warmup iteration, the warmup barrier,
;; then the main loop until a stop is requested or the fixed
;; per-worker iteration budget (warmup included) is spent. A failing
;; warmup still passes both barriers so the launcher never waits on a
;; worker that has already given up.
(defun body (w0 parent)
  ;; Warmup iteration — counted in the totals; its completion feeds
  ;; the post-warmup baselines.
  (let ((w1 (iterate w0 0)))
    (! parent `#(warmup-done ,(self)))
    (receive ('release 'ok))
    (let ((w2 (if (maps:get 'failed w1) w1 (main-loop w1 1))))
      (! parent `#(worker-done ,(self) ,(stats w2 (loop-size:now-ns)))))))

(defun main-loop (w iter)
  (let* ((run (maps:get 'run w))
         (cfg (maps:get 'cfg run))
         (budget (maps:get 'iterations cfg)))
    (if (orelse (andalso (> budget 0) (>= iter budget))
                (loop-state:stop-requested (maps:get 'flags run)))
      w
      (let ((w1 (iterate w iter)))
        (if (maps:get 'failed w1)
          w1
          (case (loop-ops:maintenance run (maps:get 'id w1) iter)
            ('ok (main-loop w1 (+ iter 1)))
            (`#(error ,text) (fail w1 text))))))))

(defun stats (w finish-ns)
  (map 'id (maps:get 'id w)
       'iters (maps:get 'iters w)
       'bytes-enc (maps:get 'bytes-enc w)
       'bytes-dec (maps:get 'bytes-dec w)
       'nanos-enc (maps:get 'nanos-enc w)
       'nanos-dec (maps:get 'nanos-dec w)
       'finish-ns finish-ns
       'failed (maps:get 'failed w)
       'error (maps:get 'error w)))

;; Records the worker's error text (first error wins) and requests a
;; stop of the whole run.
(defun fail (w text)
  (loop-state:request-stop (maps:get 'flags (maps:get 'run w)))
  (if (maps:get 'failed w)
    w
    (maps:put 'error text (maps:put 'failed 'true w))))

;;; ------------------------------------------------------------------
;;; One iteration
;;; ------------------------------------------------------------------

;; One iteration. In order: refill the plaintext under rotating mode;
;; take the read lock; pick the surface; encrypt (timed); decrypt
;; (timed); compare the round-trip with the plaintext; bump the
;; counters; release the lock. The whole round-trip runs under the
;; read lock so handle-mutating maintenance (rekey, blob reopen) never
;; lands between an encrypt and its matching decrypt — maintenance
;; runs after this returns, from the worker loop. The handles arrive
;; with the grant rather than from the worker's own state, because a
;; blob reopen swaps them.
(defun iterate (w0 iter)
  (let ((w (refill w0)))
    (if (maps:get 'failed w)
      w
      (let* ((state (maps:get 'state (maps:get 'run w)))
             (`#(,stream-pipe ,msg-pipe) (loop-state:read-lock state)))
        (try
          (round-trip w iter stream-pipe msg-pipe)
          (case
            (`#(ok ,w1) w1)
            (`#(error ,text) (fail w text)))
          (after (loop-state:read-unlock state)))))))

(defun refill (w)
  (if (=:= (maps:get 'payload-mode w) 'rotating)
    (let ((`#(,buf ,rng) (loop-payload:fill 'rotating (maps:get 'seeded w)
                                            (maps:get 'rng w)
                                            (byte_size (maps:get 'plaintext w)))))
      (maps:put 'rng rng (maps:put 'plaintext buf w)))
    w))

(defun round-trip (w iter stream-pipe msg-pipe)
  (let ((shape (select-shape (maps:get 'cfg (maps:get 'run w)) iter))
        (plain (maps:get 'plaintext w)))
    (case (do-encrypt shape stream-pipe msg-pipe plain)
      (`#(error ,what ,status ,detail)
       `#(error ,(cipher-error w iter shape "encrypt" what status detail)))
      (`#(ok ,wire ,enc-ns)
       (case (do-decrypt shape stream-pipe msg-pipe wire)
         (`#(error ,what ,status ,detail)
          `#(error ,(cipher-error w iter shape "decrypt" what status detail)))
         (`#(ok ,got ,dec-ns)
          (compare w iter shape plain got)
          `#(ok ,(maps:merge w
                   (map 'iters (+ (maps:get 'iters w) 1)
                        'bytes-enc (+ (maps:get 'bytes-enc w) (byte_size plain))
                        'bytes-dec (+ (maps:get 'bytes-dec w) (byte_size got))
                        'nanos-enc (+ (maps:get 'nanos-enc w) enc-ns)
                        'nanos-dec (+ (maps:get 'nanos-dec w) dec-ns))))))))))

;; Shape dispatch. message is one whole-buffer call on the Single
;; Message Pipeline; stream_one_shot is one whole-buffer call on the
;; streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
;; routes to the same one-shot stream entry the Go harness calls by
;; name); stream opens a session on the same streaming Pipeline and
;; drives the chunk loop from here. Under both the three rotate by
;; iteration number so the session path and the whole-buffer path
;; alternate on one handle inside every worker — the cross-path
;; state-reuse hazard this harness exists to catch.
(defun select-shape (cfg iter)
  (let ((shape (maps:get 'shape cfg)))
    (if (=:= shape 'both)
      (case (rem iter 3)
        (0 'stream)
        (1 'message)
        (_ 'stream_one_shot))
      shape)))

(defun do-encrypt
  (('stream stream-pipe _msg plain)
   (timed (lambda () (pump stream-pipe 'encrypt plain))))
  (('stream_one_shot stream-pipe _msg plain)
   (timed (lambda () (one-call (itb3-lfe:encrypt-stream-one-shot stream-pipe plain)))))
  (('message _stream msg-pipe plain)
   (timed (lambda () (one-call (itb3-lfe:encrypt-message msg-pipe plain))))))

(defun do-decrypt
  (('stream stream-pipe _msg wire)
   (timed (lambda () (pump stream-pipe 'decrypt wire))))
  (('stream_one_shot stream-pipe _msg wire)
   (timed (lambda () (one-call (itb3-lfe:decrypt-stream-one-shot stream-pipe wire)))))
  (('message _stream msg-pipe wire)
   (timed (lambda () (one-call (itb3-lfe:decrypt-message msg-pipe wire))))))

(defun timed (fun)
  (let ((t0 (loop-size:now-ns)))
    (case (funcall fun)
      (`#(ok ,out) `#(ok ,out ,(- (loop-size:now-ns) t0)))
      (other other))))

;; A whole-buffer call names itself as the failing call, so the error
;; text carries the direction once rather than twice.
(defun one-call
  ((`#(ok ,out)) `#(ok ,out))
  ((`#(error #(,status ,detail))) `#(error same ,status ,detail)))

;;; ------------------------------------------------------------------
;;; Stream pump
;;; ------------------------------------------------------------------

;; Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
;; and ITB drives the chunk loop internally; the binding's session
;; surface has no reader / writer entry, so the caller drives it: open
;; a session, feed slices of at most 1 MiB, drain whatever the session
;; has produced after every write (a read before end never blocks),
;; end, then drain until the session reports finished (after end, a
;; read on an empty spool blocks until the terminal bytes arrive). The
;; loop is written here rather than delegated to a binding-side pump
;; convenience so it stands in the utility, at the same place, in
;; every language.
(defun pump (pipe direction src)
  (let ((begin (case direction
                 ('encrypt (itb3-lfe:encrypt-stream pipe))
                 ('decrypt (itb3-lfe:decrypt-stream pipe)))))
    (case begin
      (`#(error #(,status ,detail)) `#(error "StreamBegin" ,status ,detail))
      (`#(ok ,session)
       (let ((result (feed session src '())))
         (itb3-lfe:stream-free session)
         result)))))

(defun feed (session src acc)
  (if (=:= (byte_size src) 0)
    (case (itb3-lfe:stream-end session)
      (`#(error #(,status ,detail)) `#(error "StreamEnd" ,status ,detail))
      ('ok (drain-final session acc)))
    (let* ((n (min (byte_size src) (PUMP-SLICE)))
           (slice (binary_part src 0 n))
           (rest (binary_part src n (- (byte_size src) n))))
      (case (itb3-lfe:stream-write session slice)
        (`#(error #(,status ,detail)) `#(error "StreamWrite" ,status ,detail))
        ('ok
         (case (drain-ready session acc)
           (`#(error ,w ,s ,d) `#(error ,w ,s ,d))
           (`#(ok ,acc1) (feed session rest acc1))))))))

(defun drain-ready (session acc)
  (case (itb3-lfe:stream-read session (PUMP-SLICE))
    (`#(error #(,status ,detail)) `#(error "StreamRead" ,status ,detail))
    (`#(ok ,data ,_finished)
     (if (=:= (byte_size data) 0)
       `#(ok ,acc)
       (drain-ready session (cons data acc))))))

(defun drain-final (session acc)
  (case (itb3-lfe:stream-read session (PUMP-SLICE))
    (`#(error #(,status ,detail)) `#(error "StreamRead" ,status ,detail))
    (`#(ok ,data ,finished)
     (if (=:= finished 'true)
       `#(ok ,(erlang:iolist_to_binary (lists:reverse (cons data acc))))
       (drain-final session (cons data acc))))))

;;; ------------------------------------------------------------------
;;; Failure model
;;; ------------------------------------------------------------------

;; Failure model. A cipher call that returns a non-OK status is a
;; worker error: it is recorded, the run is asked to stop, the other
;; workers finish their in-flight iteration, and the error is listed
;; in the summary with the FAIL verdict. A round-trip that returns OK
;; with different bytes is a data mismatch: the process terminates
;; here, without summary or cleanup, because the Pipeline state that
;; produced the wrong bytes is the evidence and nothing that runs
;; afterwards may touch it.
(defun compare (w iter shape plain got)
  (if (=:= plain got)
    'ok
    (let ((off (binary:longest_common_prefix (list plain got))))
      (loop-main:emit
       'standard_error
       (io_lib:format
        (++ "loop: DATA MISMATCH g~B iter ~B shape=~s: want ~B bytes, got ~B bytes, "
            "first difference at offset ~B: want ~s got ~s~n")
        (list (maps:get 'id w) iter (shape-name shape)
              (byte_size plain) (byte_size got) off
              (hex-window plain off) (hex-window got off))))
      (erlang:halt 3 (list #(flush true))))))

;; Up to 16 bytes from Off as lowercase hex, or "-" when the buffer
;; has no bytes there.
(defun hex-window (bin off)
  (if (>= off (byte_size bin))
    "-"
    (let ((n (min 16 (- (byte_size bin) off))))
      (binary_to_list (binary:encode_hex (binary_part bin off n) 'lowercase)))))

(defun cipher-error (w iter shape direction what status detail)
  (if (=:= what 'same)
    (loop-size:fmt "g~B iter ~B shape=~s: ~s: ~s"
                   (list (maps:get 'id w) iter (shape-name shape) direction
                         (loop-main:status-text status detail)))
    (loop-size:fmt "g~B iter ~B shape=~s: ~s: ~s: ~s"
                   (list (maps:get 'id w) iter (shape-name shape) direction what
                         (loop-main:status-text status detail)))))
