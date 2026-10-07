;;;; The maintenance operations that mutate a live Pipeline
;;;; handle between iterations: master rotation (--rekey-every) and
;;;; blob reopen (--blob-cycle-every).

(defmodule loop-ops
  (export (maintenance 3)))

;; Byte length of each fresh master drawn for a rotation. Matches the
;; size Init auto-generates for both the parallax and the wrapper
;; master.
(defmacro REKEY-MASTER-SIZE () 32)

;; Handle mutation. Runs the periodic Pipeline-mutating operations
;; after a completed iteration: master rotation (--rekey-every) and
;; blob reopen (--blob-cycle-every). Both intervals count per-worker
;; iterations; the warmup iteration (iter 0) never triggers because
;; the worker loop calls this for iter >= 1 only. Rekey rewrites the
;; outer-layer keying of a live handle and a blob reopen replaces the
;; handle outright; each takes the write lock, so in-flight cipher
;; calls on other workers drain before anything changes and no encrypt
;; is separated from its decrypt by either.
(defun maintenance (run id iter)
  (let ((cfg (maps:get 'cfg run)))
    (if (due (maps:get 'rekey-every cfg) iter)
      (case (rekey-pipes run id iter)
        ('ok (blob-stage run id iter))
        (`#(error ,text) `#(error ,text)))
      (blob-stage run id iter))))

(defun blob-stage (run id iter)
  (let ((cfg (maps:get 'cfg run)))
    (if (due (maps:get 'blob-cycle-every cfg) iter)
      (blob-cycle-pipes run id iter)
      'ok)))

(defun due (every iter)
  (if (=:= every 0) 'false (=:= (rem iter every) 0)))

;; Master rotation. Rotates the parallax + wrapper masters on every
;; active Pipeline under the write lock and retains the refreshed blob
;; for subsequent blob reopens. Masters are drawn fresh from the OS
;; CSPRNG on every rotation regardless of --seed (master rotation is
;; pipeline keying, not plaintext content); a disabled layer passes no
;; bytes, which Rekey ignores. The eight inner seeds and the MAC key
;; are untouched by design — Rekey targets only the two outer-layer
;; master secrets.
(defun rekey-pipes (run id iter)
  (let* ((cfg (maps:get 'cfg run))
         (state (maps:get 'state run))
         (perm (master (maps:get 'parallax cfg)))
         (wrap (master (maps:get 'wrapper cfg)))
         (`#(,stream-pipe ,msg-pipe ,_sb ,_mb) (loop-state:write-lock state)))
    (case (rekey-one stream-pipe perm wrap)
      (`#(error ,status ,detail)
       (loop-state:write-unlock state (map))
       `#(error ,(op-error id iter "Rekey" (maps:get 'stream-profile run) status detail)))
      (`#(ok ,stream-update)
       (case (rekey-one msg-pipe perm wrap)
         (`#(error ,status ,detail)
          (loop-state:write-unlock state (rename stream-update 'stream-blob))
          `#(error ,(op-error id iter "Rekey" (maps:get 'msg-profile run) status detail)))
         (`#(ok ,msg-update)
          (loop-state:write-unlock
           state (maps:merge (rename stream-update 'stream-blob)
                             (rename msg-update 'msg-blob)))
          (let ((n (loop-state:bump (maps:get 'counts run) 'rekeys)))
            (loop-main:log "rekey: g~B iter ~B rotated parallax + wrapper masters (rekey #~B)"
                           (list id iter n)))
          'ok))))))

(defun master (enabled)
  (if (=:= enabled 'true) (loop-payload:random-bytes (REKEY-MASTER-SIZE)) #""))

(defun rekey-one (pipe perm wrap)
  (if (=:= pipe 'undefined)
    `#(ok ,(map))
    (case (itb3-lfe:rekey pipe perm wrap)
      (`#(ok ,blob) `#(ok ,(map 'blob blob)))
      (`#(error #(,status ,detail)) `#(error ,status ,detail)))))

(defun rename (update key)
  (case (maps:find 'blob update)
    (`#(ok ,blob) (maps:put key blob (map)))
    ('error (map))))

;; Blob reopen. Reopens every active Pipeline from its retained blob
;; under the write lock: a fresh handle is loaded from the blob, the
;; running handle is freed, and the fresh one is swapped in, so every
;; later iteration round-trips through seeds and masters that survived
;; a blob crossing. The input is the blob Init or the latest Rekey
;; handed out, not a fresh Save: that is what a receiver holds, and
;; reopening from it proves the handed-out bytes rather than the live
;; state. The blob carries the Pipeline's full shape, so no override
;; reaches the reopen. On a Load failure the running handle stays and
;; the failure aborts the run.
(defun blob-cycle-pipes (run id iter)
  (let* ((state (maps:get 'state run))
         (`#(,stream-pipe ,msg-pipe ,stream-blob ,msg-blob)
          (loop-state:write-lock state)))
    (case (reopen stream-pipe stream-blob)
      (`#(error ,status ,detail)
       (loop-state:write-unlock state (map))
       `#(error ,(op-error id iter "Load" (maps:get 'stream-profile run) status detail)))
      (`#(ok ,stream-fresh)
       (case (reopen msg-pipe msg-blob)
         (`#(error ,status ,detail)
          (loop-state:write-unlock state (swap 'stream-pipe stream-pipe stream-fresh))
          `#(error ,(op-error id iter "Load" (maps:get 'msg-profile run) status detail)))
         (`#(ok ,msg-fresh)
          (loop-state:write-unlock
           state (maps:merge (swap 'stream-pipe stream-pipe stream-fresh)
                             (swap 'msg-pipe msg-pipe msg-fresh)))
          (let ((n (loop-state:bump (maps:get 'counts run) 'blob-cycles)))
            (loop-main:log "blob-cycle: g~B iter ~B reopened from session blob (cycle #~B)"
                           (list id iter n)))
          'ok))))))

(defun reopen (pipe blob)
  (if (=:= pipe 'undefined)
    #(ok undefined)
    (case (itb3-lfe:load blob)
      (`#(ok ,fresh) `#(ok ,fresh))
      (`#(error #(,status ,detail)) `#(error ,status ,detail)))))

;; The running handle is released only once its replacement is in
;; hand, so a failed Load leaves the Pipeline the run is using intact.
(defun swap (key old fresh)
  (if (=:= fresh 'undefined)
    (map)
    (progn (itb3-lfe:free old) (maps:put key fresh (map)))))

(defun op-error (id iter op profile status detail)
  (loop-size:fmt "g~B iter ~B: ~s(~s): ~s"
                 (list id iter op profile (loop-main:status-text status detail))))
