;;;; The state every worker shares: the Pipeline handles,
;;;; the retained blobs, the reader / writer lock that keeps iterations
;;;; clear of handle mutation, the stop request, and the rekey and
;;;; blob-cycle totals.
;;;;
;;;; LFE-specific. BEAM has no reader / writer lock primitive, so the
;;;; lock is a process that owns the handles and hands them out: a
;;;; reader is granted immediately unless a writer holds or is
;;;; waiting, a writer waits until the last reader has left. The
;;;; handles travel with the grant rather than being cached by the
;;;; worker, because a blob reopen frees the running handle and swaps
;;;; a fresh one in — a worker holding the term from launch would be
;;;; calling into a released resource from the first cycle onwards.
;;;; The lock holder is monitored, so a worker that dies holding
;;;; either side releases it instead of wedging the run.

(defmodule loop-state
  (export (start 4) (stop-process 1)
          (read-lock 1) (read-unlock 1) (write-lock 1) (write-unlock 2)
          (handles 1)
          (new-flags 0) (request-stop 1) (stop-requested 1)
          (new-counts 0) (bump 2) (count 2)))

;; Slot 1 of the atomics word carries the stop request; slots 1 and 2
;; of the counters array carry the rekey and blob-cycle totals.
(defmacro SLOT-STOP () 1)
(defmacro COUNT-REKEYS () 1)
(defmacro COUNT-BLOB-CYCLES () 2)

;;; ------------------------------------------------------------------
;;; Stop request and counters — lock-free, so a worker's per-iteration
;;; check never queues behind the lock process.
;;; ------------------------------------------------------------------

(defun new-flags ()
  (atomics:new 1 (list `#(signed false))))

(defun request-stop (flags)
  (atomics:put flags (SLOT-STOP) 1))

(defun stop-requested (flags)
  (=:= (atomics:get flags (SLOT-STOP)) 1))

(defun new-counts ()
  (counters:new 2 '(write_concurrency)))

(defun bump
  ((counts 'rekeys)
   (counters:add counts (COUNT-REKEYS) 1)
   (counters:get counts (COUNT-REKEYS)))
  ((counts 'blob-cycles)
   (counters:add counts (COUNT-BLOB-CYCLES) 1)
   (counters:get counts (COUNT-BLOB-CYCLES))))

(defun count
  ((counts 'rekeys) (counters:get counts (COUNT-REKEYS)))
  ((counts 'blob-cycles) (counters:get counts (COUNT-BLOB-CYCLES))))

;;; ------------------------------------------------------------------
;;; The lock process
;;; ------------------------------------------------------------------

(defun start (stream-pipe msg-pipe stream-blob msg-blob)
  (spawn_link
   (lambda ()
     (loop (map 'stream-pipe stream-pipe 'msg-pipe msg-pipe
                'stream-blob stream-blob 'msg-blob msg-blob
                'readers '() 'writer 'none
                'wait-readers '() 'wait-writers '()
                'monitors (map))))))

(defun stop-process (pid)
  (! pid `#(shutdown ,(self)))
  (receive
    (`#(shutdown_ok ,p) (when (=:= p pid)) 'ok)
    (after 5000 'ok)))

;; Grants the read side and hands back the handles in force at that
;; instant. Cipher calls run in the caller, not here: routing them
;; through this process would serialise every worker and remove the
;; shared-handle property the harness exists to exercise.
(defun read-lock (pid)
  (lock-call pid 'read-lock))

(defun read-unlock (pid)
  (! pid `#(read-unlock ,(self)))
  'ok)

(defun write-lock (pid)
  (lock-call pid 'write-lock))

;; Releases the write side, installing whatever the maintenance
;; produced. Updates is a map of the fields that changed.
(defun write-unlock (pid updates)
  (! pid `#(write-unlock ,(self) ,updates))
  'ok)

;; The handles without taking the lock, for the shutdown path after
;; every worker has returned.
(defun handles (pid)
  (lock-call pid 'handles))

(defun lock-call (pid request)
  (let ((ref (make_ref)))
    (! pid `#(,request ,(self) ,ref))
    (receive
      (`#(,r ,reply) (when (=:= r ref)) reply))))

;;; ------------------------------------------------------------------

(defun loop (st)
  (receive
    (`#(read-lock ,pid ,ref) (loop (request-read st pid ref)))
    (`#(write-lock ,pid ,ref) (loop (request-write st pid ref)))
    (`#(read-unlock ,pid) (loop (grant (release-reader st pid))))
    (`#(write-unlock ,pid ,updates)
     (loop (grant (release-writer (apply-updates st updates) pid))))
    (`#(handles ,pid ,ref)
     (! pid `#(,ref #(,(maps:get 'stream-pipe st) ,(maps:get 'msg-pipe st))))
     (loop st))
    ;; A holder that died never sends its unlock; drop its claim so the
    ;; run can finish instead of wedging.
    (`#(DOWN ,_mref process ,pid ,_reason)
     (loop (grant (release-writer (release-reader st pid) pid))))
    (`#(shutdown ,pid)
     (! pid `#(shutdown_ok ,(self)))
     'ok)))

(defun read-reply (st)
  `#(,(maps:get 'stream-pipe st) ,(maps:get 'msg-pipe st)))

(defun write-reply (st)
  `#(,(maps:get 'stream-pipe st) ,(maps:get 'msg-pipe st)
     ,(maps:get 'stream-blob st) ,(maps:get 'msg-blob st)))

(defun request-read (st pid ref)
  (if (andalso (=:= (maps:get 'writer st) 'none)
               (=:= (maps:get 'wait-writers st) '()))
    (progn
      (! pid `#(,ref ,(read-reply st)))
      (watch (maps:put 'readers (cons pid (maps:get 'readers st)) st) pid))
    (maps:put 'wait-readers
              (++ (maps:get 'wait-readers st) (list `#(,pid ,ref)))
              st)))

(defun request-write (st pid ref)
  (if (andalso (=:= (maps:get 'writer st) 'none)
               (=:= (maps:get 'readers st) '()))
    (progn
      (! pid `#(,ref ,(write-reply st)))
      (watch (maps:put 'writer pid st) pid))
    (maps:put 'wait-writers
              (++ (maps:get 'wait-writers st) (list `#(,pid ,ref)))
              st)))

;; Writer preference: a queued writer goes first, so a steady stream of
;; iterations cannot starve a rekey that is already waiting.
(defun grant (st)
  (let ((writer (maps:get 'writer st))
        (readers (maps:get 'readers st))
        (waitw (maps:get 'wait-writers st))
        (waitr (maps:get 'wait-readers st)))
    (cond
     ((andalso (=:= writer 'none) (andalso (=:= readers '()) (=/= waitw '())))
      (let* ((`#(,pid ,ref) (car waitw))
             (st1 (maps:put 'wait-writers (cdr waitw) st)))
        (! pid `#(,ref ,(write-reply st1)))
        (watch (maps:put 'writer pid st1) pid)))
     ((andalso (=:= writer 'none) (andalso (=:= waitw '()) (=/= waitr '())))
      (let ((st1 (maps:put 'wait-readers '()
                           (maps:put 'readers
                                     (++ (lists:map (lambda (e) (element 1 e)) waitr) readers)
                                     st))))
        (lists:foreach (lambda (e) (! (element 1 e) `#(,(element 2 e) ,(read-reply st1)))) waitr)
        (lists:foldl (lambda (e acc) (watch acc (element 1 e))) st1 waitr)))
     ('true st))))

(defun release-reader (st pid)
  (if (lists:member pid (maps:get 'readers st))
    (unwatch (maps:put 'readers (lists:delete pid (maps:get 'readers st)) st) pid)
    st))

(defun release-writer (st pid)
  (if (=:= (maps:get 'writer st) pid)
    (unwatch (maps:put 'writer 'none st) pid)
    st))

(defun apply-updates (st updates)
  (maps:merge st updates))

(defun watch (st pid)
  (let ((mons (maps:get 'monitors st)))
    (if (maps:is_key pid mons)
      st
      (maps:put 'monitors (maps:put pid (erlang:monitor 'process pid) mons) st))))

(defun unwatch (st pid)
  (if (orelse (=:= (maps:get 'writer st) pid)
              (lists:member pid (maps:get 'readers st)))
    st
    (let ((mons (maps:get 'monitors st)))
      (case (maps:take pid mons)
        ('error st)
        (`#(,mref ,rest)
         (erlang:demonitor mref '(flush))
         (maps:put 'monitors rest st))))))
