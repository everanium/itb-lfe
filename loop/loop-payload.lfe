;;;; Plaintext content: the payload modes, the seeded
;;;; per-worker generator, and the buffer fill from the
;;;; operating-system CSPRNG.
;;;;
;;;; The modes the --payload-mode flag selects:
;;;;
;;;;   - fixed: one CSPRNG-generated buffer per worker, held unchanged
;;;;     for the whole run (the default).
;;;;   - rotating: the buffer is regenerated before every iteration, so
;;;;     no two encrypt calls see the same plaintext.
;;;;   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00
;;;;     / all 0xFF) probing minimum-entropy plaintext handling.
;;;;   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
;;;;     structured text.

(defmodule loop-payload
  (export (mode-name 1) (parse-mode 1) (seed-worker 2) (fill 4)
          (random-bytes 1)))

(defmacro M64 () #xFFFFFFFFFFFFFFFF)

(defun mode-name
  (('fixed) "fixed")
  (('rotating) "rotating")
  (('pattern-zero) "pattern-zero")
  (('pattern-ff) "pattern-ff")
  (('pattern-ascii) "pattern-ascii"))

(defun parse-mode
  (("fixed") #(ok fixed))
  (("rotating") #(ok rotating))
  (("pattern-zero") #(ok pattern-zero))
  (("pattern-ff") #(ok pattern-ff))
  (("pattern-ascii") #(ok pattern-ascii))
  ((_) 'error))

;; Seeded plaintext. The seed makes plaintext content reproducible so
;; a failing iteration can be replayed with the same bytes; it governs
;; nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
;; so a seeded run is a reproduction aid and never a security test.
;; Each worker's stream is domain-separated by its id so seeded
;; workers still hold pairwise-distinct buffers under the fixed and
;; rotating modes. The generator is splitmix64: a few lines in any
;; language, which is why it is the one every binding uses.
(defun seed-worker (seed worker-id)
  (band (+ seed worker-id 1) (M64)))

(defun splitmix64 (state0)
  (let* ((s (band (+ state0 #x9E3779B97F4A7C15) (M64)))
         (z1 (band (* (bxor s (bsr s 30)) #xBF58476D1CE4E5B9) (M64)))
         (z2 (band (* (bxor z1 (bsr z1 27)) #x94D049BB133111EB) (M64))))
    `#(,(bxor z2 (bsr z2 31)) ,s)))

;; Draws N bytes from the operating-system CSPRNG.
(defun random-bytes (n)
  (crypto:strong_rand_bytes n))

;; Builds one plaintext buffer according to the payload mode. The
;; fixed and rotating modes draw from the seeded generator when the
;; run is seeded and from the OS CSPRNG otherwise; the pattern modes
;; are deterministic regardless of the seed. Returns the buffer and
;; the generator state to carry into the next fill.
(defun fill
  ((mode 'false rng n) (when (orelse (=:= mode 'fixed) (=:= mode 'rotating)))
   `#(,(random-bytes n) ,rng))
  ((mode 'true rng n) (when (orelse (=:= mode 'fixed) (=:= mode 'rotating)))
   (seeded-fill rng n '()))
  (('pattern-zero _seeded rng n) `#(,(binary:copy #b(0) n) ,rng))
  (('pattern-ff _seeded rng n) `#(,(binary:copy #b(255) n) ,rng))
  (('pattern-ascii _seeded rng n) `#(,(ascii-ramp n) ,rng)))

;; Eight little-endian bytes per generator draw, the last draw
;; truncated to the bytes the buffer still wants.
(defun seeded-fill (rng n acc)
  (if (=< n 0)
    `#(,(erlang:iolist_to_binary (lists:reverse acc)) ,rng)
    (let* ((`#(,v ,rng1) (splitmix64 rng))
           (word (binary (v integer little (size 64)))))
      (if (>= n 8)
        (seeded-fill rng1 (- n 8) (cons word acc))
        (seeded-fill rng1 0 (cons (binary_part word 0 n) acc))))))

;; Byte i is 'A' + (i rem 26), built from one 26-byte period so a
;; large buffer costs a copy rather than a per-byte comprehension.
(defun ascii-ramp (n)
  (let ((period (list_to_binary (lists:seq #\A #\Z))))
    (erlang:iolist_to_binary
     (list (binary:copy period (div n 26))
           (binary_part period 0 (rem n 26))))))
