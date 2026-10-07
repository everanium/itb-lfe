;;;; Size and duration parsing, the monotonic clock, and
;;;; the human renderings of sizes, rates and durations. Every
;;;; rendering here is part of the output contract shared with the Go
;;;; harness and the other bindings' loop utilities, so the formats
;;;; are fixed to the character, not to taste.

(defmodule loop-size
  (export (parse-size 1) (parse-duration 1) (now-ns 0)
          (human-bytes 1) (human-bytes-signed 1) (human-rate 2)
          (human-duration 1) (mb-per-sec 2) (fmt 2)))

(defun suffixes ()
  (list (tuple "KIB" (bsl 1 10)) (tuple "KB" (bsl 1 10)) (tuple "K" (bsl 1 10))
        (tuple "MIB" (bsl 1 20)) (tuple "MB" (bsl 1 20)) (tuple "M" (bsl 1 20))
        (tuple "GIB" (bsl 1 30)) (tuple "GB" (bsl 1 30)) (tuple "G" (bsl 1 30))
        (tuple "B" 1)))

(defun units ()
  (list (tuple "ns" 1.0) (tuple "us" 1.0e3) (tuple "ms" 1.0e6)
        (tuple "s" 1.0e9) (tuple "m" 60.0e9) (tuple "h" 3600.0e9)))

;; Parses a human byte-size string ("16MB", "1MiB", "512K",
;; "1073741824") into a byte count. Every suffix is a binary multiple:
;; K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
;; bytes; matching is case-insensitive and surrounding whitespace is
;; trimmed. Returns #(ok Bytes) or 'error.
(defun parse-size (s)
  (let ((upper (string:uppercase (string:trim s))))
    (if (=:= upper "")
      'error
      (split-suffix upper))))

(defun split-suffix (upper)
  (let* ((`#(,digits0 ,mult) (match-suffix upper (suffixes)))
         ;; Whitespace may sit between the number and its unit.
         (digits (string:trim digits0 'trailing)))
    (cond ((=:= digits "") 'error)
          ((not (lists:all (lambda (c) (andalso (>= c #\0) (=< c #\9))) digits)) 'error)
          ('true `#(ok ,(* (list_to_integer digits) mult))))))

(defun match-suffix
  ((upper '()) `#(,upper 1))
  ((upper (cons `#(,suffix ,mult) rest))
   (let ((sl (length suffix))
         (ul (length upper)))
     (if (andalso (>= ul sl) (=:= (lists:sublist upper (+ (- ul sl) 1) sl) suffix))
       `#(,(lists:sublist upper (- ul sl)) ,mult)
       (match-suffix upper rest)))))

;; Parses the Go duration grammar — a sequence of decimal numbers each
;; followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
;; "1h30m", "1.5s" — into nanoseconds. Returns #(ok Nanos) or 'error.
(defun parse-duration
  (("") 'error)
  ((s) (duration-parts s 0.0)))

(defun duration-parts
  (('() total) (if (=< total 9.2e18) `#(ok ,(trunc total)) 'error))
  ((s total)
   (case (number-prefix s)
     ('error 'error)
     (`#(,v ,rest)
      (case (unit-prefix rest (units))
        ('error 'error)
        (`#(,mult ,rest2) (duration-parts rest2 (+ total (* v mult)))))))))

;; A decimal run with an optional fraction. A leading sign is not part
;; of the grammar.
(defun number-prefix (s)
  (case s
    ('() 'error)
    ((cons c _)
     (if (orelse (andalso (>= c #\0) (=< c #\9)) (=:= c #\.))
       (let ((`#(,digits ,rest)
              (lists:splitwith
               (lambda (ch) (orelse (andalso (>= ch #\0) (=< ch #\9)) (=:= ch #\.)))
               s)))
         (case (string:to_float digits)
           (`#(,f ,"") `#(,f ,rest))
           (_ (case (string:to_integer digits)
                (`#(,i ,"") (when (is_integer i)) `#(,(* i 1.0) ,rest))
                (_ 'error)))))
       'error))))

(defun unit-prefix
  ((_s '()) 'error)
  ((s (cons `#(,unit ,mult) rest))
   (if (lists:prefix unit s)
     (let ((tail (lists:nthtail (length unit) s)))
       ;; A longer word starting with this unit is not this unit.
       (case tail
         ((cons c _) (when (orelse (andalso (>= c #\a) (=< c #\z))
                                   (andalso (>= c #\A) (=< c #\Z))))
          (unit-prefix s rest))
         (_ `#(,mult ,tail))))
     (unit-prefix s rest))))

;; Monotonic wall clock in nanoseconds.
(defun now-ns ()
  (erlang:monotonic_time 'nanosecond))

;; Renders a byte count with a binary-unit suffix: "1.0GiB",
;; "16.0MiB", "4.0KiB", "512B".
(defun human-bytes (n)
  (cond ((>= n (bsl 1 30)) (fmt "~.1fGiB" (list (/ n (bsl 1 30)))))
        ((>= n (bsl 1 20)) (fmt "~.1fMiB" (list (/ n (bsl 1 20)))))
        ((>= n (bsl 1 10)) (fmt "~.1fKiB" (list (/ n (bsl 1 10)))))
        ('true (fmt "~BB" (list n)))))

;; Renders a possibly-negative byte delta with an explicit sign.
(defun human-bytes-signed (n)
  (if (< n 0)
    (++ "-" (human-bytes (- n)))
    (++ "+" (human-bytes n))))

;; Binary MiB per second over a nanosecond window; 0 when the window
;; is unmeasured.
(defun mb-per-sec (bytes ns)
  (if (=< ns 0)
    0.0
    (/ (/ bytes (bsl 1 20)) (/ ns 1.0e9))))

;; Renders a throughput as "123.4MB/s" (binary MiB per second) or
;; "n/a" for an unmeasured window.
(defun human-rate (bytes ns)
  (if (=< ns 0)
    "n/a"
    (fmt "~.1fMB/s" (list (mb-per-sec bytes ns)))))

;; Renders a duration the way Go's time.Duration prints: below one
;; second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
;; where the hour part appears when non-zero, the minute part when the
;; hour part appears or the minutes are non-zero, and the seconds
;; carry their fraction with trailing zeros removed ("5s", "5.003s",
;; "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
(defun human-duration (ns0)
  (let ((ns (abs ns0)))
    (cond
     ((=:= ns 0) "0s")
     ((< ns 1000000000)
      ;; The remainder is scaled to nine digits so the fraction
      ;; renderer is the same one the seconds branch uses.
      (++ (integer_to_list (div ns 1000000))
          (fraction (* (rem ns 1000000) 1000))
          "ms"))
     ('true
      (let* ((hours (div ns 3600000000000))
             (rem1 (rem ns 3600000000000))
             (minutes (div rem1 60000000000))
             (rem2 (rem rem1 60000000000))
             (seconds (div rem2 1000000000))
             (frac (rem rem2 1000000000))
             (hpart (if (> hours 0) (++ (integer_to_list hours) "h") ""))
             (mpart (if (orelse (> hours 0) (> minutes 0))
                      (++ (integer_to_list minutes) "m")
                      "")))
        (++ hpart mpart (integer_to_list seconds) (fraction frac) "s"))))))

;; The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
;; with trailing zeros removed; empty for zero.
(defun fraction
  ((0) "")
  ((frac-ns)
   (let* ((padded (lists:flatten (string:pad (integer_to_list frac-ns) 9 'leading #\0)))
          (trimmed (string:trim padded 'trailing "0")))
     (if (=:= trimmed "") "" (++ "." trimmed)))))

(defun fmt (format args)
  (lists:flatten (io_lib:format format args)))
