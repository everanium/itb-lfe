;;;; itb-lfe-tests — EUnit suite for the LFE binding, written with
;;;; the ltest macros. Covers: version, the hash primitive roster
;;;; (canonical registry order), the Single Message round trip, the
;;;; incremental stream pump round trip, runtime knobs, profile
;;;; registration, and the error-mapping surface (unknown profile,
;;;; tampered wire, freed handles).
;;;;
;;;; The pump / pair helpers mirror the Erlang binding's
;;;; itb_test_util module (bindings/erlang/test/itb_test_util.erl).

(defmodule itb-lfe-tests
  (behaviour ltest-unit))

(include-lib "ltest/include/ltest-macros.lfe")

;; 1 MiB feed / drain slice for the pump helpers.
(defmacro SLICE () `,(bsl 1 20))

;;; ------------------------------------------------------------------
;;; Version / runtime knobs
;;; ------------------------------------------------------------------

(deftest version
  (let ((`#(ok ,version) (itb3-lfe:version)))
    (is (> (byte_size version) 0))))

(deftest runtime-knobs-query-without-changing
  ;; Negative values query without changing; the return is the
  ;; previous setting.
  (let ((prev (itb3-lfe:set-memory-limit -1)))
    (is (is_integer prev))
    (is-equal prev (itb3-lfe:set-memory-limit -1)))
  (is (is_integer (itb3-lfe:set-gc-percent -2))))

;;; ------------------------------------------------------------------
;;; Single Message round trip (MAC Authenticated profile)
;;; ------------------------------------------------------------------

(deftestgen smoke-round-trip
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
             (`#(ok ,blob) (itb3-lfe:save sender)))
        (is (> (byte_size blob) 0))
        (let* ((`#(ok ,receiver) (itb3-lfe:load blob))
               (plain #"smoke round-trip payload")
               (`#(ok ,wire) (itb3-lfe:encrypt-message sender plain)))
          (is-not-equal plain wire)
          (let ((`#(ok ,back) (itb3-lfe:decrypt-message receiver wire)))
            (is-equal plain back))
          (is-equal 'ok (itb3-lfe:free receiver))
          (is-equal 'ok (itb3-lfe:free sender)))))))

;;; ------------------------------------------------------------------
;;; Incremental stream pump round trip (Streaming Non-AEAD profile)
;;; ------------------------------------------------------------------

(deftestgen stream-pump-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-noaead-triple-v1"))
            (plain (crypto:strong_rand_bytes (+ (bsl 1 20) 12345))))
        (let ((wire (pump sender 'encrypt plain)))
          (is (> (byte_size wire) (byte_size plain)))
          (is-equal plain (pump receiver 'decrypt wire)))
        (is-equal 'ok (itb3-lfe:free receiver))
        (is-equal 'ok (itb3-lfe:free sender))))))

(deftestgen stream-zero-length-payload
  ;; Empty input is rejected at the triple.Pipeline layer before any
  ;; wire is produced: an encrypt session ended without a single
  ;; write surfaces bad_input on the drain, and the one-shot decrypt
  ;; entry rejects a zero-length wire directly.
  (tuple 'timeout 120
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-noaead-triple-v1")))
        (let* ((`#(ok ,stream) (itb3-lfe:encrypt-stream sender))
               (`ok (itb3-lfe:stream-end stream))
               (`#(error #(bad_input ,_)) (itb3-lfe:stream-read stream (SLICE))))
          (is-equal 'ok (itb3-lfe:stream-free stream)))
        (let ((`#(error #(bad_input ,_))
                (itb3-lfe:decrypt-stream-one-shot receiver #"")))
          'ok)
        (is-equal 'ok (itb3-lfe:free receiver))
        (is-equal 'ok (itb3-lfe:free sender))))))

;;; ------------------------------------------------------------------
;;; One-shot stream round trip (Streaming AEAD profile)
;;; ------------------------------------------------------------------

(deftestgen stream-one-shot-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"streaming-aead-triple-mac-v1"))
            (plain (crypto:strong_rand_bytes (+ (bsl 1 18) 12345))))
        ;; One-shot both ways, then cross-check against the
        ;; incremental session path in each direction.
        (let ((`#(ok ,wire) (itb3-lfe:encrypt-stream-one-shot sender plain)))
          (is (> (byte_size wire) (byte_size plain)))
          (let ((`#(ok ,back) (itb3-lfe:decrypt-stream-one-shot receiver wire)))
            (is-equal plain back))
          (is-equal plain (pump receiver 'decrypt wire)))
        (let* ((wire2 (pump sender 'encrypt plain))
               (`#(ok ,back2) (itb3-lfe:decrypt-stream-one-shot receiver wire2)))
          (is-equal plain back2))
        (is-equal 'ok (itb3-lfe:free receiver))
        (is-equal 'ok (itb3-lfe:free sender))))))

;;; ------------------------------------------------------------------
;;; Profile registration
;;; ------------------------------------------------------------------

(deftestgen register-round-trip
  (tuple 'timeout 240
    (lambda ()
      (let* ((hashes (list #"blake3" #"blake2s" #"areion256" #"blake2b256"
                           #"chacha20" #"blake3" #"blake2s" #"areion256"))
             (profile (map #"mode" #"singlemsg-nomac"
                           #"width" 256
                           #"hashes" hashes
                           #"keybits" 1024
                           #"parallax" 'false
                           #"wrapper" 'false)))
        (is-equal 'ok (itb3-lfe:register #"lfe-binding-test-mixed" profile))
        (is (lists:member #"lfe-binding-test-mixed" (itb3-lfe:profiles)))
        (let ((`#(ok ,record) (itb3-lfe:lookup #"lfe-binding-test-mixed")))
          (is-equal hashes (maps:get #"hashes" record)))
        ;; A duplicate registration fails with profile_exists.
        (let ((`#(error #(profile_exists ,_))
                (itb3-lfe:register #"lfe-binding-test-mixed" profile)))
          'ok)
        ;; Strict record decode on the Go side: an unknown key is
        ;; rejected there, not by the binding.
        (let ((`#(error #(bad_input ,_))
                (itb3-lfe:register #"lfe-binding-test-badkey"
                                  #"{\"mode\":\"singlemsg-nomac\",\"bogus\":1}")))
          'ok)
        (let ((`#(,sender ,receiver) (pair #"lfe-binding-test-mixed"))
              (plain (crypto:strong_rand_bytes 8192)))
          (let* ((`#(ok ,wire) (itb3-lfe:encrypt-message sender plain))
                 (`#(ok ,back) (itb3-lfe:decrypt-message receiver wire)))
            (is-equal plain back))
          (is-equal 'ok (itb3-lfe:free receiver))
          (is-equal 'ok (itb3-lfe:free sender)))))))

;;; ------------------------------------------------------------------
;;; Error mapping
;;; ------------------------------------------------------------------

(deftest unknown-profile
  (let ((`#(error #(unknown_profile ,detail))
          (itb3-lfe:init #"no-such-profile")))
    (is (> (byte_size detail) 0))))

(deftestgen save-load-round-trip
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
             (`#(ok ,blob) (itb3-lfe:save sender)))
        (is-equal `#(ok ,blob) (itb3-lfe:save sender))
        (let ((`#(ok ,receiver) (itb3-lfe:load blob)))
          (is-equal `#(ok ,blob) (itb3-lfe:save receiver))
          (let ((`#(ok ,wire) (itb3-lfe:encrypt-message sender #"in-memory persist")))
            (is-equal #(ok #"in-memory persist")
                      (itb3-lfe:decrypt-message receiver wire)))
          (is-equal 'ok (itb3-lfe:free receiver)))
        (is-equal 'ok (itb3-lfe:free sender))))))

(deftestgen save-f-load-f-round-trip
  (tuple 'timeout 120
    (lambda ()
      (let* ((dir (filename:join (os:getenv "TMPDIR" "/tmp")
                                 (++ "itb3-lfe-persist-" (os:getpid))))
             ('ok (file:make_dir dir))
             (path (filename:join dir "session.blob"))
             (`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1")))
        (is-equal 'ok (itb3-lfe:save-f sender path))
        (let ((`#(ok ,info) (file:read_file_info path)))
          (is-equal #o600 (band (element 8 info) #o777)))
        (let ((`#(ok ,receiver) (itb3-lfe:load-f path)))
          (is-equal (itb3-lfe:save sender) (itb3-lfe:save receiver))
          (let ((`#(ok ,wire) (itb3-lfe:encrypt-message sender #"file persist")))
            (is-equal #(ok #"file persist")
                      (itb3-lfe:decrypt-message receiver wire)))
          (is-equal 'ok (itb3-lfe:free receiver)))
        (let ((`#(error #(bad_input ,_))
                (itb3-lfe:load-f (filename:join dir "absent.blob"))))
          'ok)
        (is-equal 'ok (itb3-lfe:free sender))
        (is-equal 'ok (file:delete path))
        (is-equal 'ok (file:del_dir dir))))))

(deftestgen load-with-master-override
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,sender) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
             (perm (binary:copy #b(#x31) 32))
             (wrap (binary:copy #b(#x32) 32))
             (`#(ok ,rotated) (itb3-lfe:rekey sender perm wrap))
             (`#(ok ,blob) (itb3-lfe:save sender))
             (`#(ok ,receiver) (itb3-lfe:load blob perm wrap)))
        (is-equal `#(ok ,rotated) (itb3-lfe:save receiver))
        (let ((`#(ok ,wire) (itb3-lfe:encrypt-message sender #"master override")))
          (is-equal #(ok #"master override")
                    (itb3-lfe:decrypt-message receiver wire)))
        (is-equal 'ok (itb3-lfe:free receiver))
        (is-equal 'ok (itb3-lfe:free sender))))))

(deftest inspect-lookup-profiles
  ;; inspect carries the registry recipe plus the blob-only
  ;; nonce_bits / barrier_fill inspection fields; lookup returns just
  ;; the recipe.
  (let* ((`#(ok ,pipe) (itb3-lfe:init #"singlemsg-triple-mac-v1"))
         (`#(ok ,blob) (itb3-lfe:save pipe)))
    (is-equal 'ok (itb3-lfe:free pipe))
    (let ((`#(ok ,record) (itb3-lfe:inspect blob))
          (`#(ok ,looked) (itb3-lfe:lookup #"singlemsg-triple-mac-v1")))
      (is-equal #"singlemsg-triple-mac-v1" (maps:get #"name" record))
      (is-equal #"singlemsg-mac" (maps:get #"mode" record))
      (is (> (maps:get #"keybits" record) 0))
      (is (maps:is_key #"nonce_bits" record))
      (is (maps:is_key #"barrier_fill" record))
      (is (not (maps:is_key #"nonce_bits" looked)))
      (is (not (maps:is_key #"barrier_fill" looked)))
      (is-equal looked
                (maps:without (list #"nonce_bits" #"barrier_fill") record)))
    (let ((`#(error #(bad_input ,_)) (itb3-lfe:inspect #"not a blob")))
      'ok)
    (let ((`#(error #(unknown_profile ,_)) (itb3-lfe:lookup #"no-such-profile")))
      'ok)
    (let ((names (itb3-lfe:profiles)))
      (is (lists:member #"singlemsg-triple-mac-v1" names))
      (is-equal (lists:sort names) names)
      (lists:foreach
        (lambda (name)
          (let ((`#(ok ,r) (itb3-lfe:lookup name)))
            (is-equal name (maps:get #"name" r))))
        names))))

(deftest max-workers
  (let ((`#(ok ,pipe) (itb3-lfe:init #"singlemsg-triple-mac-v1")))
    (is-equal 'ok (itb3-lfe:max-workers pipe 2))
    ;; Clamped to auto / 256, never rejected.
    (is-equal 'ok (itb3-lfe:max-workers pipe -1))
    (is-equal 'ok (itb3-lfe:max-workers pipe 10000))
    (let ((`#(ok ,wire) (itb3-lfe:encrypt-message pipe #"after cap change")))
      (is-equal #(ok #"after cap change") (itb3-lfe:decrypt-message pipe wire)))
    (is-equal 'ok (itb3-lfe:free pipe))
    ;; A negative init-time cap is clamped as well.
    (let* ((`#(ok ,neg) (itb3-lfe:init #"singlemsg-triple-mac-v1"
                                      (map #"maxWorkers" -1)))
           (`#(ok ,w2) (itb3-lfe:encrypt-message neg #"negative cap")))
      (is-equal #(ok #"negative cap") (itb3-lfe:decrypt-message neg w2))
      (is-equal 'ok (itb3-lfe:free neg)))))

(deftest unknown-inner-hash
  ;; An unknown inner-hash name is relayed to Go and rejected there.
  (let ((`#(error ,_) (itb3-lfe:init #"singlemsg-triple-mac-v1"
                                    (map #"innerHash" #"no-such-hash"))))
    'ok))

(deftest malformed-blob
  (let ((`#(error ,_) (itb3-lfe:load #"not a session blob")))
    'ok))

;; A bit flip in authenticated wire content fails with mac_failure.
;; A single flip can land in the container's CSPRNG residue — where
;; the decrypt legitimately completes clean — so successive flip
;; positions are probed until one lands in authenticated content.
(deftestgen tampered-message
  (tuple 'timeout 300
    (lambda ()
      (let ((`#(,sender ,receiver) (pair #"singlemsg-triple-mac-v1"))
            (plain (crypto:strong_rand_bytes 4096)))
        (let ((`#(ok ,wire) (itb3-lfe:encrypt-message sender plain)))
          (is (probe-flip receiver wire 0)))
        (is-equal 'ok (itb3-lfe:free receiver))
        (is-equal 'ok (itb3-lfe:free sender))))))

(deftest freed-pipeline
  (let ((`#(ok ,pipe) (itb3-lfe:init #"singlemsg-triple-mac-v1")))
    (is-equal 'ok (itb3-lfe:free pipe))
    (is-equal 'ok (itb3-lfe:free pipe)) ;; idempotent
    (let ((`#(error #(bad_handle ,_)) (itb3-lfe:encrypt-message pipe #"x")))
      'ok)
    (let ((`#(error #(bad_handle ,_)) (itb3-lfe:save pipe)))
      'ok)
    (let ((`#(error #(bad_handle ,_)) (itb3-lfe:encrypt-stream pipe)))
      'ok)))

(deftestgen freed-stream
  (tuple 'timeout 120
    (lambda ()
      (let* ((`#(ok ,pipe) (itb3-lfe:init #"streaming-noaead-triple-v1"))
             (`#(ok ,stream) (itb3-lfe:encrypt-stream pipe)))
        (is-equal 'ok (itb3-lfe:stream-free stream))
        (is-equal 'ok (itb3-lfe:stream-free stream)) ;; idempotent
        (let ((`#(error #(bad_handle ,_)) (itb3-lfe:stream-write stream #"x")))
          'ok)
        (let ((`#(error #(bad_handle ,_)) (itb3-lfe:stream-end stream)))
          'ok)
        (let ((`#(error #(bad_handle ,_)) (itb3-lfe:stream-read stream 16)))
          'ok)
        (is-equal 'ok (itb3-lfe:free pipe))))))

;;; ------------------------------------------------------------------
;;; Helpers (not tests)
;;; ------------------------------------------------------------------

;; Sender + receiver pipelines over one profile with default opts.
(defun pair (profile)
  (let* ((`#(ok ,sender) (itb3-lfe:init profile))
         (`#(ok ,blob) (itb3-lfe:save sender))
         (`#(ok ,receiver) (itb3-lfe:load blob)))
    (tuple sender receiver)))

;; Whole-buffer pump through an incremental session with 1 MiB feed /
;; drain slices: begin -> write slices (draining the spool after each
;; write) -> end -> drain until finished -> free.
(defun pump (pipe direction data)
  (let ((`#(ok ,stream) (case direction
                          ('encrypt (itb3-lfe:encrypt-stream pipe))
                          ('decrypt (itb3-lfe:decrypt-stream pipe)))))
    (let ((acc (feed stream data '())))
      (let ((`ok (itb3-lfe:stream-end stream)))
        (let ((out (drain-all stream acc)))
          (let ((`ok (itb3-lfe:stream-free stream)))
            out))))))

(defun feed (stream data acc)
  (if (=:= data #"")
    acc
    (let* ((n (erlang:min (byte_size data) (SLICE)))
           (slice (binary:part data 0 n))
           (rest (binary:part data n (- (byte_size data) n)))
           (`ok (itb3-lfe:stream-write stream slice))
           ;; A read before end never blocks; drain whatever the chain
           ;; has produced so far to bound the Go-side spool.
           (acc1 (drain-ready stream acc)))
      (feed stream rest acc1))))

(defun drain-ready (stream acc)
  (case (itb3-lfe:stream-read stream (SLICE))
    (`#(ok #"" ,_) acc)
    (`#(ok ,piece false) (drain-ready stream (cons piece acc)))
    (`#(ok ,piece true) (cons piece acc))))

(defun drain-all (stream acc)
  (case (itb3-lfe:stream-read stream (SLICE))
    (`#(ok ,piece true)
      (iolist_to_binary (lists:reverse (cons piece acc))))
    (`#(ok ,piece false)
      (drain-all stream (cons piece acc)))))

;; Probes successive flip positions until one lands in authenticated
;; content (mac_failure); 'false only if the whole wire is exhausted.
(defun probe-flip (receiver wire pos)
  (if (>= pos (byte_size wire))
    'false
    (case (itb3-lfe:decrypt-message receiver (flip-byte wire pos))
      (`#(error #(mac_failure ,_)) 'true)
      ;; A clean decrypt (flip in unauthenticated residue) or a
      ;; structural envelope failure — keep probing for a MAC hit.
      (`#(ok ,_) (probe-flip receiver wire (+ pos 1)))
      (`#(error #(,_ ,_)) (probe-flip receiver wire (+ pos 1))))))

;; Copy of wire with bit 0 of byte pos flipped.
(defun flip-byte (wire pos)
  (let ((head (binary:part wire 0 pos))
        (byte (binary:at wire pos))
        (tail (binary:part wire (+ pos 1) (- (byte_size wire) pos 1))))
    (iolist_to_binary (list head (bxor byte 1) tail))))
