;; Decode the NTLM NEGOTIATE FLAGS
;; [MS-NLMP].pdf section 2.2.2.5. NEGOCIATE (page 31/95)

(ql:quickload :babel)


(defparameter *ntlm-negotiate-flags*
  #(;; from  0 to 31
    (:ntlmssp-negotiate-56           "requests 56-bit encryption")
    (:ntlmssp-negotiate-key-exch     "requests explicit key exchange")
    (:ntlmssp-negotiate-128          "requests 128-bit session key negotiation")
    (:reserved-1                     "reserved 1")
    (:reserved-2                     "reserved 2")
    (:reserved-3                     "reserved 3")
    (:ntlmssp-negotiate-version      "request the protocol version number")
    (:reserved-4                     "reserved 4")
    (:ntlmssp-negotiate-target-info  "TargetInfo fields in CHALLENGE_MESSAGE are populated")
    (:ntlmssp-negotiate-request-non-nt-session-key "requests non NT session key (LMOWF)")
    (:reserved-5                     "reserved 5")
    (:ntlmssp-negotiate-identify     "requests an identify level token")
    (:ntlmssp-negotiate-extended-session-security "requests NTLM v2 session security")
    (:reserved-6                     "reserved 6")
    (:ntlmssp-target-type-server     "TargetName must be a server name")
    (:ntlmssp-target-type-domain     "TargetName must be a domain name")
    (:ntlmssp-negotiate-always-sign  "requests signature blocks on all messages")
    (:reserved-7                     "reserved 7")
    (:ntlmssp-negotiate-oem-workstation-supplied "workstation field present")
    (:ntlmssp-negotiate-oem-domain-supplied      "domain name provided")
    (nil "connection should be anonymous")
    (:reserved-8                     "reserved 8")
    (:ntlmssp-negotiate-ntlm         "requests NTLM v1 session security protocol")
    (:reserved-9                     "reserved 9")
    (:ntlmssp-negotiate-lm-key       "requests Lan Manager session key computation")
    (:ntlmssp-negotiate-datagram     "requests connectionless authentication")
    (:ntlmssp-negotiate-seal         "requests session key negotiation for message confidentiality")
    (:ntlmssp-negotiate-sign         "requests session key negotiation for message signature")
    (:reserved-10                    "reserved 10")
    (:ntlmssp-request-target         "TargetName field in CHALLENGE_MESSAGE must be supplied")
    (:ntlmssp-negotiate-oem          "requests OEM character set encoding")
    (:ntlmssp-negotiate-unicode      "requests Unicode character set encoding")))


(defun print-nlmp-negotiate-flags (negotiate-flags)
  (loop :for bit :from 31 :downto 0
        :for desc := (aref *ntlm-negotiate-flags* bit)
        :if (logbitp (- 31 bit) negotiate-flags)
          :do (format t "~2D: ~A~%" bit (second desc))))

(defun decode-nlmp-negotiate-flags (negotiate-flags)
  (loop :for bit :from 31 :downto 0
        :for desc := (aref *ntlm-negotiate-flags* bit)
        :if (logbitp (- 31 bit) negotiate-flags)
          :collect (first desc)))


;; (decode-nlmp-negotiate-flags #xE20882B7)
;;
;; 31: requests Unicode character set encoding
;; 30: requests OEM character set encoding
;; 29: TargetName field in CHALLENGE_MESSAGE must be supplied
;; 27: requests session key negotiation for message signature
;; 26: requests session key negotiation for message confidentiality
;; 24: requests Lan Manager session key computation
;; 22: requests NTLM v1 session security protocol
;; 16: requests signature blocks on all messages
;; 12: requests NTLM v2 session security
;;  6: request the protocol version number
;;  2: requests 128-bit session key negotiation
;;  1: requests explicit key exchange
;;  0: requests 56-bit encryption

(defconstant +authenticate-message+ #x00000003)

(defun uint32-at (message offset)
  (dpb (aref message (+ 3 offset))
       (byte 8 24)
       (dpb (aref message (+ 2 offset))
            (byte 8 16)
            (dpb (aref message (+ 1 offset))
                 (byte 8 8)
                 (aref message offset)))))

(defun uint16-at (message offset)
  (dpb (aref message (+ 1 offset))
       (byte 8 8)
       (aref message offset)))

(defun decode-unicode16 (bytes)
  (if (zerop (length bytes))
      ""
      (babel:octets-to-string (if (typep bytes '(vector (unsigned-byte 8)))
                                    bytes
                                    (coerce bytes '(vector (unsigned-byte 8))))
                              :encoding :utf-16/le)))

(defun check-ntlm-signature (message type)
  (assert (string= "NTLMSSP" (map 'string (function code-char) (subseq message 0 7))))
  (assert (= 0 (aref message 7)))
  (assert (= type (uint32-at message 8))))

(defun get-ntlm-field (message offset)
  (let ((length       (uint16-at message offset))
        (maxlength    (uint16-at message (+ 2 offset)))
        (field-offset (uint32-at message (+ 4 offset))))
    (print (list field-offset length))
    (subseq message field-offset (+ field-offset length))))

(defun get-ntlm-version (message offset)
  (list :major (aref message offset)
        :minor (aref message (+ offset 1))
        :build (uint16-at message (+ offset 2))
        :ntlm-revision-current (aref message (+ offset 7))))

(defun get-ntlm-mic (message offset)
  (subseq message offset (+ offset 16)))


(defun decode-authenticate-message (message)
  (check-ntlm-signature message +authenticate-message+)
  (list :ntlmssp +authenticate-message+
        :lm-challenge-response        (get-ntlm-field message 12)
        :nt-challenge-response        (get-ntlm-field message 20)
        :domain-name                  (decode-unicode16 (get-ntlm-field message 28))
        :user-name                    (decode-unicode16 (get-ntlm-field message 36))
        :workstation                  (decode-unicode16 (get-ntlm-field message 44))
        :encrypted-random-session-key (get-ntlm-field message 52)
        :negotiate-flags              (decode-nlmp-negotiate-flags (uint32-at message 60))
        :version                      (get-ntlm-version message 64)
        :mic                          (get-ntlm-mic message 72)
        :payload                      (subseq message 88)))

