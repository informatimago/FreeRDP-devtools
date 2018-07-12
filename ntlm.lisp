;; Decode the NTLM NEGOTIATE FLAGS
;; [MS-NLMP].pdf section 2.2.2.5. NEGOCIATE (page 31/95)


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


(defun decode-nlmp-negotiate-flags (negotiate-flags)
  (loop :for bit :from 31 :downto 0
        :for desc := (aref *ntlm-negotiate-flags* bit)
        :if (logbitp (- 31 bit) negotiate-flags)
          :do (format t "~2D: ~A~%" bit (second desc))))

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
