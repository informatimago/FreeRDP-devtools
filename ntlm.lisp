;; Decode the NTLM NEGOTIATE FLAGS.

(defparameter *ntlm-negotiate-flags*
  '(;; from  0 to 31

    (:ntlmssp-negotiate-56           "requests 56-bit encryption")
    (:ntlmssp-negotiate-key-exch     "requests explicit key exchange")
    (:ntlmssp-negotiate-128          "requests 128-bit session key negotiation")
    (:reserved-1                     "reserved 1")
    (:reserved-2                     "reserved 2")
    (:reserved-3                     "reserved 3")
    (:ntlmssp-negotiate-version      "request the protocol version number")
    (:reserved-4                     "reserved 4")
    (:ntlmssp-negotiate-target-info  "TargetInfo fields in challenge_message are populated")
    (:ntlmssp-negotiate-request-non-nt-session-key "requests non NT session key (LMOWF)")
    (:reserved-5                     "reserved 5")
    (:ntlmssp-negotiate-identify     "requests an identify level token")
    (:ntlmssp-negotiate-extended-session-security "requests NTLM v2 session security")
    (:reserved-6                     "reserved 6")
    (:ntlmssp-target-type-domain     "TargetName must be a domain name")
    (:ntlmssp-negotiate-always-sign  "requests signature blocks on all messages")
    (:reserved-7                     "reserved 7")
    (:ntlmssp-negotiate-oem-workstation-supplied "workstation field present")
    (:ntlmssp-negotiate-oem-domain-supplied      "domain name provided")
    (nil "connection should be anonymous")
    (:reserved-8                     "reserved 8")
    ))

(defun decode-ntlm-negotiate-flags (flags)

  )

(decode-ntlm-negoctate-flags #xe20882b7) 
