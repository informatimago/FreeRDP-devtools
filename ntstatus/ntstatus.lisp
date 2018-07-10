(ql:quickload :xmls)
(ql:quickload :split-sequence)



'((:ntstatus "https://msdn.microsoft.com/en-us/library/cc704588.aspx")
  (:hresult  "https://msdn.microsoft.com/en-us/library/cc704587.aspx"))

(defun skip-to-begining-of-line-with (stream substring)
  (loop
    :for pos := (file-position stream)
    :for line := (read-line stream)
    :until (search substring line)
    :finally (file-position stream pos)))

(defun flatten-text (items)
  (let ((out (with-output-to-string (*standard-output*)
               (dolist (item items)
                 (write-string (if (stringp item)
                                   item
                                   (flatten-text (xmls:node-children item))))
                 (write-string " ")))))
    (if (plusp (length out))
        (subseq out 0 (1- (length out)))
        out)))


(defun windows-status-codes ()
  (let ((*default-pathname-defaults* (if *load-truename*
                                         (make-pathname :name nil :type nil :version nil
                                                        :defaults *load-truename*)
                                         #P"~/src/public/FreeRDP-devtools/ntstatus/"))
        (entries '()))
    
    (dolist (table (list (with-open-file (ntstatus "NTSTATUS-Values.xml")
                           (xmls:parse ntstatus :quash-errors nil))
                         (with-open-file (ntstatus "HRESULT-Values.xml")
                           (xmls:parse ntstatus :quash-errors nil))))
      (dolist (row (xmls:xmlrep-find-child-tags "tr" (xmls:xmlrep-find-child-tag "tbody"  table)))
        (unless (xmls:xmlrep-find-child-tags "th" row)
          (destructuring-bind (value-code description) (xmls:xmlrep-find-child-tags "td" row)
            (destructuring-bind (value code)
                (mapcar (lambda (node) (flatten-text (xmls:node-children node)))
                        (xmls:xmlrep-find-child-tags "p" value-code))
              (let ((value (or (ignore-errors (read-from-string (if (and (< 2 (length value))
                                                                         (char= #\x (aref value 1)))
                                                                    (concatenate 'string "#" (subseq value 1))
                                                                    value)))
                               value)))
                (push (list value code
                            (flatten-text (mapcan (function xmls:node-children)
                                                  (xmls:xmlrep-find-child-tags "p" description))))
                      entries)))))))
    (sort entries (function <) :key (function first))))



(defun format-c-string-in (string)
  (with-output-to-string (*standard-output*)
   (loop
     :for ch :across string
     :do (case ch
           ((#\bell)      (write-string "\\a"))
           ((#\backspace) (write-string "\\b"))
           ((#\newline)   (write-string "\\n"))
           ((#\return)    (write-string "\\r"))
           ((#\tab)       (write-string "\\t"))
           ((#\pageup)    (write-string "\\v"))
           ((#\\)         (write-string "\\\\"))
           ((#\")         (write-string "\\\""))
           ((#\esc)       (write-string "\\e"))
           (otherwise (cond
                        ((<= 32 (char-code ch) 126)
                         (write-char ch))
                        ((< (char-code ch) 256)
                         (format t "\\~3,'0o" (char-code ch)))
                        ((< (char-code ch) #x10000)
                         (format t "\\u~4,'0x" (char-code ch)))
                        (t
                         (format t "\\U~8,'0x" (char-code ch)))))))))


(defun gen-c-string-literal (string)
  (format nil "(~{\"~A\\n\"~^~%~})"
          (mapcar (lambda (line) (format-c-string-in (string-trim " " line)))
                  (split-sequence:split-sequence #\newline string))))


(defun gen-c-status-code-case (codes vstatus vprinter)
  (with-output-to-string (*standard-output*)
    (format t "switch(~A)~%" vstatus)
    (format t "{~%")
    (loop :for (value code description) :in codes
          :do (format t "case 0x~8,'0X:~%~A(~A, \"~A\", ~% ~A);~%break;~%"
                      value vprinter vstatus code (gen-c-string-literal description)))
    (format t "default:~%")
    (format t "  ~A(~A, \"Unexpected status code\", \"\");~%" vprinter vstatus)
    (format t "  break;~%")
    (format t "}~%")))




(defun generate-ntstatus-report-source (codes)
  (format t "
/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * NTStatus description printing function.
 *
 * Copyright 2018 Pascal J. Bourguignon <pjb@informatimago.com>
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include \"config.h\"
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

#include <freerdp/log.h>

static void print_nt_status(unsigned long value,const char* status,const char* description)
{
    WLog_ERR(TAG, \"%s [0x%08x]\", status, value);
    WLog_DBG(TAG, \"%s\", description);
}

void ntstatus_report(unsigned long value)
{
~A
}"
          (gen-c-status-code-case codes "value" "print_nt_status")))


(let ((name #P"ntstatus"))
  (with-open-file (*standard-output* (merge-pathnames name #P".c")
                                     :direction :output
                                     :if-does-not-exist :create
                                     :if-exists :supersede)
    (generate-ntstatus-report-source
     (windows-status-codes)))
  (with-open-file (*standard-output* (merge-pathnames name #P".h")
                                     :direction :output
                                     :if-does-not-exist :create
                                     :if-exists :supersede)
    (generate-ntstatus-report-header)))



