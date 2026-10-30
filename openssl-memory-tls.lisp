;(openssl-memory-tls::run-integration-test "localhost.crt" "localhost.key")
;;;; openssl-memory-tls.lisp
;;;; OpenSSL Memory BIO + TLS/SSL 层封装
;;;; 依赖：openssl-memory-bio.lisp, CFFI, Babel, Ubuntu libssl-dev
;;;; 修正说明：修复 BIO 双重释放导致的段错误，修正结构体类型标注

(defpackage #:openssl-memory-tls
  (:use #:cl #:cffi #:openssl-memory-bio)
  (:shadow #:read)
  (:export
   #:tls-session
   #:tls-session-p
   #:tls-session-ssl-pointer
   #:tls-session-read-bio
   #:tls-session-write-bio
   #:tls-session-role
   #:create-tls-context
   #:free-tls-context
   #:tls-context-load-certificate
   #:create-client-tls-session
   #:create-server-tls-session
   #:free-tls-session
   #:tls-handshake-step
   #:tls-handshake-completed-p
   #:perform-memory-handshake
   #:send
   #:read
   #:tls-write-plaintext-bytes
   #:tls-read-plaintext-bytes
   #:tls-write-plaintext-string
   #:tls-read-plaintext-string
   #:tls-feed-ciphertext-input
   #:tls-get-ciphertext-output
   #:tls-shutdown
   #:with-tls-context
   #:with-tls-session
   #:run-integration-test))

(in-package #:openssl-memory-tls)

;;; ============================================================================
;;; 1. 加载 libssl 动态库
;;; ============================================================================

(define-foreign-library libssl
  (:unix (:or "libssl.so" "libssl.so.3"))
  (t (:default "libssl")))

(use-foreign-library libssl)

;;; ============================================================================
;;; 2. TLS 常量定义
;;; ============================================================================

(defconstant +ssl-error-none+ 0)
(defconstant +ssl-error-want-read+ 2)
(defconstant +ssl-error-want-write+ 3)
(defconstant +ssl-error-zero-return+ 6)
(defconstant +ssl-error-syscall+ 5)
(defconstant +ssl-error-ssl+ 1)
(defconstant +ssl-filetype-pem+ 1)
(defconstant +ssl-verify-none+ #x00)
(defconstant +ssl-verify-peer+ #x01)

;;; ============================================================================
;;; 3. 底层 libssl C API 绑定
;;; ============================================================================

(defcfun ("TLS_client_method" %tls-client-method) :pointer)
(defcfun ("TLS_server_method" %tls-server-method) :pointer)

(defcfun ("SSL_CTX_new" %ssl-ctx-new) :pointer
  (method :pointer))

(defcfun ("SSL_CTX_free" %ssl-ctx-free) :void
  (ctx :pointer))

(defcfun ("SSL_CTX_use_certificate_file" %ssl-ctx-use-certificate-file) :int
  (ctx :pointer)
  (file :string)
  (type :int))

(defcfun ("SSL_CTX_use_PrivateKey_file" %ssl-ctx-use-privatekey-file) :int
  (ctx :pointer)
  (file :string)
  (type :int))

(defcfun ("SSL_CTX_set_verify" %ssl-ctx-set-verify) :void
  (ctx :pointer)
  (mode :int)
  (callback :pointer))

(defcfun ("SSL_new" %ssl-new) :pointer
  (ctx :pointer))

(defcfun ("SSL_free" %ssl-free) :void
  (ssl :pointer))

(defcfun ("SSL_set_bio" %ssl-set-bio) :void
  (ssl :pointer)
  (read-bio bio-pointer)
  (write-bio bio-pointer))

(defcfun ("SSL_set_connect_state" %ssl-set-connect-state) :void
  (ssl :pointer))

(defcfun ("SSL_set_accept_state" %ssl-set-accept-state) :void
  (ssl :pointer))

(defcfun ("SSL_do_handshake" %ssl-do-handshake) :int
  (ssl :pointer))

(defcfun ("SSL_is_init_finished" %ssl-is-init-finished) :int
  (ssl :pointer))

(defcfun ("SSL_read" %ssl-read) :int
  (ssl :pointer)
  (buffer :pointer)
  (length :int))

(defcfun ("SSL_write" %ssl-write) :int
  (ssl :pointer)
  (buffer :pointer)
  (length :int))

(defcfun ("SSL_shutdown" %ssl-shutdown) :int
  (ssl :pointer))

(defcfun ("SSL_get_error" %ssl-get-error) :int
  (ssl :pointer)
  (return-code :int))

(defcfun ("ERR_get_error" %err-get-error) :unsigned-long)

(defcfun ("ERR_error_string_n" %err-error-string-n) :void
  (error-code :unsigned-long)
  (buffer :pointer)
  (buffer-size :int))

;;; ============================================================================
;;; 4. TLS 会话结构体
;;; ============================================================================

(defstruct (tls-session (:constructor %make-tls-session))
  "TLS 会话封装，包含 SSL 对象与一对内存 BIO。
注意：BIO 所有权归 SSL 对象，由 SSL_free 统一释放。"
  (ssl-pointer (null-pointer))
  (read-bio (null-pointer))
  (write-bio (null-pointer))
  (role :client :type (member :client :server)))

;;; ============================================================================
;;; 5. 内部错误工具
;;; ============================================================================

(defun get-last-ssl-error-string ()
  "获取 OpenSSL 错误队列最新错误描述。"
  (let ((err-code (%err-get-error)))
    (if (zerop err-code)
        "Unknown SSL error"
        (with-foreign-pointer (buf 256 buf-size)
          (%err-error-string-n err-code buf buf-size)
          (foreign-string-to-lisp buf)))))

;;; ============================================================================
;;; 6. SSL 上下文管理
;;; ============================================================================

(defun create-tls-context (role &key (verify-mode +ssl-verify-none+))
  "创建 TLS 上下文对象。ROLE 为 :client 或 :server。"
  (let* ((method (ecase role
                   (:client (%tls-client-method))
                   (:server (%tls-server-method))))
         (ctx (%ssl-ctx-new method)))
    (when (null-pointer-p ctx)
      (error "Failed to create TLS context: ~a" (get-last-ssl-error-string)))
    (%ssl-ctx-set-verify ctx verify-mode (null-pointer))
    ctx))

(defun free-tls-context (ctx)
  "释放 TLS 上下文资源。"
  (unless (pointerp ctx)
    (error "Argument to free-tls-context must be a valid pointer."))
  (%ssl-ctx-free ctx)
  (values))

(defun tls-context-load-certificate (ctx certificate-file private-key-file)
  "加载 PEM 格式证书和私钥到服务端上下文。"
  (unless (pointerp ctx)
    (error "Argument to tls-context-load-certificate must be a valid pointer."))
  (let ((cert-ret (%ssl-ctx-use-certificate-file ctx certificate-file +ssl-filetype-pem+)))
    (when (<= cert-ret 0)
      (error "Failed to load certificate ~s: ~a"
             certificate-file (get-last-ssl-error-string))))
  (let ((key-ret (%ssl-ctx-use-privatekey-file ctx private-key-file +ssl-filetype-pem+)))
    (when (<= key-ret 0)
      (error "Failed to load private key ~s: ~a"
             private-key-file (get-last-ssl-error-string))))
  t)

;;; ============================================================================
;;; 7. TLS 会话创建与释放（核心修复：避免双重释放）
;;; ============================================================================

(defun create-client-tls-session (ctx)
  "创建客户端 TLS 会话，自动绑定内存 BIO 对。"
  (unless (pointerp ctx)
    (error "Argument to create-client-tls-session must be a valid context pointer."))
  (let ((ssl (%ssl-new ctx))
        (rbio (create-memory-bio))
        (wbio (create-memory-bio)))
    (cond
      ((null-pointer-p ssl)
       ;; SSL 创建失败，BIO 尚未绑定，手动释放
       (free-bio rbio)
       (free-bio wbio)
       (error "Failed to create client SSL object: ~a" (get-last-ssl-error-string)))
      (t
       ;; 绑定 BIO 后，所有权转移给 SSL 对象
       (%ssl-set-bio ssl rbio wbio)
       (%ssl-set-connect-state ssl)
       (%make-tls-session :ssl-pointer ssl
                          :read-bio rbio
                          :write-bio wbio
                          :role :client)))))

(defun create-server-tls-session (ctx)
  "创建服务端 TLS 会话，自动绑定内存 BIO 对。"
  (unless (pointerp ctx)
    (error "Argument to create-server-tls-session must be a valid context pointer."))
  (let ((ssl (%ssl-new ctx))
        (rbio (create-memory-bio))
        (wbio (create-memory-bio)))
    (cond
      ((null-pointer-p ssl)
       ;; SSL 创建失败，BIO 尚未绑定，手动释放
       (free-bio rbio)
       (free-bio wbio)
       (error "Failed to create server SSL object: ~a" (get-last-ssl-error-string)))
      (t
       ;; 绑定 BIO 后，所有权转移给 SSL 对象
       (%ssl-set-bio ssl rbio wbio)
       (%ssl-set-accept-state ssl)
       (%make-tls-session :ssl-pointer ssl
                          :read-bio rbio
                          :write-bio wbio
                          :role :server)))))

(defun free-tls-session (session)
  "释放 TLS 会话所有资源。
注意：BIO 已随 SSL 对象一同释放，禁止重复释放 BIO 指针。"
  (unless (tls-session-p session)
    (error "Argument to free-tls-session must be a valid tls-session object."))
  (let ((ssl (tls-session-ssl-pointer session)))
    (unless (null-pointer-p ssl)
      ;; SSL_free 会自动释放绑定的读写 BIO，无需手动释放
      (%ssl-free ssl)))
  ;; 仅置空指针，避免野指针引用
  (setf (tls-session-ssl-pointer session) (null-pointer)
        (tls-session-read-bio session) (null-pointer)
        (tls-session-write-bio session) (null-pointer))
  (values))

;;; ============================================================================
;;; 8. 密文输入输出接口
;;; ============================================================================

(defun tls-feed-ciphertext-input (session ciphertext-bytes)
  "将对端密文喂入本端 TLS 读缓冲区。"
  (unless (tls-session-p session)
    (error "Argument to tls-feed-ciphertext-input must be a valid tls-session."))
  (bio-write-bytes (tls-session-read-bio session) ciphertext-bytes))

(defun tls-get-ciphertext-output (session)
  "从本端 TLS 写缓冲区读出所有待发送密文。"
  (unless (tls-session-p session)
    (error "Argument to tls-get-ciphertext-output must be a valid tls-session."))
  (bio-read-all-bytes (tls-session-write-bio session)))

;;; ============================================================================
;;; 9. 握手流程控制
;;; ============================================================================

(defun tls-handshake-completed-p (session)
  "检查 TLS 握手是否完成，返回布尔值。"
  (unless (tls-session-p session)
    (error "Argument to tls-handshake-completed-p must be a valid tls-session."))
  (= 1 (%ssl-is-init-finished (tls-session-ssl-pointer session))))

(defun tls-handshake-step (session)
  "执行单步握手，返回 :completed / :want-read / :want-write / :error。"
  (unless (tls-session-p session)
    (error "Argument to tls-handshake-step must be a valid tls-session."))
  (let ((ret (%ssl-do-handshake (tls-session-ssl-pointer session))))
    (cond
      ((> ret 0) :completed)
      ((= ret 0) :error)
      (t
       (let ((err (%ssl-get-error (tls-session-ssl-pointer session) ret)))
         (cond
           ((= err +ssl-error-want-write+) :want-write)
           ((= err +ssl-error-want-read+) :want-read)
           (t :error)))))))

(defun perform-memory-handshake (client-session server-session &key (max-steps 50))
  "纯内存环境自动完成两端完整握手。"
  (unless (and (tls-session-p client-session) (tls-session-p server-session))
    (error "Arguments to perform-memory-handshake must be valid tls-session objects."))
  (loop repeat max-steps
        do
    (tls-handshake-step client-session)
    (tls-handshake-step server-session)
    (let ((client-out (tls-get-ciphertext-output client-session)))
      (when (> (length client-out) 0)
        (tls-feed-ciphertext-input server-session client-out)))
    (let ((server-out (tls-get-ciphertext-output server-session)))
      (when (> (length server-out) 0)
        (tls-feed-ciphertext-input client-session server-out)))
    (when (and (tls-handshake-completed-p client-session)
               (tls-handshake-completed-p server-session))
      (return-from perform-memory-handshake t)))
  (error "TLS handshake failed to complete within ~d steps." max-steps))

;;; ============================================================================
;;; 10. 非阻塞标准 IO：send / read
;;; ============================================================================

(defun send (session data-vector)
  "非阻塞写入明文字节，返回实际写入字节数。返回 0 表示暂不可写。"
  (unless (tls-session-p session)
    (error "Argument to send must be a valid tls-session object."))
  (check-type data-vector (vector (unsigned-byte 8)))
  (let ((data-length (length data-vector)))
    (when (zerop data-length)
      (return-from send 0))
    (with-foreign-object (buf :unsigned-char data-length)
      (dotimes (i data-length)
        (setf (mem-aref buf :unsigned-char i) (aref data-vector i)))
      (let ((ret (%ssl-write (tls-session-ssl-pointer session) buf data-length)))
        (cond
          ((> ret 0) ret)
          ((= ret 0) 0)
          (t
           (let ((err (%ssl-get-error (tls-session-ssl-pointer session) ret)))
             (cond
               ((or (= err +ssl-error-want-read+)
                    (= err +ssl-error-want-write+))
                0)
               ((= err +ssl-error-zero-return+) 0)
               (t
                (error "TLS send failed: ~a" (get-last-ssl-error-string)))))))))))

(defun read (session buffer-vector)
  "非阻塞读取明文到调用方缓冲区，返回实际读取字节数。返回 0 表示无数据。"
  (unless (tls-session-p session)
    (error "Argument to read must be a valid tls-session object."))
  (check-type buffer-vector (vector (unsigned-byte 8)))
  (let ((buf-size (length buffer-vector)))
    (when (zerop buf-size)
      (return-from read 0))
    (with-foreign-object (buf :unsigned-char buf-size)
      (let ((ret (%ssl-read (tls-session-ssl-pointer session) buf buf-size)))
        (cond
          ((> ret 0)
           (dotimes (i ret)
             (setf (aref buffer-vector i) (mem-aref buf :unsigned-char i)))
           ret)
          ((= ret 0) 0)
          (t
           (let ((err (%ssl-get-error (tls-session-ssl-pointer session) ret)))
             (cond
               ((or (= err +ssl-error-want-read+)
                    (= err +ssl-error-want-write+))
                0)
               ((= err +ssl-error-zero-return+) 0)
               (t
                (error "TLS read failed: ~a" (get-last-ssl-error-string)))))))))))

;;; ============================================================================
;;; 11. 兼容接口与字符串高层接口
;;; ============================================================================

(defun tls-write-plaintext-bytes (session plaintext-bytes)
  "兼容接口：写入明文字节。推荐使用 send。"
  (send session plaintext-bytes))

(defun tls-read-plaintext-bytes (session max-length)
  "兼容接口：读取明文字节。推荐使用 read。"
  (check-type max-length (integer 1))
  (let ((buf (make-array max-length :element-type '(unsigned-byte 8))))
    (let ((n (read session buf)))
      (subseq buf 0 n))))

(defun tls-write-plaintext-string (session string)
  "写入 UTF-8 字符串，返回实际写入字节数。"
  (check-type string string)
  (send session (babel:string-to-octets string :encoding :utf-8)))

(defun tls-read-plaintext-string (session max-byte-length)
  "读取明文并解码为 UTF-8 字符串。"
  (check-type max-byte-length (integer 1))
  (let ((bytes (tls-read-plaintext-bytes session max-byte-length)))
    (babel:octets-to-string bytes :encoding :utf-8)))

;;; ============================================================================
;;; 12. 连接关闭
;;; ============================================================================

(defun tls-shutdown (session)
  "发起 TLS 正常关闭，返回 :completed 或 :want-write。"
  (unless (tls-session-p session)
    (error "Argument to tls-shutdown must be a valid tls-session object."))
  (let ((ret (%ssl-shutdown (tls-session-ssl-pointer session))))
    (cond
      ((= ret 1) :completed)
      ((= ret 0) :want-write)
      (t
       (let ((err (%ssl-get-error (tls-session-ssl-pointer session) ret)))
         (if (= err +ssl-error-want-write+)
             :want-write
             (error "TLS shutdown failed: ~a" (get-last-ssl-error-string))))))))

;;; ============================================================================
;;; 13. 便捷宏
;;; ============================================================================

(defmacro with-tls-context ((var role &rest options) &body body)
  `(let ((,var (create-tls-context ,role ,@options)))
     (unwind-protect
          (progn ,@body)
       (free-tls-context ,var))))

(defmacro with-tls-session ((var create-form) &body body)
  `(let ((,var ,create-form))
     (unwind-protect
          (progn ,@body)
       (free-tls-session ,var))))

;;; ============================================================================
;;; 14. 集成自测
;;; ============================================================================

(defun run-integration-test (cert-file key-file)
  "运行完整内存 TLS 集成测试。"
  (format t "~&=== Running Memory TLS Integration Test ===~%")
  (with-tls-context (server-ctx :server)
    (tls-context-load-certificate server-ctx cert-file key-file)
    (with-tls-context (client-ctx :client)
      (with-tls-session (server (create-server-tls-session server-ctx))
        (with-tls-session (client (create-client-tls-session client-ctx))
          (format t "Performing TLS handshake...~%")
          (perform-memory-handshake client server)
          (assert (and (tls-handshake-completed-p client)
                       (tls-handshake-completed-p server)))
          (format t "Handshake completed successfully.~%")

          (let ((test-message "Hello, Memory TLS! 内存加密通信测试"))
            (format t "Client sending: ~s~%" test-message)
            (send client (babel:string-to-octets test-message :encoding :utf-8))
            (let ((ciphertext (tls-get-ciphertext-output client)))
              (format t "Ciphertext length: ~d bytes~%" (length ciphertext))
              (tls-feed-ciphertext-input server ciphertext))
            (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
              (let ((n (read server buf)))
                (let ((received (babel:octets-to-string buf :end n :encoding :utf-8)))
                  (format t "Server received: ~s~%" received)
                  (assert (string= test-message received))
                  (format t "Client->Server transfer PASSED~%")))))

          (let ((reply "Server response: message received 服务端已收到"))
            (format t "Server replying: ~s~%" reply)
            (send server (babel:string-to-octets reply :encoding :utf-8))
            (let ((ciphertext (tls-get-ciphertext-output server)))
              (tls-feed-ciphertext-input client ciphertext))
            (let ((buf (make-array 1024 :element-type '(unsigned-byte 8))))
              (let ((n (read client buf)))
                (let ((received (babel:octets-to-string buf :end n :encoding :utf-8)))
                  (format t "Client received: ~s~%" received)
                  (assert (string= reply received))
                  (format t "Server->Client transfer PASSED~%")))))

          (tls-shutdown client)
          (tls-shutdown server)
          (format t "Shutdown completed.~%")))))
  (format t "~&=== All Memory TLS tests passed ===~%")
  t)

  ;(openssl-memory-tls::run-integration-test "localhost.crt" "localhost.key")
