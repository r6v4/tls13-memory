;;;; tls13-memory-server-example.lisp
;;;; 与网络完全解耦的 TLS 1.3 服务端实现示例
;;;; 修正说明：常量本地定义，消除跨包符号依赖；修复空向量类型校验

(in-package #:tls13-memory)

;;; ============================================================================
;;; 1. 本地常量定义（与OpenSSL标准值一致，不依赖外部包导出）
;;; ============================================================================

;; 协议版本禁用选项
(defconstant +ssl-op-no-tls-v1+   #x04000000
  "禁用 TLS 1.0。")
(defconstant +ssl-op-no-tls-v1-1+ #x10000000
  "禁用 TLS 1.1。")
(defconstant +ssl-op-no-tls-v1-2+ #x08000000
  "禁用 TLS 1.2。")

;; 证书验证模式
(defconstant +verify-none+ 0
  "不验证对端证书。")

;;; ============================================================================
;;; 2. C API 绑定
;;; ============================================================================

(defcfun ("SSL_CTX_set_options" %ssl-ctx-set-options) :unsigned-long
  "设置 SSL 上下文选项，返回最终生效的选项掩码。"
  (ctx :pointer)
  (options :unsigned-long))

;;; ============================================================================
;;; 3. TLS 1.3 上下文管理
;;; ============================================================================

(defun create-tls13-server-context (certificate-file private-key-file)
  "创建仅支持 TLS 1.3 的服务端上下文。"
  (let ((ctx (openssl-memory-tls:create-tls-context
              :server :verify-mode +verify-none+)))
    ;; 禁用所有旧版本协议，仅保留 TLS 1.3
    (%ssl-ctx-set-options
     ctx
     (logior +ssl-op-no-tls-v1+
             +ssl-op-no-tls-v1-1+
             +ssl-op-no-tls-v1-2+))
    ;; 加载证书与私钥
    (openssl-memory-tls:tls-context-load-certificate
     ctx certificate-file private-key-file)
    ctx))

;;; ============================================================================
;;; 4. 服务端连接对象
;;; ============================================================================

(defstruct tls13-server-connection
  (session nil)
  (state :handshaking :type (member :handshaking :established :closed :error))
  (pending-plaintext nil :type list))

(defun create-tls13-server-connection (tls-context)
  (unless (pointerp tls-context)
    (error "Argument must be a valid context pointer."))
  (make-tls13-server-connection
   :session (openssl-memory-tls:create-server-tls-session tls-context)
   :state :handshaking
   :pending-plaintext nil))

(defun free-tls13-server-connection (connection)
  (unless (tls13-server-connection-p connection)
    (error "Argument must be a valid connection object."))
  (when (tls13-server-connection-session connection)
    (openssl-memory-tls:free-tls-session
     (tls13-server-connection-session connection)))
  (setf (tls13-server-connection-session connection) nil
        (tls13-server-connection-state connection) :closed
        (tls13-server-connection-pending-plaintext connection) nil)
  (values))

;;; ============================================================================
;;; 5. 核心：统一数据处理入口（与网络完全解耦）
;;; ============================================================================

(defun tls13-server-handle-input (connection input-ciphertext)
  "输入密文字节，返回 (输出密文, 当前状态, 明文列表)。"
  (unless (tls13-server-connection-p connection)
    (error "Argument must be a valid connection object."))
  ;; 兼容空向量：自动转换为正确类型的字节向量
  (let ((input (if (and (vectorp input-ciphertext)
                        (= (length input-ciphertext) 0))
                   (make-array 0 :element-type '(unsigned-byte 8))
                   input-ciphertext)))
    (check-type input (vector (unsigned-byte 8)))
    (let ((session (tls13-server-connection-session connection))
          (output-bytes (make-array 0 :element-type '(unsigned-byte 8)
                                      :adjustable t
                                      :fill-pointer 0))
          (received-plaintext nil))

      (when (> (length input) 0)
        (openssl-memory-tls:tls-feed-ciphertext-input session input))

      (ecase (tls13-server-connection-state connection)
        (:handshaking
         (let ((handshake-status (openssl-memory-tls:tls-handshake-step session)))
           (cond
             ((eq handshake-status :completed)
              (setf (tls13-server-connection-state connection) :established)
              (setf received-plaintext (drain-all-plaintext session)))
             ((or (eq handshake-status :want-read)
                  (eq handshake-status :want-write))
              nil)
             (t
              (setf (tls13-server-connection-state connection) :error)))))

        (:established
         (setf received-plaintext (drain-all-plaintext session))
         (when (and (null received-plaintext)
                    (= 0 (bio-available-bytes
                          (openssl-memory-tls:tls-session-read-bio session))))
           (let ((test-buf (make-array 1 :element-type '(unsigned-byte 8))))
             (when (= 0 (openssl-memory-tls:read session test-buf))
               (setf (tls13-server-connection-state connection) :closed)))))

        (:closed nil)
        (:error nil))

      (let ((out-chunk (openssl-memory-tls:tls-get-ciphertext-output session)))
        (when (> (length out-chunk) 0)
          (loop for byte across out-chunk
                do (vector-push-extend byte output-bytes))))

      (when received-plaintext
        (setf (tls13-server-connection-pending-plaintext connection)
              (append (tls13-server-connection-pending-plaintext connection)
                      received-plaintext)))

      (values output-bytes
              (tls13-server-connection-state connection)
              received-plaintext))))

;;; ============================================================================
;;; 6. 内部辅助函数
;;; ============================================================================

(defun drain-all-plaintext (session &key (chunk-size 4096))
  "排空所有可用明文，返回字节向量列表。"
  (loop with buf = (make-array chunk-size :element-type '(unsigned-byte 8))
        for n = (openssl-memory-tls:read session buf)
        while (> n 0)
        collect (subseq buf 0 n)))

;;; ============================================================================
;;; 7. 应用层响应逻辑
;;; ============================================================================

(defun generate-application-response (request-bytes)
  "应用层 Echo 响应逻辑，可替换为任意业务。"
  (let ((request-string (babel:octets-to-string request-bytes :encoding :utf-8)))
    (babel:string-to-octets
     (format nil "[TLS 1.3 Server Echo] ~a" request-string)
     :encoding :utf-8)))

(defun tls13-server-send-response (connection response-bytes)
  "将应用层响应加密到 TLS 写缓冲区。"
  (unless (tls13-server-connection-p connection)
    (error "Argument must be a valid connection object."))
  (check-type response-bytes (vector (unsigned-byte 8)))
  (when (eq (tls13-server-connection-state connection) :established)
    (openssl-memory-tls:send
     (tls13-server-connection-session connection)
     response-bytes)))

;;; ============================================================================
;;; 8. 纯内存集成自测
;;; ============================================================================

(defun run-tls13-memory-server-test (cert-file key-file)
  "运行完整内存态 TLS 1.3 服务端测试。"
  (format t "~&===== TLS 1.3 Memory Server Test =====~%")
  (let ((server-ctx (create-tls13-server-context cert-file key-file))
        (client-ctx (openssl-memory-tls:create-tls-context
                     :client :verify-mode +verify-none+))
        (empty-bytes (make-array 0 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           ;; 客户端同样禁用旧版本，强制使用 TLS 1.3
           (%ssl-ctx-set-options
            client-ctx
            (logior +ssl-op-no-tls-v1+
                    +ssl-op-no-tls-v1-1+
                    +ssl-op-no-tls-v1-2+))

           (let ((server-conn (create-tls13-server-connection server-ctx))
                 (client-sess (openssl-memory-tls:create-client-tls-session client-ctx)))
             (unwind-protect
                  (progn
                    ;; 握手阶段
                    (format t "~&--- Starting TLS 1.3 Handshake ---~%")
                    (loop for step from 1
                          with handshake-done = nil
                          until handshake-done
                          do
                      (openssl-memory-tls:tls-handshake-step client-sess)
                      (multiple-value-bind (server-out server-state)
                          (tls13-server-handle-input
                           server-conn
                           (openssl-memory-tls:tls-get-ciphertext-output client-sess))
                        (openssl-memory-tls:tls-feed-ciphertext-input client-sess server-out)
                        (format t "  Step ~d: state=~a, output=~d bytes~%"
                                step server-state (length server-out))
                        (setf handshake-done
                              (and (eq server-state :established)
                                   (openssl-memory-tls:tls-handshake-completed-p client-sess)))))
                    (format t "~&--- Handshake Completed ---~%")
                    (assert (eq (tls13-server-connection-state server-conn) :established))
                    (format t "TLS 1.3 handshake verified success.~%")

                    ;; 应用数据传输
                    (format t "~&--- Application Data Transfer ---~%")
                    (let ((client-message "Hello TLS 1.3 Server! 你好，纯内存服务端"))
                      (format t "Client sends: ~s~%" client-message)
                      (openssl-memory-tls:send
                       client-sess
                       (babel:string-to-octets client-message :encoding :utf-8))
                      (multiple-value-bind (server-out state plaintext-list)
                          (tls13-server-handle-input
                           server-conn
                           (openssl-memory-tls:tls-get-ciphertext-output client-sess))
                        (declare (ignore state))
                        (dolist (chunk plaintext-list)
                          (format t "Server received: ~s~%"
                                  (babel:octets-to-string chunk :encoding :utf-8)))
                        (dolist (chunk plaintext-list)
                          (tls13-server-send-response
                           server-conn
                           (generate-application-response chunk)))
                        ;; 取出响应密文
                        (multiple-value-bind (response-cipher)
                            (tls13-server-handle-input server-conn empty-bytes)
                          (openssl-memory-tls:tls-feed-ciphertext-input
                           client-sess response-cipher))))
                      (let ((buf (make-array 4096 :element-type '(unsigned-byte 8))))
                        (let ((n (openssl-memory-tls:read client-sess buf)))
                          (let ((response (babel:octets-to-string buf :end n :encoding :utf-8)))
                            (format t "Client received: ~s~%" response)
                            (assert (search "TLS 1.3 Server Echo" response))
                            (format t "Application data transfer PASSED~%")))))

                    ;; 关闭连接
                    (format t "~&--- Connection Shutdown ---~%")
                    (openssl-memory-tls:tls-shutdown client-sess)
                    (tls13-server-handle-input
                     server-conn
                     (openssl-memory-tls:tls-get-ciphertext-output client-sess))
                    (format t "Connection closed gracefully.~%"))
               (free-tls13-server-connection server-conn)
               (openssl-memory-tls:free-tls-session client-sess)))
      (openssl-memory-tls:free-tls-context server-ctx)
      (openssl-memory-tls:free-tls-context client-ctx)))
  (format t "~&===== All TLS 1.3 Tests Passed =====~%")
  t)

#|
(defun run-tls13-memory-server-test (cert-file key-file)
  "纯内存环境下的 TLS 1.3 服务端集成测试。
测试目标：验证服务端在完全无网络依赖的情况下，能否完整完成 TLS 1.3 握手、加密数据收发与优雅关闭。
测试架构：
  - 服务端：使用本文件实现的 tls13-server-connection 高层封装
  - 客户端：使用底层 tls-session 模拟真实客户端
  - 传输层：完全通过手动搬运密文字节模拟网络传输，无任何系统网络调用
覆盖功能：
  1. TLS 1.3 全流程握手协商
  2. 客户端 -> 服务端加密数据传输
  3. 服务端业务响应与加密回传
  4. 客户端解密验证数据正确性
  5. TLS 连接优雅关闭
  6. 所有资源正确释放，无内存泄漏"
  (format t "~&===== TLS 1.3 Memory Server Test =====~%")

  ;; ======================================================================
  ;; 阶段一：初始化 TLS 全局上下文
  ;; ======================================================================
  ;; TLS 上下文（CTX）是全局配置对象，包含证书、协议版本、验证模式等设置
  ;; 一个上下文可以复用于成千上万条连接，对应真实服务端的全局配置
  (let* (
         ;; 服务端上下文：加载证书私钥，禁用旧版本协议，仅支持 TLS 1.3
         (server-ctx (create-tls13-server-context cert-file key-file))
         ;; 客户端上下文：关闭证书验证（测试场景），同样仅支持 TLS 1.3
         (client-ctx (openssl-memory-tls:create-tls-context
                      :client :verify-mode +verify-none+))
         ;; 预定义类型正确的空字节向量，用于触发服务端输出缓冲区刷新
         ;; 不直接使用 #() 是因为其元素类型不满足 (unsigned-byte 8) 校验
         (empty-bytes (make-array 0 :element-type '(unsigned-byte 8))))

    ;; unwind-protect 保证即使测试中途报错，也能正确释放资源，避免内存泄漏
    (unwind-protect
         (progn
           ;; 给客户端上下文也禁用所有旧版本协议，强制两端协商 TLS 1.3
           (%ssl-ctx-set-options
            client-ctx
            (logior +ssl-op-no-tls-v1+
                    +ssl-op-no-tls-v1-1+
                    +ssl-op-no-tls-v1-2+))

           ;; ======================================================================
           ;; 阶段二：创建单条连接的状态机
           ;; ======================================================================
           ;; 真实服务端每接受一个客户端连接，就创建一个 connection 对象
           ;; 这里创建一组客户端-服务端连接对，模拟一条完整的 TLS 链路
           (let (
                 ;; 服务端连接对象：高层封装，包含 TLS 会话 + 业务状态机
                 (server-conn (create-tls13-server-connection server-ctx))
                 ;; 客户端会话对象：底层 TLS 会话，模拟真实客户端行为
                 (client-sess (openssl-memory-tls:create-client-tls-session client-ctx)))

             (unwind-protect
                  (progn
                    ;; ======================================================================
                    ;; 阶段三：TLS 1.3 握手流程
                    ;; ======================================================================
                    ;; TLS 握手是多轮交互协议：客户端发 ClientHello -> 服务端回 ServerHello...
                    ;; 每一步只处理当前可用数据，产生输出后等待对端响应
                    ;; 循环直到两端都确认握手完成，对应真实网络中多次 TCP 报文往返
                    (format t "~&--- Starting TLS 1.3 Handshake ---~%")
                    (loop for step from 1
                          with handshake-done = nil
                          until handshake-done
                          do
                       ;; 客户端前进一步握手：如果有数据要发就写入写 BIO
                       (openssl-memory-tls:tls-handshake-step client-sess)

                       ;; 【等价网络操作】从客户端取出握手报文，通过网络发给服务端
                       (let ((client-out (openssl-memory-tls:tls-get-ciphertext-output client-sess)))
                         ;; 将客户端的握手密文喂给服务端处理
                         (multiple-value-bind (server-out server-state)
                             (tls13-server-handle-input server-conn client-out)

                           ;; 【等价网络操作】从服务端取出响应报文，通过网络发回客户端
                           (openssl-memory-tls:tls-feed-ciphertext-input client-sess server-out)

                           ;; 打印每一步的状态，方便观察握手轮次（TLS 1.3 通常 1-2 轮即可完成）
                           (format t "  Step ~d: state=~a, output=~d bytes~%"
                                   step server-state (length server-out))

                           ;; 握手完成判定：两端都进入已建立状态
                           (setf handshake-done
                                 (and (eq server-state :established)
                                      (openssl-memory-tls:tls-handshake-completed-p client-sess))))))

                    (format t "~&--- Handshake Completed ---~%")
                    ;; 断言验证：服务端状态必须为已建立，确保握手成功
                    (assert (eq (tls13-server-connection-state server-conn) :established))
                    (format t "TLS 1.3 handshake verified success.~%")

                    ;; ======================================================================
                    ;; 阶段四：应用数据加密传输
                    ;; ======================================================================
                    (format t "~&--- Application Data Transfer ---~%")
                    (let ((client-message "Hello TLS 1.3 Server! 你好，纯内存服务端"))
                      (format t "Client sends: ~s~%" client-message)

                      ;; 1. 客户端写入明文，TLS 层自动加密后写入写 BIO
                      (openssl-memory-tls:send
                       client-sess
                       (babel:string-to-octets client-message :encoding :utf-8))

                      ;; 2. 取出客户端加密后的密文，喂给服务端处理
                      ;; 【等价网络操作】客户端把加密报文通过 TCP 发给服务端
                      (multiple-value-bind (server-out state plaintext-list)
                          (tls13-server-handle-input
                           server-conn
                           (openssl-memory-tls:tls-get-ciphertext-output client-sess))
                        (declare (ignore state))

                        ;; 3. 打印服务端解密后的明文，验证接收正确
                        (dolist (chunk plaintext-list)
                          (format t "Server received: ~s~%"
                                  (babel:octets-to-string chunk :encoding :utf-8)))

                        ;; 4. 服务端业务逻辑：对每条请求生成响应并加密
                        ;; 对应真实服务端的业务处理 + 响应回包
                        (dolist (chunk plaintext-list)
                          (tls13-server-send-response
                           server-conn
                           (generate-application-response chunk))))

                      ;; 5. 触发一次空输入，让服务端把加密后的响应密文从缓冲区取出来
                      ;; 原因：服务端加密后数据存在写 BIO 里，需要一次 handle 调用才会输出
                      (multiple-value-bind (response-cipher)
                          (tls13-server-handle-input server-conn empty-bytes)
                        ;; 【等价网络操作】服务端把响应报文通过 TCP 发回客户端
                        (openssl-memory-tls:tls-feed-ciphertext-input client-sess response-cipher)))

                      ;; 6. 客户端解密读取响应，验证内容正确性
                      (let ((buf (make-array 4096 :element-type '(unsigned-byte 8))))
                        (let ((n (openssl-memory-tls:read client-sess buf)))
                          (let ((response (babel:octets-to-string buf :end n :encoding :utf-8)))
                            (format t "Client received: ~s~%" response)
                            ;; 断言验证：响应中包含预期的 Echo 标识
                            (assert (search "TLS 1.3 Server Echo" response))
                            (format t "Application data transfer PASSED~%")))))

                    ;; ======================================================================
                    ;; 阶段五：TLS 连接优雅关闭
                    ;; ======================================================================
                    ;; 调用 tls-shutdown 发送 CloseNotify 告警，对应标准 TLS 正常关闭流程
                    ;; 区别于直接释放资源的粗暴关闭，符合协议规范
                    (format t "~&--- Connection Shutdown ---~%")
                    (openssl-memory-tls:tls-shutdown client-sess)
                    ;; 把客户端的关闭报文喂给服务端，完成双向关闭
                    (tls13-server-handle-input
                     server-conn
                     (openssl-memory-tls:tls-get-ciphertext-output client-sess))
                    (format t "Connection closed gracefully.~%"))

               ;; 内层资源释放：单条连接的资源
               (free-tls13-server-connection server-conn)
               (openssl-memory-tls:free-tls-session client-sess))))

      ;; 外层资源释放：全局上下文资源
      (openssl-memory-tls:free-tls-context server-ctx)
      (openssl-memory-tls:free-tls-context client-ctx)))

  (format t "~&===== All TLS 1.3 Tests Passed =====~%")
  t)
|#
