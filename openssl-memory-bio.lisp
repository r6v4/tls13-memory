;;;; openssl-memory-bio.lisp
;;;; 基于 OpenSSL Memory BIO 的 Common Lisp 封装库
;;;; 依赖：CFFI, OpenSSL (Ubuntu 下 libssl-dev 包)
;;;; 设计原则：显式创建/释放，减少宏封装，函数命名完整语义化
;;;; 修正说明：修复括号语法错误，修复悬空指针缺陷，统一错误处理逻辑

(defpackage #:openssl-memory-bio
  (:use #:cl #:cffi)
  (:export
   #:bio-pointer
   #:bio-pointer-p
   #:create-memory-bio
   #:create-memory-bio-from-buffer
   #:free-bio
   #:bio-write-bytes
   #:bio-read-bytes
   #:bio-read-all-bytes
   #:bio-available-bytes
   #:bio-reset
   #:bio-get-internal-pointer
   #:bio-write-string
   #:bio-read-string
   #:bio-read-all-string
   #:with-bio
   #:run-self-test))

(in-package #:openssl-memory-bio)

;;; ============================================================================
;;; 1. 外部库加载
;;; ============================================================================

(define-foreign-library libcrypto
  (:unix (:or "libcrypto.so.3" "libcrypto.so.1.1" "libcrypto.so"))
  (t (:default "libcrypto")))

(use-foreign-library libcrypto)

;;; ============================================================================
;;; 2. 类型与常量
;;; ============================================================================

(defctype bio-pointer :pointer
  "BIO 对象的不透明 C 指针类型，仅用于 CFFI 函数签名。")

(defun bio-pointer-p (obj)
  "类型谓词：判断对象是否为有效的非空 BIO 指针对象。"
  (and (pointerp obj)
       (not (null-pointer-p obj))))

(defconstant +bio-control-reset+ 1)
(defconstant +bio-control-get-mem-ptr+ 12)
(defconstant +bio-control-pending+ 10)

;;; ============================================================================
;;; 3. 底层 C API 绑定
;;; ============================================================================

(defcfun ("BIO_new" %bio-new) bio-pointer
  (method :pointer))

(defcfun ("BIO_s_mem" %bio-s-mem) :pointer)

(defcfun ("BIO_free" %bio-free) :int
  (bio bio-pointer))

(defcfun ("BIO_read" %bio-read) :int
  (bio bio-pointer)
  (buf :pointer)
  (len :int))

(defcfun ("BIO_write" %bio-write) :int
  (bio bio-pointer)
  (buf :pointer)
  (len :int))

(defcfun ("BIO_ctrl" %bio-ctrl) :long
  (bio bio-pointer)
  (cmd :int)
  (larg :long)
  (parg :pointer))

(defcfun ("ERR_get_error" %err-get-error) :unsigned-long)

(defcfun ("ERR_error_string_n" %err-error-string-n) :void
  (error-code :unsigned-long)
  (buffer :pointer)
  (buffer-size :int))

;;; ============================================================================
;;; 4. 内部错误工具函数
;;; ============================================================================

(defun get-last-error-string ()
  "获取 OpenSSL 错误队列中的错误描述，返回两个值：描述字符串、是否存在真实错误。"
  (let ((err-code (%err-get-error)))
    (if (zerop err-code)
        (values "No error in queue" nil)
        (values
         (with-foreign-pointer (buf 256 buf-size)
           (%err-error-string-n err-code buf buf-size)
           (foreign-string-to-lisp buf))
         t))))

;;; ============================================================================
;;; 5. 生命周期管理
;;; ============================================================================

(defun create-memory-bio ()
  "创建一个空的内存型 BIO 对象。使用完毕必须调用 free-bio 释放。"
  (let ((bio (%bio-new (%bio-s-mem))))
    (if (null-pointer-p bio)
        (multiple-value-bind (err has-err) (get-last-error-string)
          (error "Failed to create memory BIO.~@[ ~a~]" (when has-err err)))
        bio)))

(defun create-memory-bio-from-buffer (data-vector)
  "基于字节向量创建内存 BIO，数据会被内部复制管理。
使用完毕必须调用 free-bio 释放。"
  (check-type data-vector (vector (unsigned-byte 8)))
  (let ((bio (create-memory-bio)))
    (handler-case
        (progn
          (bio-write-bytes bio data-vector)
          bio)
      (error (e)
        (free-bio bio)
        (error "Failed to create memory BIO from buffer: ~a" e)))))

(defun free-bio (bio)
  "释放 BIO 对象及其内部缓冲区资源。"
  (unless (bio-pointer-p bio)
    (error "Argument to free-bio must be a valid BIO pointer, got: ~a" bio))
  (%bio-free bio)
  (values))

;;; ============================================================================
;;; 6. 字节读写接口
;;; ============================================================================

(defun bio-write-bytes (bio data-vector)
  "向内存 BIO 写入字节数据，返回实际写入的字节数。
返回 0 表示暂不可写入（可重试），仅致命错误抛出异常。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-write-bytes must be a valid BIO pointer, got: ~a" bio))
  (let ((len (length data-vector)))
    (when (zerop len)
      (return-from bio-write-bytes 0))
    (with-foreign-object (buf :unsigned-char len)
      (dotimes (i len)
        (setf (mem-aref buf :unsigned-char i) (aref data-vector i)))
      (let ((result (%bio-write bio buf len)))
        (cond
          ((> result 0) result)
          ((= result 0) 0)
          (t
           (multiple-value-bind (err has-err) (get-last-error-string)
             (if has-err
                 (error "BIO write failed, code: ~d, detail: ~a" result err)
                 0))))))))

(defun bio-read-bytes (bio max-length)
  "从内存 BIO 读取最多 MAX-LENGTH 个字节，返回字节向量。
返回空向量表示无数据可读（可重试），仅致命错误抛出异常。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-read-bytes must be a valid BIO pointer, got: ~a" bio))
  (check-type max-length (integer 1))
  (with-foreign-object (buf :unsigned-char max-length)
    (let ((bytes-read (%bio-read bio buf max-length)))
      (cond
        ((> bytes-read 0)
         (let ((vector (make-array bytes-read :element-type '(unsigned-byte 8))))
           (dotimes (i bytes-read)
             (setf (aref vector i) (mem-aref buf :unsigned-char i)))
           vector))
        ((= bytes-read 0)
         (make-array 0 :element-type '(unsigned-byte 8)))
        (t
         (multiple-value-bind (err has-err) (get-last-error-string)
           (if has-err
               (error "BIO read failed, code: ~d, detail: ~a" bytes-read err)
               (make-array 0 :element-type '(unsigned-byte 8)))))))))

(defun bio-read-all-bytes (bio &key (chunk-size 4096))
  "读取 BIO 中全部剩余数据，返回合并后的字节向量。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-read-all-bytes must be a valid BIO pointer, got: ~a" bio))
  (loop with total = (make-array 0
                                 :element-type '(unsigned-byte 8)
                                 :adjustable t
                                 :fill-pointer 0)
        for chunk = (bio-read-bytes bio chunk-size)
        while (> (length chunk) 0)
        do (dotimes (i (length chunk))
             (vector-push-extend (aref chunk i) total))
        finally (return total)))

;;; ============================================================================
;;; 7. 状态查询与控制
;;; ============================================================================

(defun bio-available-bytes (bio)
  "查询 BIO 中当前可读的字节数。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-available-bytes must be a valid BIO pointer, got: ~a" bio))
  (let ((pending (%bio-ctrl bio +bio-control-pending+ 0 (null-pointer))))
    (if (< pending 0) 0 pending)))

(defun bio-reset (bio)
  "重置内存 BIO，清空内部缓冲区。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-reset must be a valid BIO pointer, got: ~a" bio))
  (%bio-ctrl bio +bio-control-reset+ 0 (null-pointer))
  (values))

(defun bio-get-internal-pointer (bio)
  "获取 BIO 内部缓冲区的原始指针和长度。警告：仅用于只读窥视。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-get-internal-pointer must be a valid BIO pointer, got: ~a" bio))
  (with-foreign-object (ptr-ptr :pointer)
    (let ((ret (%bio-ctrl bio +bio-control-get-mem-ptr+ 0 ptr-ptr)))
      (if (zerop ret)
          (multiple-value-bind (err has-err) (get-last-error-string)
            (error "Failed to get internal memory pointer.~@[ ~a~]" (when has-err err)))
          (let ((mem-struct (mem-ref ptr-ptr :pointer)))
            (values (mem-ref mem-struct :pointer 16)
                    (mem-ref mem-struct :unsigned-long 0)))))))

;;; ============================================================================
;;; 8. 字符串高层接口
;;; ============================================================================

(defun bio-write-string (bio string)
  "向 BIO 写入 UTF-8 字符串，返回实际写入的字节数。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-write-string must be a valid BIO pointer, got: ~a" bio))
  (check-type string string)
  (bio-write-bytes bio (babel:string-to-octets string :encoding :utf-8)))

(defun bio-read-string (bio max-byte-length)
  "从 BIO 读取数据并解码为 UTF-8 字符串。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-read-string must be a valid BIO pointer, got: ~a" bio))
  (let ((bytes (bio-read-bytes bio max-byte-length)))
    (babel:octets-to-string bytes :encoding :utf-8)))

(defun bio-read-all-string (bio &key (chunk-size 4096))
  "读取 BIO 全部数据并解码为 UTF-8 字符串。"
  (unless (bio-pointer-p bio)
    (error "Argument to bio-read-all-string must be a valid BIO pointer, got: ~a" bio))
  (babel:octets-to-string (bio-read-all-bytes bio :chunk-size chunk-size)
                          :encoding :utf-8))

;;; ============================================================================
;;; 9. 便捷宏
;;; ============================================================================

(defmacro with-bio ((var bio-form) &body body)
  "便捷宏：创建 BIO 并在执行 BODY 后自动释放。"
  `(let ((,var ,bio-form))
     (unwind-protect
          (progn ,@body)
       (free-bio ,var))))

;;; ============================================================================
;;; 10. 自测
;;; ============================================================================

(defun run-self-test ()
  "运行内置自测，全部通过返回 T。"
  (format t "~&=== Running OpenSSL Memory BIO self test ===~%")

  ;; 测试 1：基础读写
  (let ((bio (create-memory-bio)))
    (unwind-protect
         (let ((test-string "Hello, OpenSSL Memory BIO from Common Lisp! 你好"))
           (bio-write-string bio test-string)
           (let ((available (bio-available-bytes bio)))
             (format t "Test 1 - Available bytes after write: ~d~%" available)
             (assert (> available 0)))
           (let ((read-back (bio-read-all-string bio)))
             (format t "Test 1 - Read back: ~s~%" read-back)
             (assert (string= test-string read-back))
             (format t "Test 1 PASSED~%")))
      (free-bio bio)))

  ;; 测试 2：分块读取
  (let ((bio (create-memory-bio)))
    (unwind-protect
         (progn
           (bio-write-string bio "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
           (let ((part1 (bio-read-string bio 10))
                 (part2 (bio-read-string bio 10))
                 (part3 (bio-read-string bio 10)))
             (format t "Test 2 - Chunk read: ~s ~s ~s~%" part1 part2 part3)
             (assert (string= part1 "ABCDEFGHIJ"))
             (assert (string= part2 "KLMNOPQRST"))
             (assert (string= part3 "UVWXYZ"))
             (format t "Test 2 PASSED~%")))
      (free-bio bio)))

  ;; 测试 3：重置功能
  (let ((bio (create-memory-bio)))
    (unwind-protect
         (progn
           (bio-write-string bio "data to be cleared")
           (bio-reset bio)
           (assert (= 0 (bio-available-bytes bio)))
           (bio-write-string bio "new data after reset")
           (assert (string= "new data after reset" (bio-read-all-string bio)))
           (format t "Test 3 PASSED~%"))
      (free-bio bio)))

  ;; 测试 4：从缓冲区创建
  (let* ((data (babel:string-to-octets "Preloaded buffer content"))
         (bio (create-memory-bio-from-buffer data)))
    (unwind-protect
         (progn
           (assert (string= "Preloaded buffer content" (bio-read-all-string bio)))
           (format t "Test 4 PASSED~%"))
      (free-bio bio)))

  (format t "~&=== All tests passed ===~%")
  t)
