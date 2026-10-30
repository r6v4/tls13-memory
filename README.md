# tls13-memory
openssl tls1.3 memory-bio written by doubao.

## example 
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
```
```common-lisp
(ql:quickload '(:cffi :babel "tls13-memory"))

;(load "openssl-memory-bio.lisp")
;(load "openssl-memory-tls.lisp")
;(load "tls13-memory-server-example.lisp")

(setf server-ctx (tls13-memory-server::create-tls13-server-context "server.crt" "server.key"))
(setf my-socket (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp))
(setf my-address (sb-bsd-sockets:make-inet-address "127.0.0.1"))
(sb-bsd-sockets:socket-bind my-socket my-address 8888 :reuse-address t)
(sb-bsd-sockets:socket-listen my-socket 5)

(setf my-client (sb-bsd-sockets:socket-accept my-socket))
(setf empty-bytes (make-array 0 :element-type '(unsigned-byte 8)))
(setf server-conn (tls13-memory-server::create-tls13-server-connection server-ctx))
(cffi:use-foreign-library openssl-memory-tls::libssl)

(defun handshake (my-client server-conn) 
    (multiple-value-bind (a b) (sb-bsd-sockets:socket-receive my-client nil 4096 :element-type '(unsigned-byte 8) :dontwait t)
        (setf a (subseq a 0 b))
        (multiple-value-bind (server-out server-state)
            (tls13-memory-server::tls13-server-handle-input server-conn a)
            (sb-bsd-sockets:socket-send my-client server-out nil) ))
            
(defun tlsreceive (my-client server-conn)
    (multiple-value-bind (a b) (sb-bsd-sockets:socket-receive my-client nil 4096 :element-type '(unsigned-byte 8) :dontwait t)
        (setf a (subseq a 0 b))
            (multiple-value-bind (server-out state plaintext-list)
                (tls13-memory-server::tls13-server-handle-input server-conn a)
                plaintext-list )))

(defun tlssend (my-client server-conn server-message)
    (tls13-memory-server::tls13-server-send-response server-conn server-message)
        (multiple-value-bind (response-cipher)
            (tls13-memory-server::tls13-server-handle-input server-conn empty-bytes)
            (sb-bsd-sockets:socket-send my-client response-cipher nil)))

(handshake my-client server-conn)
(handshake my-client server-conn)
(tlsreceive my-client server-conn)
(setf server-message "HTTP/1.1 200 OK ~A
Content-Type: text/html; charset=UTF-8~A
Content-Length: 3~A
~A
200" #\return #\return #\return #\return)
(tlssend my-client server-conn server-message)
```
```bash
curl -k https://127.0.0.1:8888/
```

