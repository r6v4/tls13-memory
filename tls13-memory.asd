(asdf:defsystem tls13-memory
    :name "tls13-memory"
    :description "openssl tls1.3"
    :version "1.0"
    :depends-on (:cffi :babel) 
    :serial t
    :components (
        (:static-file "LICENSE")
        (:file "package")
        ;(:file "openssl-memory-bio") 
        (:file "openssl-memory-tls")
        (:file "tls13-memory-server-example") ))
