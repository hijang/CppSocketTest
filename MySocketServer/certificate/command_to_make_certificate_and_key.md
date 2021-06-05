# Self-signed server key and certificate

### Root CA key
> openssl ecparam -out rootca.key -name prime256v1 -genkey

### CSR(Certificae Signiture Request) for Root Certificate
> openssl req -new -sha256 -key rootca.key -out rootca.csr

### Make Root CA and self-sign
> openssl x509 -req -sha256 -days 999999 -in rootca.csr -signkey rootca.key -out rootca.crt

### Make private key for server
> openssl ecparam -out server.key -name prime256v1 -genkey

### CSR(Certificae Signiture Request) for server
> openssl req -new -sha256 -key server.key -out server.csr

### Make certificate for server and sign it.
> openssl x509 -req -sha256 -days 999999 -in server.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out server.crt

### Describe server certificate.
> openssl x509 -in server.crt -text -noout

### Make certificate for server
> cat server.crt rootca.crt > server.pem