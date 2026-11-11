Self-signed certificate and private key for tests only (P-256, `CN=nett-hub-test`,
`subjectAltName=IP:127.0.0.1`), used only for tests in which the Hub terminates TLS itself on
127.0.0.1 and not for any deployment. How to generate them:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
  -subj /CN=nett-hub-test -addext subjectAltName=IP:127.0.0.1 -keyout test-key.pem -out test-cert.pem
```
