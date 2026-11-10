测试专用的自签证书与私钥（P-256，`CN=nett-hub-test`，`subjectAltName=IP:127.0.0.1`），只用于 Hub 在
127.0.0.1 上自己终止 TLS 的测试，不用于任何部署。生成方法：

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
  -subj /CN=nett-hub-test -addext subjectAltName=IP:127.0.0.1 -keyout test-key.pem -out test-cert.pem
```
