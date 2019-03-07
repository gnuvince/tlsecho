# tlsecho

This is a very simple server/client program to learn how to use rustls.

## Building

First, you need to create private keys and certificates.
The `Makefile` will help you do that:

```
$ make certs
$ ls -1 certs/
ca.cert
ca.key
client.cert
client.csr
client.fullchain
client.key
client.rsa
inter.cert
inter.csr
inter.key
openssl.cnf
server.cert
server.csr
server.fullchain
server.key
server.rsa
```

To build *tlsecho* itself, use *cargo*:

```
$ cargo build --release
```

## Running

To run the **server**, you must provide *tlsecho* with:

1. The certificate chain for the server;
2. The private key (RSA) for the server.

(You can set the `RUST_LOG` environment variable to have more information on `stderr`.)

```
$ RUST_LOG=info ./target/release/tlsecho server --cert certs/server.fullchain --privkey certs/server.rsa
```

To run the **client**, you must provide *tlsecho* with:

1. The certificate of the CA (Certification Authority) that issued the certificate for the server.

(In this example, the server does not authenticate the client.)

```
$ RUST_LOG=info ./target/release/tlsecho client --ca certs/ca.cert
```
