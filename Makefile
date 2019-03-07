KEY_VALIDITY_DAYS=365

certs: certs/client.fullchain certs/client.rsa certs/server.fullchain certs/server.rsa

clean:
	rm -f certs/*.cert certs/*.key certs/*.csr certs/*.fullchain certs/*.rsa

# I would have preferred to use ECDSA (or Ed25519!) but rustls doesn't
# support either at this time.  Maybe check ctz/rustls#52.
certs/ca.cert:
	openssl req -nodes		\
	  -x509				\
	  -newkey rsa:8192		\
	  -keyout certs/ca.key		\
	  -out certs/ca.cert		\
	  -sha256			\
	  -batch			\
	  -days $(KEY_VALIDITY_DAYS)	\
	  -subj '/CN=ACR service CA'

certs/inter.key:
	openssl req -nodes		\
	  -newkey rsa:2048		\
	  -keyout certs/inter.key	\
	  -out certs/inter.csr		\
	  -sha256			\
	  -batch			\
	  -days $(KEY_VALIDITY_DAYS)	\
	  -subj "/CN=ACR service intermediate"

certs/inter.cert: certs/inter.key certs/ca.cert certs/openssl.cnf
	openssl x509 -req		\
	  -in certs/inter.csr		\
	  -out certs/inter.cert		\
	  -CA certs/ca.cert		\
	  -CAkey certs/ca.key		\
	  -sha256			\
	  -days $(KEY_VALIDITY_DAYS)	\
	  -set_serial 333		\
	  -extensions inter		\
	  -extfile certs/openssl.cnf

certs/client.key:
	openssl req -nodes		\
	  -newkey rsa:2048		\
	  -keyout certs/client.key	\
	  -out certs/client.csr		\
	  -sha256			\
	  -batch			\
	  -days $(KEY_VALIDITY_DAYS)	\
	  -subj '/CN=ACR client'

certs/client.cert: certs/client.key certs/inter.cert certs/openssl.cnf
	openssl x509 -req		\
	  -in certs/client.csr		\
	  -out certs/client.cert	\
	  -CA certs/inter.cert		\
	  -CAkey certs/inter.key	\
	  -set_serial 666		\
	  -extensions client		\
	  -extfile certs/openssl.cnf	\
	  -sha256			\
	  -days $(KEY_VALIDITY_DAYS)

certs/server.key:
	openssl req -nodes		\
	  -newkey rsa:2048		\
	  -keyout certs/server.key	\
	  -out certs/server.csr		\
	  -sha256			\
	  -batch			\
	  -days $(KEY_VALIDITY_DAYS)	\
	  -subj '/CN=ACR server'

certs/server.cert: certs/server.key certs/inter.cert certs/openssl.cnf
	openssl x509 -req		\
	  -in certs/server.csr		\
	  -out certs/server.cert	\
	  -CA certs/inter.cert		\
	  -CAkey certs/inter.key	\
	  -set_serial 777		\
	  -extensions server		\
	  -extfile certs/openssl.cnf	\
	  -sha256			\
	  -days $(KEY_VALIDITY_DAYS)

certs/%.fullchain: certs/%.cert certs/inter.cert certs/ca.cert
	cat $^ > $@

certs/%.rsa: certs/%.key
	openssl rsa -in $< -out $@

.PHONY: certs clean
