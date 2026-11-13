# Written by openssl/build/build.sh from targets.conf. To change it, edit targets.conf and run "openssl/build/build.sh linkmk".
OSSL_LIBS = -lssl -lcrypto -lpthread
OSSL_LDFLAGS = -Wl,--gc-sections
OSSL_CFLAGS = 
