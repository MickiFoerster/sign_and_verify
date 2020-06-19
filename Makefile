MBEDTLS=mbedtls-2.16.6
DEBUG=-DDEBUG
CFLAGS=-Wall -g -I$(MBEDTLS)/include $(DEBUG) -fopenmp
LDFLAGS=-L$(MBEDTLS)/bld/library -lmbedcrypto 
BINARIES=ecdsa-verify \
		 ecdsa-sign \
		 hash-benchmark \
		 ecdsa-keygen

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

all: $(BINARIES)

ecdsa-keygen : ecdsa-keygen.o writer.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ecdsa-verify : ecdsa-verify.o writer.o ecdsa-hash.o reader.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
ecdsa-sign : ecdsa-sign.o writer.o ecdsa-hash.o load-keypair.o reader.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: hash-benchmark
	dd if=/dev/urandom of=testfile bs=4 count=4
	./$<

hash-benchmark : hash-benchmark.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

load-keypair.o : reader.o
ecdsa-verify.o: $(MBEDTLS)/bld/library/libmbedcrypto.a
ecdsa-sign.o: $(MBEDTLS)/bld/library/libmbedcrypto.a
hash-benchmark.o: $(MBEDTLS)/bld/library/libmbedcrypto.a

$(MBEDTLS)/bld/library/libmbedcrypto.a: $(MBEDTLS)-apache.tgz
	rm -rf $(MBEDTLS)
	tar xfz $<
	cd $(MBEDTLS) && mkdir bld && cd bld && cmake -GNinja .. && ninja

$(MBEDTLS)-apache.tgz:
	wget https://tls.mbed.org/download/$(MBEDTLS)-apache.tgz

clean:
	rm -f *.o $(BINARIES)

.PHONY: clean test
