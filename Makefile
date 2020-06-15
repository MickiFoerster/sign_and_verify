MBEDTLS=mbedtls-2.16.6
CFLAGS=-Wall -g -I$(MBEDTLS)/include 
#-fopenmp
LDFLAGS=-L$(MBEDTLS)/bld/library -lmbedcrypto 

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

create_signature : create_signature.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test: hash-evaluation
	dd if=/dev/urandom of=testfile bs=4 count=4
	./$<

main.o: $(MBEDTLS)/bld/library/libmbedcrypto.a
hash-evaluation : main.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(MBEDTLS)/bld/library/libmbedcrypto.a: $(MBEDTLS)-apache.tgz
	tar xfz $<
	cd $(MBEDTLS) && mkdir bld && cd bld && cmake -GNinja .. && ninja

$(MBEDTLS)-apache.tgz:
	wget https://tls.mbed.org/download/$(MBEDTLS)-apache.tgz

clean:
	rm -f *.o hash-evaluation create_signature

.PHONY: clean test
