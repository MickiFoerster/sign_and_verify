MBEDTLS=mbedtls-2.16.6
CFLAGS=-Wall -Werror -g -I$(MBEDTLS)/include -fopenmp
LDFLAGS=-L$(MBEDTLS)/bld/library -lmbedcrypto 

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

test: hash-evaluation
	dd if=/dev/urandom of=testfile bs=4 count=4
	./$<

hash-evaluation : main.o $(MBEDTLS)/bld/library/libmbedcrypto.a
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(MBEDTLS)/bld/library/libmbedcrypto.a: $(MBEDTLS)-apache.tgz
	tar xfz $<
	cd $(MBEDTLS) && mkdir bld && cd bld && cmake -GNinja .. && ninja

$(MBEDTLS)-apache.tgz:
	curl -O https://tls.mbed.org/download/$(MBEDTLS)-apache.tgz

clean:
	rm -f *.o hash-evaluation 

.PHONY: clean test
