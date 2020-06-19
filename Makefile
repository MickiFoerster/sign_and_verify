MBEDTLS=mbedtls-2.16.6
DEBUG=-DDEBUG
CFLAGS=-Wall -g -I$(MBEDTLS)/include $(DEBUG)
#-fopenmp
LDFLAGS=-L$(MBEDTLS)/bld/library -lmbedcrypto 

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

all: verify_signature \
     create_signature \
     hash-evaluation \
     create_keypair

create_keypair : create_keypair.o printer.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

verify_signature : verify_signature.o printer.o create_hash.o reader.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
create_signature : create_signature.o printer.o create_hash.o 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: hash-evaluation
	dd if=/dev/urandom of=testfile bs=4 count=4
	./$<

hash-evaluation : hash-evaluation.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

verify_signature.o: $(MBEDTLS)/bld/library/libmbedcrypto.a
create_signature.o: $(MBEDTLS)/bld/library/libmbedcrypto.a
hash-evaluation.o: $(MBEDTLS)/bld/library/libmbedcrypto.a

$(MBEDTLS)/bld/library/libmbedcrypto.a: $(MBEDTLS)-apache.tgz
	rm -rf $(MBEDTLS)
	tar xfz $<
	cd $(MBEDTLS) && mkdir bld && cd bld && cmake -GNinja .. && ninja

$(MBEDTLS)-apache.tgz:
	wget https://tls.mbed.org/download/$(MBEDTLS)-apache.tgz

clean:
	rm -f *.o \
		    hash-evaluation \
		    create_signature \
				verify_signature 

.PHONY: clean test
