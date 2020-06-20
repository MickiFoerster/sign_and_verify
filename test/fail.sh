./ecdsa-keygen &&
dd if=/dev/urandom of=testfile bs=1M count=1 &&
./ecdsa-sign testfile &&
dd if=/dev/urandom of=testfile seek=512 bs=1 count=1 &&
./ecdsa-verify testfile.sig ||
echo "Expected result that verification failed - Test passed" 
