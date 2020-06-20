./ecdsa-keygen &&
dd if=/dev/urandom of=testfile bs=1M count=1 &&
./ecdsa-sign testfile &&
./ecdsa-verify testfile.sig &&
echo "Test OK" 
