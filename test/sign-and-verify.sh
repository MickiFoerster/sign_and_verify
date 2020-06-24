./ecdsa-keygen  1>/dev/null 2>&1 &&
dd if=/dev/urandom of=testfile bs=1M count=1  1>/dev/null 2>&1 &&
./ecdsa-sign testfile  1>/dev/null 2>&1 &&
./ecdsa-verify testfile.sig  1>/dev/null 2>&1 &&
echo "Test OK" 
