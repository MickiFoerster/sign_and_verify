#!/bin/bash
dd if=/dev/urandom of=testfile bs=4 count=4
./hash-benchmark
