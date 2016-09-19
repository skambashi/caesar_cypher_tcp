#!/bin/bash

ENCRYPT="./client -h 143.248.56.16 -p 3000 -o 0 -s 3"
DECRYPT="./client -h 143.248.56.16 -p 3000 -o 1 -s 3"
FILENUM=$(\ls -afq | grep .in | wc -l)

rm -f *.out
touch passed.out
touch failed.out

for i in `seq 1 $FILENUM`
do
    echo "==============================================================="
    echo "TEST $i"
    echo "---------------------------------------------------------------"
    .././$ENCRYPT < $i.input > a$i.out

    if ! diff -q a$i.out $i.correct > /dev/null  2>&1; then
#        echo "---------------------------------------------------------------"
#        echo "a$i FAILED"
#        echo "---------------------------------------------------------------"
#        echo "$(diff $i.out $i.correct)"
        echo "==============================================================="
        echo -n "a$i " >> failed.out
    else
        echo "---------------------------------------------------------------"
 #       echo "$i PASSED"
 #       echo "==============================================================="
        echo -n "a$i " >> passed.out
        .././$DECRYPT < a$i.out > b$i.out
        if ! diff -q b$i.out $i.input > /dev/null  2>&1; then
            echo -n "b$i " >> failed.out
        else
            echo -n "b$i " >> passed.out
        fi
        echo "==============================================================="
    fi
done
echo "==============================================================="
echo "PASSED: $(cat passed.out)"
echo "---------------------------------------------------------------"
echo "FAILED: $(cat failed.out)"
echo "==============================================================="
