#!/bin/bash

EXECUTABLE="./client -h 143.248.56.16 -p 3000 -o 0 -s 3"
FILENUM=$(\ls -afq | grep .in | wc -l)

rm -f *.out

for i in `seq 1 $FILENUM`
do
    .././$EXECUTABLE < $i.in > $i.out
    if ! diff -q $i.out $i.correct > /dev/null  2>&1; then
        echo "$i failed"
    else
        echo "$i passed"
    fi
done

