#!/bin/bash

make clean
make all
cd tests
./solo.sh $1
