#!/bin/bash

make clean
make all
cd tests
./run.sh
