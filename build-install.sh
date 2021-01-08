#!/bin/bash
sudo g++ -std=c++11 -I . -I ./src *.cc src/*.cc -w -o K55
sudo gcc -z execstack k55_example_process/k55_test_process.c -o k55_example_process/k55_test_process
