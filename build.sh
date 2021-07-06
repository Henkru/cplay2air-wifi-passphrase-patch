#!/bin/sh
export PATH=$PWD/toolchain/gcc-linaro-5.1-2015.08-x86_64_arm-linux-gnueabi/bin:$PATH
arm-linux-gnueabi-gcc -Wall -shared -g -fPIC -o inject.o inject.c && arm-linux-gnueabi-strip inject.o
